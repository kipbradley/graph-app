#!/usr/bin/python
#
# Copyright 2020 VirusTotal. All Rights Reserved.

"""Upload your propietary software to your Monitor account.

The first time you run this script you will be asked to enter your username and
apikey.

Provide local and remote path as arguments, remote paths ending in "/" will be
treated as directories.

Examples:
$ vt_monitor_uploader.py my_file.bin /my_folder/
-> Create "/my_folder/my_file.bin" file inside "/my_folder/".

$ vt_monitor_uploader.py my_file.bin /my_folder
-> Create "/my_folder" file with my_file.bin contents.

$ vt_monitor_uploader.py local_folder /my_folder/
-> Uploads all files inside local_folder

Requirements:
$ pip install requests

Python 2 requirements:
$ pip install futures
"""

__author__ = 'fsantos@virustotal.com (Francisco Santos)'


import argparse
import logging
import os
import signal
import sys

from concurrent import futures

import requests


try:  # py3 compat
  input = raw_input
except NameError:
  pass


_API_USER = '[YOUR-USER-ID]'
_API_KEY = '[YOUR-API-KEY]'
_DEFAULT_HOST = 'https://www.virustotal.com'
_DEFAULT_USER_AGENT = 'MonitorSimpleUploaderV1'

# Logging
log = logging.getLogger('monitor-uploader')
formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                              datefmt='%b.%d/%H:%M:%S')
log.setLevel(logging.INFO)
_sh = logging.StreamHandler()
_sh.setFormatter(formatter)
log.addHandler(_sh)


def autoupdate():
  print('This is the first time you run this script, we are going to take you '
        'to your profile to retrieve your API key.')

  username = input('Insert your username: ')
  apikey = input('Please visit https://www.virustotal.com/gui/user/%s/apikey '
                 'and insert your API key here:' % username)

  with open(__file__, 'r') as f_obj:
    content = f_obj.read()

  content = content.replace('[YOUR-USER-ID]', username, 1)
  content = content.replace('[YOUR-API-KEY]', apikey, 1)
  with open(__file__, 'w') as f_obj:
    f_obj.write(content)

  print('Script setup finished correctly, please run it again.')


class MonitorUploader(object):

  def __init__(self, command_args):
    self._threads = int(command_args.threads)
    self.pool = futures.ThreadPoolExecutor(self._threads)
    self.pool_futures = []
    self.pool_added = 0
    self._host = _DEFAULT_HOST
    self.session = requests.Session()
    self.session.headers.update({
        'X-Apikey': _API_KEY,
        'User-Agent': _DEFAULT_USER_AGENT})
    self.local_path = command_args.local_path
    self.remote_path = command_args.remote_path
    self.running = True

  def enqueue(self, path):
    if os.path.isfile(path):
      relative_path = path.partition(self.local_path)[2]

      if self.remote_path.endswith('/'):
        destination = os.path.join(self.remote_path, relative_path)
      else:  # single upload
        destination = self.remote_path

      self.pool_futures.append(self.pool.submit(self.upload, path, destination))
      self.pool_added += 1
      return

    for name in os.listdir(path):
      if not self.running:
        return
      self.enqueue(os.path.join(path, name))

  def stop(self, unused_signum, unused_frame):
    self.running = False
    self.pool.shutdown(wait=False)
    log.info('Termination signal received, waiting threads to finish')

  def _get_big_upload_url(self):
    log.info('Obtaining bigfile url')
    big_upload_url = self._host + '/api/v3/monitor/items/upload_url'

    for attempt in range(3):
      try:
        response = self.session.get(big_upload_url)
        return response.json().get('data')
      except:
        log.error('Could not obtain "%s" (%d)', big_upload_url, attempt + 1)
        continue
    return None

  def upload(self, local, remote):
    if not self.running:
      return

    if os.sep == '\\':  # Windows path to standard path fix
      remote = remote.replace('\\', '/')

    url = self._host + '/api/v3/monitor/items'
    if os.stat(local).st_size > 30000 * 1024:
      url = self._get_big_upload_url()

    if url:
      log.debug('Uploading "%s" -> "%s"', local, remote)
      with open(local, 'rb') as file_obj:
        files = {'file': ('filepath', file_obj, 'application/octet-stream')}
        args = {'path': remote}

        response = self.session.post(url, files=files, data=args)
        if response.status_code == 200:
          log.info('Uploaded "%s"', local)
        else:
          log.error('Failed uploading "%s"\n%s', local, response.text)
    else:
      log.error('Failed receiving big files destination for "%s"', local)

  def run(self):
    self.enqueue(self.local_path)
    if not self.running:
      return
    log.info('Enqueued finished (%d files), waiting uploads to finish',
             self.pool_added)
    futures.as_completed(self.pool_futures)


def commandline_to_unicode(argument):
  """Python2: Convert params from system encoding to unicode."""
  if sys.version_info < (3, 0, 0):
    return argument.decode(sys.getfilesystemencoding())
  return argument


if __name__ == '__main__':
  if len(_API_KEY) < 64:
    autoupdate()
    sys.exit()

  parser = argparse.ArgumentParser(description=(
      'Monitor Uploader. '
      'Upload your propietary software collection to Monitor. Provide local '
      'and remote path. This path could be files or folders, remote paths '
      'ending with "/" will be treated as folder. '
      'Attention! This script does not check if remote file already exists, '
      'it just overwrite them with a new version.'))
  parser.add_argument(
      'local_path',
      help='Local path to upload',
      type=commandline_to_unicode)
  parser.add_argument(
      'remote_path',
      help='Remote path to upload to',
      type=commandline_to_unicode)
  parser.add_argument(
      '--threads',
      help='Do number of simultaneous uploads (default: 10)',
      dest='threads',
      action='store',
      default=10)
  parser.add_argument(
      '-d', '--debug',
      help='Print debug messages',
      dest='debug',
      action='store_true')
  args = parser.parse_args()

  if args.debug:
    log.setLevel(logging.DEBUG)

  if not args.remote_path.startswith('/'):
    log.error('Remote_path have to start with /')

  else:
    # Process directory upload (both params need to be folders)
    if os.path.isdir(args.local_path):
      args.local_path = args.local_path.rstrip('/') + '/'
      args.remote_path = args.remote_path.rstrip('/') + '/'

    # Process single file upload that is sent to a remote directory
    if os.path.isfile(args.local_path) and args.remote_path.endswith('/'):
      args.remote_path += args.local_path.rpartition('/')[2]

    uploader = MonitorUploader(command_args=args)
    signal.signal(signal.SIGTERM, uploader.stop)
    signal.signal(signal.SIGINT, uploader.stop)
    uploader.run()
