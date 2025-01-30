"""VirusTotal Graph id load example."""


import vt_graph_api


API_KEY = ""  # Insert your VT API here.
GRAPH_ID = ""  # Insert yout graph id here.


# Retrieve the graph.
graph = vt_graph_api.VTGraph.load_graph(GRAPH_ID, API_KEY)

# Modify your graph here

# Save it in VirusTotal.
graph.save_graph()

# Get the graph id
print("Graph Id: %s" % graph.graph_id)

# Visualizing the Graph
print(graph.get_ui_link())  # Open the url in the browser
