from flask import Flask
import networkx as nx
from tabulate import tabulate
import cyberbattle.simulation.model as model
import cyberbattle.simulation.actions as actions
import cyberbattle.simulation.commandcontrol as commandcontrol
import importlib
importlib.reload(model)
importlib.reload(actions)
importlib.reload(commandcontrol)
import plotly.offline as plo
import json

app = Flask(__name__)

g = nx.erdos_renyi_graph(35,0.05,directed=True)
g = model.assign_random_labels(g)
env = model.Environment(network=g, vulnerability_library=dict([]), identifiers=model.SAMPLE_IDENTIFIERS)

c = commandcontrol.CommandControl(env)
dbg = commandcontrol.EnvironmentDebugging(c)
env.plot_environment_graph()
# print(json.dumps(env.get_data()))

# serialized = env.get_json()
# print('Serialized: ' + serialized)


print(nx.info(env.network))
# print(c.get_json())
print("Nodes disovered so far: " + str(c.list_nodes()))
starting_node = c.list_nodes()[0]['id']

print("serializing")
env.deserialize()
