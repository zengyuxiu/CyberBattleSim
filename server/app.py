import plotly.offline as plo
from flask import Flask
from flask import request
import networkx as nx
from tabulate import tabulate
import cyberbattle.simulation.model as model
import cyberbattle.simulation.actions as actions
import cyberbattle.simulation.commandcontrol as commandcontrol
import importlib
import json
importlib.reload(model)
importlib.reload(actions)
importlib.reload(commandcontrol)

app = Flask(__name__)


g = nx.erdos_renyi_graph(35, 0.05, directed=True)
g = model.assign_random_labels(g)
env = model.Environment(network=g, vulnerability_library=dict([]), identifiers=model.SAMPLE_IDENTIFIERS)

c = commandcontrol.CommandControl(env)

c.plot_nodes()
print("Nodes disovered so far: " + str(c.list_nodes()))
starting_node = c.list_nodes()[0]['id']

dbg = commandcontrol.EnvironmentDebugging(c)

env.plot_environment_graph()
print(nx.info(env.network))

print(tabulate(c.list_all_attacks(), {}))


@app.route("/")
def hello_world():
    return "<p>Hello, World</p>"

# GETTERS


@app.route("/api/get_nodes")
def get_nodes():
    return env.get_nodes()


@app.route("/api/get_data")
def get_data():
    return env.get_data()


@app.route("/api/get_total_reward")
def get_total_reward():
    return json.dumps(c.total_reward())


@app.route("/api/get_list_discovered_nodes")
def get_list_discovered_nodes():
    return json.dumps(c.list_nodes())

# TODO: add input


@app.route("/api/get_node_color")
def get_node_color():
    return json.dumps(c.get_node_color())


@app.route("/api/get_known_vulnerabilities")
def get_known_vulnerabilities():
    return json.dumps(c.known_vulnerabilities())

# TODO: add input


@app.route("/api/get_list_remote_attacks")
def get_list_remote_attacks():
    return json.dumps(c.list_remote_attacks)
# TODO: add input


@app.route("/api/get_list_local_atacks")
def get_list_local_atacks():
    return json.dumps(c.list_local_atacks())

# TODO: add input


@app.route("/api/get_list_attacks")
def get_list_attacks():
    return json.dumps(c.list_attacks())


@app.route("/api/get_list_all_attacks")
def get_list_all_attacks():
    return json.dumps(c.list_all_attacks())


@app.route("/api/get_run_attack")
def get_run_attack():
    return json.dumps(c.run_attack())

# TODO: add input


@app.route("/api/get_run_remote_attack")
def get_(run_remote_attack):
    return json.dumps(c.run_remote_attack())

# TODO: add input


@app.route("/api/get_connect_and_infect")
def get_connect_and_infect():
    return json.dumps(c.connect_and_infect())

# SETTERS


@app.route("/api/change_value", methods=['POST'])
def change_value():
    updated_node = request.form["updatedNode"]
    return model.update_node(g, updated_node)


if __name__ == "__main__":
    app.run(debug=True)
