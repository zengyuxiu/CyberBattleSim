
import cyberbattle.simulation.model as model
import cyberbattle.simulation.commandcontrol as commandcontrol
import json
import logging

from flask import Flask, request
from LogStream import LogStreamHandler

import cyberbattle.samples.toyctf.toy_ctf as ctf

app = Flask(__name__)

# network = nx.erdos_renyi_graph(35, 0.05, directed=True)
# network = model.assign_random_labels(network)
network = model.create_network(ctf.nodes)
env = model.Environment(network=network, vulnerability_library=dict([]), identifiers=ctf.ENV_IDENTIFIERS)
c = commandcontrol.CommandControl(env)

c.plot_nodes()
# print("Nodes disovered so far: " + str(c.list_nodes()))
starting_node = c.list_nodes()[0]['id']

dbg = commandcontrol.EnvironmentDebugging(c)

env.plot_environment_graph()

# set up logging
log_stream = LogStreamHandler()
# configure basic logging with time support
logging.basicConfig(level=logging.INFO)
cyberbattle_logger = logging.getLogger("cyberbattlesim")
cyberbattle_logger.addHandler(log_stream)

# set up reward caching
cached_rewards = []


class Respone():
    def __init__(self, result, logs) -> None:
        self.result = result
        self.logs = logs

    def encode(self):
        return {"result": self.result, "logs": self.logs, "cached_rewards": cached_rewards}


def reset_environment():
    global env, c, dbg, log_stream, cached_rewards
    env = model.Environment(network=network, vulnerability_library=dict([]), identifiers=ctf.ENV_IDENTIFIERS)
    c = commandcontrol.CommandControl(env)
    dbg = commandcontrol.EnvironmentDebugging(c)
    log_stream = LogStreamHandler()
    cyberbattle_logger.addHandler(log_stream)
    cached_rewards = []
    print(env.identifiers)


@ app.route("/")
def hello_world():
    return "<p>Hello, World</p>"

# GETTERS


@ app.route("/api/get_nodes")
def get_nodes():
    return env.get_nodes()


@ app.route("/api/get_supported_ports")
def get_supported_ports():
    return json.dumps(model.collect_ports_from_nodes(env.nodes(), {}))


@ app.route("/api/total_reward")
def get_total_reward():
    result = c.total_reward()
    # append result if cache is empty or if last reward is different from result
    if not cached_rewards or cached_rewards[-1] != result:
        cached_rewards.append(result)
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())


@ app.route("/api/list_nodes")
def list_nodes():
    result = c.list_nodes()
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())

# TODO: add input


@ app.route("/api/get_node_color")
def get_node_color():
    return json.dumps(c.get_node_color())


@ app.route("/api/known_vulnerabilities")
def get_known_vulnerabilities():
    return json.dumps(c.known_vulnerabilities())

# TODO: add input


@ app.route("/api/list_remote_attacks")
def get_list_remote_attacks():
    return json.dumps(c.list_remote_attacks)
# TODO: add input


@ app.route("/api/list_local_atacks")
def get_list_local_atacks():
    return json.dumps(c.list_local_atacks())

# TODO: add input


@ app.route("/api/list_attacks")
def get_list_attacks():
    return json.dumps(c.list_attacks())


@ app.route("/api/list_all_attacks")
def get_list_all_attacks():
    result = c.list_all_attacks()
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())


@ app.route("/api/credentials_gathered_so_far")
def get_credentials():
    result = list(c.credentials_gathered_so_far)
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())


@ app.route("/api/run_attack", methods=['POST'])
def run_attack():
    target_node_id = request.form["targetNodeId"]
    vulnerability_id = request.form["vulnerabilityId"]
    result = c.run_attack(target_node_id, vulnerability_id)
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())


# TODO: add input


@ app.route("/api/run_remote_attack", methods=['POST'])
def run_remote_attack():
    source_node_id = request.form.get("sourceNodeId")
    target_node_id = request.form["targetNodeId"]
    vulnerability_id = request.form["vulnerabilityId"]
    result = c.run_remote_attack(source_node_id, target_node_id, vulnerability_id)
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())


@ app.route("/api/connect_and_infect", methods=['POST'])
def connect_and_infect():
    source_node_id = request.form.get("sourceNodeId")
    target_node_id = request.form["targetNodeId"]
    credential_id = request.form["credentialId"]
    port_name = request.form["port"]
    print(source_node_id, target_node_id, port_name, credential_id)
    print(c.list_attacks("client"))
    print(c.list_attacks("GitHubProject"))
    result = c.connect_and_infect(source_node_id, target_node_id, port_name, credential_id)
    response = Respone(result, log_stream)
    return json.dumps(response, default=lambda x: x.encode())

# SETTERS


@ app.route("/api/change_value", methods=['POST'])
def change_value():
    updated_node = request.form["updatedNode"]
    result = model.update_node(network, updated_node)
    reset_environment()
    return result


@ app.route("/api/remove_node", methods=['POST'])
def remove_node():
    node_id = request.form["nodeToRemove"]
    result = model.remove_node(network, node_id)
    reset_environment()
    return result


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
