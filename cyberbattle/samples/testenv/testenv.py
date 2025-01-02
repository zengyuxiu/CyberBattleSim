# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Defines a set of networks following a speficic pattern
learnable from the properties associated with the nodes.

The network pattern is:
         Start ---> (Linux ---> Windows --->  ... Linux ---> Windows)*  ---> Linux[Flag]

The network is parameterized by the length of the central Linux-Windows chain.
The start node leaks the credentials to connect to all other nodes:

For each `XXX ---> Windows` section, the XXX node has:
    -  a local vulnerability exposing the RDP password to the Windows machine
    -  a bunch of other trap vulnerabilities (high cost with no outcome)
For each `XXX ---> Linux` section,
    - the Windows node has a local vulnerability exposing the SSH password to the Linux machine
    - a bunch of other trap vulnerabilities (high cost with no outcome)

The chain is terminated by one node with a flag (reward).

A Node-Property matrix would be three-valued (0,1,?) and look like this:

===== Initial state
        Properties
Nodes   L  W  SQL
1       1  0  0
2       ?  ?  ?
3       ?  ?  ?
...
10
======= After discovering node 2
        Properties
Nodes   L  W  SQL
1       1  0  0
2       0  1  1
3       ?  ?  ?
...
10
===========================

"""

from cyberbattle.simulation.model import Identifiers, NodeID, NodeInfo
from ...simulation import model as m
from typing import Dict
import json

DEFAULT_ALLOW_RULES = [
    m.FirewallRule("RDP", m.RulePermission.ALLOW),
    m.FirewallRule("SSH", m.RulePermission.ALLOW),
    m.FirewallRule("HTTPS", m.RulePermission.ALLOW),
    m.FirewallRule("HTTP", m.RulePermission.ALLOW)]

# Environment constants used for all instances of the chain network
ENV_IDENTIFIERS = Identifiers(
    properties=[
        "Apache",
        "Apache Struts2",
        "Apache Log4j2",
        'Windows',
        'windowsXP',
        'BlueKeep_one',
        'Linux',
        'ApacheWebSite',
        'IIS_2019',
        'IIS_2020_patched',
        'MySql',
        'Ubuntu',
        'nginx/1.10.3',
        'SMB_vuln',
        'SMB_vuln_patched',
        'SQLServer',
        'Win10',
        'Win10Patched',
        'FLAG:Linux',
        'ubuntu20.04',
        'windows10',
        'ubuntu18.04',
        'windows7'
        'ubuntu18.04',
        'windows7',
        'windows10',
        'windows11'
    ],
    ports=[
        'HTTPS',
        'GIT',
        'SSH',
        'RDP',
        'PING',
        'MySQL',
        'SSH-key',
        'SMB',
        'su'
    ],
    local_vulnerabilities=[
        "Leak_Node_From_Log4",
        'Leak_Node_From_MS17010',
        'Leak_Node_From_BlueKeep',
        "Leak_Node_From_StrutsS2",
        # 'Log4',
        # "StrutsS2",
        'BlueKeep',
        "MS17010",
        "Other_BlueKeep",
        'BlueKeep_one',
        "Leak_Node_From_Other_BlueKeep"
    ],
    remote_vulnerabilities=[
        'Log4',
        "StrutsS2",
        "Strust2",
        'RemoteVul_one',
        'RemoteVul_two',
        'RemoteVul_three',
        'RemoteVul_four',
        'RemoteVul_five',
        'RemoteVul_six',
        '2_MS17-010',
        '1_Log4J',
        '0_MS17-010',
        '12_Strust2',
        '10_MS17-010',
        '8_BlueKeep',
        '1_Log4J',
        '8_BlueKeep',
        '2_MS17-010',
        '12_Strust2',
        '0_MS17-010',
        '10_MS17-010',
        '12_BlueKeep',
        'Log4J',
        'MS17010',
        'BlueKeep',
        'MS170101'
    ]
)


def rdp_password(index):
    """Generate RDP password for the specified chain link"""
    return f"WindowsPassword!{index}"


def ssh_password(index):
    """Generate SSH password for the specified chain link"""
    return f"LinuxPassword!{index}"


def create_network_chain_link(n: int,data) -> Dict[NodeID, NodeInfo]:
    """Instantiate one link of the network chain with associated index n"""
    result = {}
    for node_id, node_info in data.items():
        print(node_id,node_info)
        services = [m.ListeningService("HTTPS")]

        vulnerabilities = {}
        for vuln_id, vuln_info in node_info.get("transfer", {}).items():
            vuln_name = vuln_info["name"].replace('-', '')
            print(vuln_name)
            vulnerabilities[vuln_name] = m.VulnerabilityInfo(
                description="========",
                type=m.VulnerabilityType.REMOTE,
                outcome=m.LeakedNodesId([vuln_id]),
                reward_string=vuln_info["reward_string"],
                cost=vuln_info["cost"]
            )
            print(vulnerabilities[vuln_name])

        node_config = m.NodeInfo(
            services=services,
            value=node_info["value"],
            properties=node_info["properties"],
            owned_string=node_info.get("owned_string", "N/A"),
            firewall=m.FirewallConfiguration(incoming=DEFAULT_ALLOW_RULES, outgoing=DEFAULT_ALLOW_RULES),
            vulnerabilities=vulnerabilities
        )
        print(node_config)
        result[node_id] = node_config
    return result


    # return {
    #     "0": m.NodeInfo(
    #         services=[m.ListeningService("HTTPS"),
    #                   m.ListeningService("SSH", allowedCredentials=[ssh_password(n + 123)])],
    #         firewall=m.FirewallConfiguration(incoming=DEFAULT_ALLOW_RULES,
    #                                          outgoing=DEFAULT_ALLOW_RULES),
    #         value=100,
    #         properties=["windows7", "MySql"],
    #         owned_string="owned 0",
    #         vulnerabilities=dict(
    #             Log4J=m.VulnerabilityInfo(
    #                 description="========",
    #                 type=m.VulnerabilityType.REMOTE,
    #                 outcome=m.LeakedNodesId(["1"]),
    #                 reward_string="Win Log4J",
    #                 cost=200
    #             ),
    #             MS17010=m.VulnerabilityInfo(
    #                 description="========",
    #                 type=m.VulnerabilityType.REMOTE,
    #                 outcome=m.LeakedNodesId(["2"]),
    #                 reward_string="=======",
    #                 cost=1
    #             ), )),
    #
    #     "1": m.NodeInfo(
    #         services=[m.ListeningService("HTTPS"),
    #                   m.ListeningService("RDP", allowedCredentials=[rdp_password(n + 123)])],
    #         value=200,
    #         properties=["windows10", "MySql"],
    #         vulnerabilities=dict(
    #             MS17010=m.VulnerabilityInfo(
    #                 description="=======",
    #                 type=m.VulnerabilityType.REMOTE,
    #                 outcome=m.LeakedNodesId(["0"]),
    #                 reward_string="======",
    #                 cost=1
    #             ),
    #         )),
    #
    #     # 第三个漏洞
    #     "2": m.NodeInfo(
    #         services=[m.ListeningService("HTTPS"),
    #                   m.ListeningService("SSH", allowedCredentials=[ssh_password(n + 123)])],
    #         firewall=m.FirewallConfiguration(incoming=DEFAULT_ALLOW_RULES,
    #                                          outgoing=DEFAULT_ALLOW_RULES),
    #         value=50,
    #         properties=["ubuntu20.04", "MySql"],
    #         owned_string="=========",
    #         vulnerabilities=dict(
    #             BlueKeep=m.VulnerabilityInfo(
    #                 description="====",
    #                 type=m.VulnerabilityType.REMOTE,
    #                 outcome=m.LeakedNodesId(["12"]),
    #                 reward_string="====",
    #                 cost=50
    #             ),
    #             MS170101=m.VulnerabilityInfo(
    #                 description="======",
    #                 type=m.VulnerabilityType.REMOTE,
    #                 outcome=m.LeakedNodesId(["0"]),
    #                 reward_string="======",
    #                 cost=1
    #             ),
    #         )),
    #
    #     # 第四个漏洞
    #     "12": m.NodeInfo(
    #         services=[m.ListeningService("HTTPS"),
    #                   m.ListeningService("SSH", allowedCredentials=[ssh_password(n + 123)]),
    #                   m.ListeningService("RDP", allowedCredentials=[rdp_password(n + 123)])],
    #         value=1,
    #         properties=["windows10", "MySql"],
    #         vulnerabilities=dict(
    #             MS17010=m.VulnerabilityInfo(
    #                 description="========",
    #                 type=m.VulnerabilityType.REMOTE,
    #                 outcome=m.LeakedNodesId(["2"]),
    #                 reward_string="=======",
    #                 cost=1.0
    #             )
    #         ))
    # }


# 为节点添加一个前缀，例如 prefix(3, 'nodeA') 返回 3_nodeA
def prefix(x: int, name: str):
    """Prefix node name with an instance"""
    return f"{x}_{name}"


def create_chain_network(data,size) -> Dict[NodeID, NodeInfo]:
    # with open('out_data_test.json', 'r') as json_file:
    #     data = json.load(json_file)
    first_key = list(data.keys())[0]
    print(first_key)
    last_key = list(data.keys())[-1]
    print(last_key)

    # 映射攻击类型字符串到 VulnerabilityType 枚举
    vulnerability_type_mapping = {
        "REMOTE": m.VulnerabilityType.REMOTE,
        "LOCAL": m.VulnerabilityType.LOCAL,
        # 添加其他类型的映射
    }

    final_node_index = size + 1
    nodes = {
        'start': m.NodeInfo(
            services=[],
            value=0,
            vulnerabilities=dict(
                BlueKeep_one=m.VulnerabilityInfo(
                    description="Scan Windows Explorer recent files for possible references to other machines",
                    type=m.VulnerabilityType.LOCAL,
                    outcome=m.LeakedCredentials(credentials=[
                        m.CachedCredential(node=first_key, port="SSH",
                                            credential=ssh_password(1))]),
                    reward_string="Found a reference to a remote Linux node in bash history",
                    cost=1.0
                )),
            agent_installed=True,
            reimagable=False),
        # 5_LinunxH1
        prefix(final_node_index, last_key): m.NodeInfo(
            services=[m.ListeningService("HTTPS"),
                        m.ListeningService("SSH", allowedCredentials=[ssh_password(final_node_index)])],
            value=1000,
            owned_string="FLAG: flag discovered!",
            properties=["MySql", "Ubuntu", "nginx/1.10.3", "FLAG:Linux"],
            vulnerabilities=dict()
        )
    }
    print("============准备更新有漏洞节点的data============")
    nodes.update(create_network_chain_link(size, data))

    return nodes


def new_environment(data,size) -> m.Environment:
    return m.Environment(
        network=m.create_network(create_chain_network(data,size)),
        vulnerability_library=dict([]),
        identifiers=ENV_IDENTIFIERS
    )
