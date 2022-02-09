import sys
import logging
from typing import cast
import gym
import numpy as np
import matplotlib.pyplot as plt  # type:ignore
from cyberbattle.agents.baseline.learner import TrainedLearner
import cyberbattle.agents.baseline.plotting as p
import cyberbattle.agents.baseline.agent_wrapper as w
import cyberbattle.agents.baseline.agent_tabularqlearning as a
from cyberbattle.agents.baseline.agent_wrapper import Verbosity
import cyberbattle.agents.baseline.learner as learner
from cyberbattle._env.cyberbattle_env import AttackerGoal, DefenderGoal
from gym.envs.registration import registry
from cyberbattle.samples.toyctf import toy_ctf
from cyberbattle import register
from cyberbattle.simulation.model import Environment, NodeInfo
import cyberbattle.simulation.model as model


def count_credentials(node: NodeInfo):
    count = 0
    for vulnerability in node.vulnerabilities.values():
        credentials = getattr(vulnerability.outcome, "credentials", [])
        count += len(credentials)
    return count


def run_simulation(env: Environment, simulation_parameters: dict) -> TrainedLearner:
    if 'AppSimulation-v0' in registry.env_specs:
        print("deleted registry")
        del registry.env_specs['AppSimulation-v0']

    register(
        id='AppSimulation-v0',
        # cyberbattle_env_identifiers=env.identifiers,
        cyberbattle_env_identifiers=env.identifiers,
        entry_point='cyberbattle._env.app_simulation:AppSimulation'
        # max_episode_steps=2600,
    )

    # Extract Parameters
    attacker_parameters = simulation_parameters["attackerGoal"]
    attacker_goal = AttackerGoal(reward=attacker_parameters["reward"],
                                 low_availability=attacker_parameters["lowAvailability"],
                                 own_atleast=attacker_parameters["ownAtLeast"],
                                 own_atleast_percent=attacker_parameters["ownAtLeastPercent"])

    defender_parameters = simulation_parameters["defenderGoal"]
    defender_goal = DefenderGoal(eviction=defender_parameters["eviction"])

    app_simulation = gym.make('AppSimulation-v0', env=env, renderer='iframe_connected', attacker_goal=attacker_goal, defender_goal=defender_goal, defender_agent=None)

    network_size = len(list(env.nodes()))
    total_credentials = sum(count_credentials(node) for _, node in env.nodes())

    ep = w.EnvironmentBounds.of_identifiers(
        maximum_node_count=network_size,
        maximum_total_credentials=total_credentials,
        identifiers=env.identifiers
    )

    iteration_count = int(simulation_parameters["iterationCount"])
    training_episode_count = int(simulation_parameters["trainingEpisodeCount"])
    gamma = float(simulation_parameters["gamma"])
    learning_rate = float(simulation_parameters["learningRate"])
    epsilon = float(simulation_parameters["epsilon"])
    epsilon_decay = float(simulation_parameters["epsilonDecay"])

    def qlearning_run(gym_env):
        """Execute one run of the q-learning algorithm for the
        specified gamma value"""
        return learner.epsilon_greedy_search(
            gym_env,
            ep,
            a.QTabularLearner(ep, gamma=gamma,
                              learning_rate=learning_rate,
                              exploit_percentile=100),
            episode_count=training_episode_count,
            iteration_count=iteration_count,
            epsilon=epsilon,
            render=True,
            render_last_episode_rewards_to="iframe_figures/reward_images/step",
            epsilon_multdecay=epsilon_decay,  # 0.999,
            epsilon_minimum=0.01,
            verbosity=Verbosity.Quiet,
            title="Q-learning"
        )

    # Run Q-learning with gamma; return learner
    return qlearning_run(app_simulation)


# Benchmark parameters:
#   Parameters from DeepDoubleQ paper
#    - learning_rate = 0.00025
#    - linear epsilon decay
#    - gamma = 0.99
#   Eliminated gamma_values
#       0.0,
#       0.0015,  # too small
#       0.15,  # too big
#       0.25,  # too big
#       0.35,  # too big
#
# NOTE: Given the relatively low number of training episodes (50,
# a high learning rate of .99 gives better result
# than a lower learning rate of 0.25 (i.e. maximal rewards reached faster on average).
# Ideally we should decay the learning rate just like gamma and train over a
# much larger number of episodes
