# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from gym.core import Env
from ..samples.toyctf import toy_ctf
from . import cyberbattle_env
from cyberbattle.simulation.model import Environment


class AppSimulation(cyberbattle_env.CyberBattleEnv):
    """App simulation based on a toy CTF exercise"""

    def __init__(self, env: Environment, **kwargs):
        print("getting initalized")
        super().__init__(
            initial_environment=env,
            **kwargs)
