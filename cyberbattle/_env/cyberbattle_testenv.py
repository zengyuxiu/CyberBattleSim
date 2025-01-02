# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""CyberBattle environment based on a simple chain network structure"""

from ..samples.testenv import testenv
from . import cyberbattle_env


class CyberBattleTestEnv(cyberbattle_env.CyberBattleEnv):
    """CyberBattle environment based on a simple chain network structure"""

    def __init__(self, data, size, **kwargs):
        self.size = size
        self.data = data
        super().__init__(initial_environment=testenv.new_environment(data,size), **kwargs)

    @property
    def name(self) -> str:
        return f"CyberBattleTestEnv-{self.size}"
