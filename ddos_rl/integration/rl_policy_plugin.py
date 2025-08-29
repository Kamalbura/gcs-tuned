from __future__ import annotations

import logging
import os
from typing import Dict, Optional

import numpy as np

from ddos_rl.agents import SafeQLearningAgent


logger = logging.getLogger("RLPolicyPlugin")


class RLPolicyPlugin:
    """
    Lightweight integration layer to access trained RL agents from scheduler code.
    Does not modify existing schedulers; import and use explicitly.
    """

    def __init__(self, config: Dict | None = None):
        self.config = {
            "tactical_agent_path": os.path.join("models", "tactical_best"),
            "strategic_agent_path": os.path.join("models", "strategic_best"),
            "learning_enabled": False,
        }
        if config:
            self.config.update(config)
        self.tactical_agent: Optional[SafeQLearningAgent] = None
        self.strategic_agent: Optional[SafeQLearningAgent] = None
        if self.config.get("tactical_agent_path"):
            self._load_tactical_agent(self.config["tactical_agent_path"])
        if self.config.get("strategic_agent_path"):
            self._load_strategic_agent(self.config["strategic_agent_path"])

    def _load_tactical_agent(self, path: str) -> bool:
        try:
            state_dims = [4, 4, 3, 3]
            action_dim = 3
            self.tactical_agent = SafeQLearningAgent(state_dims, action_dim)
            ok = self.tactical_agent.load_policy(path)
            if ok and self.config.get("learning_enabled"):
                self.tactical_agent.start_learning_thread()
            return ok
        except Exception as e:
            logger.error(f"Failed to load tactical agent: {e}")
            self.tactical_agent = None
            return False

    def _load_strategic_agent(self, path: str) -> bool:
        try:
            state_dims = [3, 3, 4]
            action_dim = 4
            self.strategic_agent = SafeQLearningAgent(state_dims, action_dim)
            ok = self.strategic_agent.load_policy(path)
            if ok and self.config.get("learning_enabled"):
                self.strategic_agent.start_learning_thread()
            return ok
        except Exception as e:
            logger.error(f"Failed to load strategic agent: {e}")
            self.strategic_agent = None
            return False

    def get_tactical_action(self, system_state: Dict) -> Optional[int]:
        if not self.tactical_agent:
            return None
        s = self._get_tactical_state(system_state)
        return int(self.tactical_agent.choose_action(s, training=False))

    def get_strategic_action(self, fleet_state: Dict) -> Optional[int]:
        if not self.strategic_agent:
            return None
        s = self._get_strategic_state(fleet_state)
        return int(self.strategic_agent.choose_action(s, training=False))

    @staticmethod
    def _get_tactical_state(system_state: Dict) -> np.ndarray:
        threat = int(system_state.get("threat_level", 0))
        batt = float(system_state.get("battery_percent", 100.0))
        if batt < 20:
            batt_s = 0
        elif batt < 50:
            batt_s = 1
        elif batt < 80:
            batt_s = 2
        else:
            batt_s = 3
        temp = float(system_state.get("temperature", 45.0))
        if temp < 65:
            therm = 0
        elif temp < 78:
            therm = 1
        else:
            therm = 2
        power = float(system_state.get("power_draw_watts", 0.0))
        if power < 5:
            crypto_s = 0
        elif power < 8:
            crypto_s = 1
        else:
            crypto_s = 2
        return np.array([threat, batt_s, therm, crypto_s])

    @staticmethod
    def _get_strategic_state(fleet_state: Dict) -> np.ndarray:
        threat = min(2, int(fleet_state.get("threat_level", 0)))
        batt = float(fleet_state.get("avg_battery_percent", 100.0))
        if batt < 30:
            batt_s = 0
        elif batt < 70:
            batt_s = 1
        else:
            batt_s = 2
        mission = int(fleet_state.get("mission_phase", 0))
        return np.array([threat, batt_s, mission])

    def shutdown(self):
        if self.tactical_agent and self.config.get("learning_enabled"):
            self.tactical_agent.stop_learning_thread()
        if self.strategic_agent and self.config.get("learning_enabled"):
            self.strategic_agent.stop_learning_thread()
