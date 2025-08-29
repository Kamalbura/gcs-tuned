"""
UAV security simulation environments (tactical and strategic).

Requires: gymnasium, numpy
"""
from __future__ import annotations

from typing import Dict, Tuple
import numpy as np

try:
    import gymnasium as gym
    from gymnasium import spaces
except Exception as e:
    raise RuntimeError("Install gymnasium in your rl_env: pip install gymnasium") from e


class UAVSecurityEnv(gym.Env):
    """
    Tactical environment for drone-side DDoS security posture decisions.
    Observations: MultiDiscrete [Threat(4), Battery(4), Thermal(3), Crypto(3)]
    Actions: 0=CONSERVE, 1=MONITOR (XGBOOST), 2=INVESTIGATE (TST)
    """

    metadata = {"render_modes": ["human"]}

    def __init__(self, config: Dict | None = None):
        super().__init__()
        self.config = self._get_default_config()
        if config:
            self.config.update(config)

        # State
        self.threat_level = 0
        self.battery_percent = self.config["initial_battery"]
        self.temperature = 45.0
        self.crypto_power_draw = 0.0
        self.ddos_power_draw = 0.0
        self.total_power_draw = 0.0
        self.cpu_frequency = 1_200_000  # Hz
        self.active_cores = 2
        self.current_crypto = "KYBER"
        self.current_ddos_model = None
        self.step_count = 0

        # Spaces
        self.action_space = spaces.Discrete(3)
        self.observation_space = spaces.MultiDiscrete([4, 4, 3, 3])

        self.performance_profiles = self._load_performance_profiles()

    def _get_default_config(self) -> Dict:
        return {
            "initial_battery": 100.0,
            "battery_capacity_wh": 133.2,  # 22.2V × 6000mAh
            "nominal_voltage": 22.2,
            "threat_occurrence_prob": 0.05,
            "threat_escalation_prob": 0.3,
            "threat_deescalation_prob": 0.1,
            "simulation_step_seconds": 2.0,
            "temperature_base": 45.0,
            "temperature_noise_std": 2.0,
            "max_steps": 500,
        }

    def _load_performance_profiles(self) -> Dict:
        return {
            "crypto": {
                "KYBER": {
                    "power_draw": {
                        "600MHz": {1: 0.21, 2: 0.20, 3: 0.25, 4: 0.27},
                        "1200MHz": {1: 0.27, 2: 0.31, 3: 0.40, 4: 0.47},
                        "1800MHz": {1: 0.44, 2: 0.51, 3: 0.65, 4: 0.81},
                    },
                    "latency": {
                        "600MHz": {1: 3.0, 2: 0.2, 3: 0.2, 4: 0.2},
                        "1200MHz": {1: 0.2, 2: 0.1, 3: 0.1, 4: 0.3},
                        "1800MHz": {1: 0.1, 2: 0.1, 3: 0.1, 4: 0.3},
                    },
                    "security_score": 85,
                },
                "DILITHIUM": {
                    "power_draw": {
                        "600MHz": {1: 0.18, 2: 0.23, 3: 0.18, 4: 0.26},
                        "1200MHz": {1: 0.28, 2: 0.33, 3: 0.40, 4: 0.51},
                        "1800MHz": {1: 0.36, 2: 0.42, 3: 0.60, 4: 0.80},
                    },
                    "latency": {
                        "600MHz": {1: 4.0, 2: 0.7, 3: 0.2, 4: 1.0},
                        "1200MHz": {1: 0.3, 2: 0.2, 3: 0.3, 4: 0.4},
                        "1800MHz": {1: 0.3, 2: 0.3, 3: 0.2, 4: 0.3},
                    },
                    "security_score": 95,
                },
                "SPHINCS": {
                    "power_draw": {
                        "600MHz": {1: 0.17, 2: 0.21, 3: 0.22, 4: 0.31},
                        "1200MHz": {1: 0.28, 2: 0.35, 3: 0.45, 4: 0.49},
                        "1800MHz": {1: 0.37, 2: 0.47, 3: 0.62, 4: 0.81},
                    },
                    "latency": {
                        "600MHz": {1: 4.2, 2: 1.8, 3: 0.3, 4: 0.2},
                        "1200MHz": {1: 0.7, 2: 0.3, 3: 0.2, 4: 0.4},
                        "1800MHz": {1: 0.3, 2: 0.2, 3: 0.2, 4: 0.2},
                    },
                    "security_score": 99,
                },
                "FALCON": {
                    "power_draw": {
                        "600MHz": {1: 0.20, 2: 0.20, 3: 0.21, 4: 0.27},
                        "1200MHz": {1: 0.27, 2: 0.33, 3: 0.44, 4: 0.49},
                        "1800MHz": {1: 0.38, 2: 0.43, 3: 0.63, 4: 0.78},
                    },
                    "latency": {
                        "600MHz": {1: 4.5, 2: 0.4, 3: 0.3, 4: 0.3},
                        "1200MHz": {1: 0.4, 2: 0.2, 3: 0.2, 4: 0.2},
                        "1800MHz": {1: 0.3, 2: 0.2, 3: 0.1, 4: 0.2},
                    },
                    "security_score": 90,
                },
            },
            "ddos": {
                "TST": {
                    "power_draw": {
                        "600MHz": {1: 4.5, 2: 4.5, 3: 4.5, 4: 4.5},
                        "1200MHz": {1: 5.0, 2: 5.0, 3: 5.0, 4: 5.0},
                        "1800MHz": {1: 5.5, 2: 5.5, 3: 5.5, 4: 5.5},
                    },
                    "execution_time": {
                        "600MHz": {1: 13.5, 2: 8.8, 3: 8.8, 4: 8.9},
                        "1200MHz": {1: 5.1, 2: 4.2, 3: 4.2, 4: 4.2},
                        "1800MHz": {1: 3.2, 2: 2.7, 3: 2.8, 4: 2.8},
                    },
                    "detection_accuracy": 0.97,
                    "prediction_time_ms": {
                        "600MHz": {1: 3.9, 2: 46.2, 3: 50.3, 4: 50.4},
                        "1200MHz": {1: 2.2, 2: 21.8, 3: 55.8, 4: 59.6},
                        "1800MHz": {1: 1.6, 2: 39.2, 3: 41.4, 4: 45.7},
                    },
                },
                "XGBOOST": {
                    "power_draw": {
                        "600MHz": {1: 2.0, 2: 2.0, 3: 2.0, 4: 2.0},
                        "1200MHz": {1: 2.5, 2: 2.5, 3: 2.5, 4: 2.5},
                        "1800MHz": {1: 3.0, 2: 3.0, 3: 3.0, 4: 3.0},
                    },
                    "execution_time": {
                        "600MHz": {1: 0.5, 2: 0.4, 3: 0.4, 4: 0.4},
                        "1200MHz": {1: 0.3, 2: 0.25, 3: 0.25, 4: 0.25},
                        "1800MHz": {1: 0.2, 2: 0.15, 3: 0.15, 4: 0.15},
                    },
                    "detection_accuracy": 0.85,
                    "prediction_time_ms": {
                        "600MHz": {1: 1.0, 2: 1.0, 3: 1.0, 4: 1.0},
                        "1200MHz": {1: 0.8, 2: 0.8, 3: 0.8, 4: 0.8},
                        "1800MHz": {1: 0.6, 2: 0.6, 3: 0.6, 4: 0.6},
                    },
                },
            },
            "base_power": {
                "600MHz": {1: 3.95, 2: 3.95, 3: 4.10, 4: 4.30},
                "1200MHz": {1: 5.35, 2: 5.50, 3: 6.10, 4: 6.70},
                "1800MHz": {1: 5.80, 2: 6.10, 3: 7.10, 4: 8.35},
            },
        }

    def _get_frequency_str(self) -> str:
        if self.cpu_frequency <= 600_000:
            return "600MHz"
        elif self.cpu_frequency <= 1_200_000:
            return "1200MHz"
        else:
            return "1800MHz"

    def reset(self, seed=None, options=None) -> Tuple[np.ndarray, Dict]:
        super().reset(seed=seed)
        self.threat_level = 0
        self.battery_percent = self.config["initial_battery"]
        self.temperature = self.config["temperature_base"] + self.np_random.normal(
            0, self.config["temperature_noise_std"]
        )
        self.cpu_frequency = 1_200_000
        self.active_cores = 2
        self.current_crypto = "KYBER"
        self.current_ddos_model = None
        self.crypto_power_draw = self.performance_profiles["crypto"]["KYBER"][
            "power_draw"
        ][self._get_frequency_str()][self.active_cores]
        self.ddos_power_draw = 0.0
        self.total_power_draw = self._calculate_total_power()
        self.step_count = 0
        return self._get_observation(), {}

    def _get_observation(self) -> np.ndarray:
        threat_state = self.threat_level
        if self.battery_percent < 20:
            battery_state = 0
        elif self.battery_percent < 50:
            battery_state = 1
        elif self.battery_percent < 80:
            battery_state = 2
        else:
            battery_state = 3
        if self.temperature < 65:
            thermal_state = 0
        elif self.temperature < 78:
            thermal_state = 1
        else:
            thermal_state = 2
        crypto_profiles = self.performance_profiles["crypto"]
        crypto_draws = [
            crypto_profiles[c]["power_draw"][self._get_frequency_str()][self.active_cores]
            for c in crypto_profiles.keys()
        ]
        avg_crypto_draw = sum(crypto_draws) / len(crypto_draws)
        low_threshold = avg_crypto_draw * 0.8
        high_threshold = avg_crypto_draw * 1.2
        if self.crypto_power_draw < low_threshold:
            crypto_state = 0
        elif self.crypto_power_draw < high_threshold:
            crypto_state = 1
        else:
            crypto_state = 2
        return np.array([threat_state, battery_state, thermal_state, crypto_state])

    def step(self, action: int):
        prev_ddos_model = self.current_ddos_model
        if action == 0:
            self.current_ddos_model = None
            self.ddos_power_draw = 0.0
        elif action == 1:
            self.current_ddos_model = "XGBOOST"
            self.ddos_power_draw = self.performance_profiles["ddos"]["XGBOOST"][
                "power_draw"
            ][self._get_frequency_str()][self.active_cores]
        elif action == 2:
            self.current_ddos_model = "TST"
            self.ddos_power_draw = self.performance_profiles["ddos"]["TST"][
                "power_draw"
            ][self._get_frequency_str()][self.active_cores]

        self.total_power_draw = self._calculate_total_power()
        self._update_threat_level()
        self._update_battery()
        self._update_temperature()
        self.step_count += 1

        observation = self._get_observation()
        reward = self._calculate_reward(prev_ddos_model)
        terminated = (self.battery_percent <= 0) or (self.temperature >= 85)
        truncated = (self.step_count >= self.config["max_steps"])
        info = {
            "battery_percent": self.battery_percent,
            "temperature": self.temperature,
            "threat_level": self.threat_level,
            "power_draw": self.total_power_draw,
            "ddos_model": self.current_ddos_model,
            "crypto_model": self.current_crypto,
        }
        return observation, reward, terminated, truncated, info

    def _calculate_total_power(self) -> float:
        freq_str = self._get_frequency_str()
        base_power = self.performance_profiles["base_power"][freq_str][self.active_cores]
        return base_power + self.crypto_power_draw + self.ddos_power_draw

    def _update_threat_level(self):
        if self.threat_level == 0:
            if self.np_random.random() < self.config["threat_occurrence_prob"]:
                self.threat_level = 1
        elif self.threat_level == 1:
            escalation_prob = self.config["threat_escalation_prob"]
            if self.current_ddos_model == "XGBOOST":
                escalation_prob *= 0.5
            elif self.current_ddos_model == "TST":
                escalation_prob *= 0.1
            if self.np_random.random() < escalation_prob:
                self.threat_level = 2
            elif self.np_random.random() < self.config["threat_deescalation_prob"]:
                self.threat_level = 0
        elif self.threat_level == 2:
            if self.current_ddos_model != "TST":
                if self.np_random.random() < 0.7:
                    self.threat_level = 3
            else:
                if self.np_random.random() < 0.2:
                    self.threat_level = 3
                elif self.np_random.random() < 0.4:
                    self.threat_level = 1
        elif self.threat_level == 3:
            if self.current_ddos_model == "TST":
                if self.np_random.random() < 0.3:
                    self.threat_level = 2

    def _update_battery(self):
        energy_wh = self.total_power_draw * (self.config["simulation_step_seconds"] / 3600)
        percent_consumed = (energy_wh / self.config["battery_capacity_wh"]) * 100
        self.battery_percent = max(0, self.battery_percent - percent_consumed)

    def _update_temperature(self):
        temp_change = -0.2
        temp_change += 0.1 * self.total_power_draw
        temp_change += self.np_random.normal(0, 0.5)
        self.temperature = max(
            self.config["temperature_base"], min(90, self.temperature + temp_change)
        )

    def _calculate_reward(self, prev_ddos_model: str | None) -> float:
        w_security, w_power, w_thermal, w_battery = 2.0, 1.0, 1.5, 2.5
        if self.current_ddos_model == "TST":
            detection_accuracy = self.performance_profiles["ddos"]["TST"][
                "detection_accuracy"
            ]
            security_reward = detection_accuracy * (self.threat_level / 3)
        elif self.current_ddos_model == "XGBOOST":
            detection_accuracy = self.performance_profiles["ddos"]["XGBOOST"][
                "detection_accuracy"
            ]
            security_reward = detection_accuracy * (self.threat_level / 3)
        else:
            security_reward = 0.1 * (self.threat_level / 3)
        if self.threat_level == 3 and self.current_ddos_model != "TST":
            security_reward -= 1.0
        power_penalty = self.total_power_draw / 15.0
        thermal_normalized = (self.temperature - 45) / 40.0
        thermal_penalty = thermal_normalized ** 2
        battery_penalty = 1.0 if self.battery_percent < 20 else 0.0
        return (
            (w_security * security_reward)
            - (w_power * power_penalty)
            - (w_thermal * thermal_penalty)
            - (w_battery * battery_penalty)
        )

    def render(self, mode="human"):
        if mode == "human":
            print(
                f"Step {self.step_count} | Threat:{self.threat_level} Battery:{self.battery_percent:.1f}% "
                f"Temp:{self.temperature:.1f}C DDoS:{self.current_ddos_model or 'None'} Power:{self.total_power_draw:.2f}W"
            )


class StrategicCryptoEnv(gym.Env):
    """GCS-side strategic crypto selection environment."""

    def __init__(self, config: Dict | None = None):
        super().__init__()
        self.config = self._get_default_config()
        if config:
            self.config.update(config)
        self.threat_level = 0
        self.avg_battery = self.config["initial_battery"]
        self.mission_phase = 0
        self.current_crypto = "KYBER"
        self.step_count = 0
        self.action_space = spaces.Discrete(4)
        self.observation_space = spaces.MultiDiscrete([3, 3, 4])
        self.performance_profiles = self._load_performance_profiles()

    def _get_default_config(self) -> Dict:
        return {
            "initial_battery": 100.0,
            "threat_occurrence_prob": 0.05,
            "threat_escalation_prob": 0.2,
            "threat_deescalation_prob": 0.1,
            "simulation_step_seconds": 5.0,
            "max_steps": 500,
            "drone_count": 3,
        }

    def _load_performance_profiles(self) -> Dict:
        return {
            "KYBER": {"security_score": 85, "power_draw": 0.35, "latency": 0.15},
            "DILITHIUM": {"security_score": 95, "power_draw": 0.45, "latency": 0.28},
            "SPHINCS": {"security_score": 99, "power_draw": 0.55, "latency": 0.65},
            "FALCON": {"security_score": 90, "power_draw": 0.40, "latency": 0.22},
        }

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.threat_level = 0
        self.avg_battery = self.config["initial_battery"]
        self.mission_phase = 0
        self.current_crypto = "KYBER"
        self.step_count = 0
        return self._get_observation(), {}

    def _get_observation(self) -> np.ndarray:
        threat_state = min(2, self.threat_level)
        if self.avg_battery < 30:
            battery_state = 0
        elif self.avg_battery < 70:
            battery_state = 1
        else:
            battery_state = 2
        mission_state = self.mission_phase
        return np.array([threat_state, battery_state, mission_state])

    def step(self, action: int):
        crypto_map = ["KYBER", "DILITHIUM", "SPHINCS", "FALCON"]
        prev_crypto = self.current_crypto
        self.current_crypto = crypto_map[action]
        self._update_threat_level()
        self._update_battery()
        self._update_mission_phase()
        self.step_count += 1
        observation = self._get_observation()
        reward = self._calculate_reward(prev_crypto)
        terminated = (self.avg_battery <= 0)
        truncated = (self.step_count >= self.config["max_steps"])
        info = {
            "avg_battery": self.avg_battery,
            "threat_level": self.threat_level,
            "mission_phase": self.mission_phase,
            "crypto_algorithm": self.current_crypto,
        }
        return observation, reward, terminated, truncated, info

    def _update_threat_level(self):
        if self.threat_level == 0:
            if self.np_random.random() < self.config["threat_occurrence_prob"]:
                self.threat_level = 1
        elif self.threat_level == 1:
            if self.np_random.random() < self.config["threat_escalation_prob"]:
                self.threat_level = 2
            elif self.np_random.random() < self.config["threat_deescalation_prob"]:
                self.threat_level = 0
        elif self.threat_level == 2:
            if self.np_random.random() < self.config["threat_deescalation_prob"]:
                self.threat_level = 1

    def _update_battery(self):
        power_draw = self.performance_profiles[self.current_crypto]["power_draw"]
        battery_drain = 0.05 + (power_draw * 0.1)
        drains = []
        for _ in range(self.config["drone_count"]):
            d = battery_drain * (0.8 + 0.4 * self.np_random.random())
            if self.mission_phase in [1, 2]:
                d *= 1.5
            drains.append(d)
        self.avg_battery = max(0, self.avg_battery - (sum(drains) / len(drains)))

    def _update_mission_phase(self):
        if self.step_count % 100 == 0:
            self.mission_phase = (self.mission_phase + 1) % 4
        if self.np_random.random() < 0.02:
            self.mission_phase = int(self.np_random.integers(0, 4))

    def _calculate_reward(self, prev_crypto: str) -> float:
        w_security, w_power, w_latency = 2.0, 1.0, 1.0
        security_score = self.performance_profiles[self.current_crypto]["security_score"] / 100.0
        threat_importance = min(1.0, self.threat_level * 0.5)
        security_reward = security_score * (0.5 + threat_importance)
        power_draw = self.performance_profiles[self.current_crypto]["power_draw"]
        battery_factor = 2.0 if self.avg_battery < 30 else (1.5 if self.avg_battery < 70 else 1.0)
        power_penalty = power_draw * battery_factor
        latency = self.performance_profiles[self.current_crypto]["latency"]
        mission_factor = 2.0 if self.mission_phase == 2 else (0.5 if self.mission_phase == 0 else 1.0)
        latency_penalty = latency * mission_factor
        reward = (w_security * security_reward) - (w_power * power_penalty) - (w_latency * latency_penalty)
        if self.step_count > 0 and prev_crypto != self.current_crypto:
            reward -= 0.2
        return reward
