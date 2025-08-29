from __future__ import annotations

import json
import os
from typing import Dict

import numpy as np

try:
    import matplotlib.pyplot as plt
    import seaborn as sns
except Exception:
    plt = None
    sns = None

try:
    from tqdm import tqdm
except Exception:
    def tqdm(x):
        return x

from ddos_rl.agents import SafeQLearningAgent
from ddos_rl.uav_security_env import UAVSecurityEnv, StrategicCryptoEnv


class ValidationFramework:
    def __init__(self, output_dir: str = "validation_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.scenarios = self._define_scenarios()

    def _define_scenarios(self) -> Dict[str, Dict]:
        return {
            "normal_operation": {
                "initial_battery": 100.0,
                "threat_occurrence_prob": 0.01,
                "temperature_base": 45.0,
            },
            "under_attack": {
                "initial_battery": 100.0,
                "threat_occurrence_prob": 0.3,
                "threat_escalation_prob": 0.5,
                "temperature_base": 45.0,
            },
            "low_battery": {
                "initial_battery": 40.0,
                "threat_occurrence_prob": 0.05,
                "temperature_base": 45.0,
            },
            "thermal_stress": {
                "initial_battery": 100.0,
                "threat_occurrence_prob": 0.05,
                "temperature_base": 70.0,
                "temperature_noise_std": 5.0,
            },
            "combined_stress": {
                "initial_battery": 35.0,
                "threat_occurrence_prob": 0.2,
                "temperature_base": 65.0,
            },
        }

    def validate_tactical_agent(self, agent_path: str, episodes_per_scenario: int = 50) -> Dict:
        env = UAVSecurityEnv()
        agent = SafeQLearningAgent(list(env.observation_space.nvec), env.action_space.n)
        if not agent.load_policy(agent_path):
            raise ValueError(f"Failed to load agent from {agent_path}")
        results = {}
        for name, cfg in self.scenarios.items():
            scenario_env = UAVSecurityEnv(config=cfg)
            results[name] = self._run_validation(agent, scenario_env, episodes_per_scenario)
        self._save_results(results, "tactical_validation_results.json")
        self._visualize_results(results, "tactical_validation")
        return results

    def validate_strategic_agent(self, agent_path: str, episodes_per_scenario: int = 50) -> Dict:
        env = StrategicCryptoEnv()
        agent = SafeQLearningAgent(list(env.observation_space.nvec), env.action_space.n)
        if not agent.load_policy(agent_path):
            raise ValueError(f"Failed to load agent from {agent_path}")
        results = {}
        for name, cfg in self.scenarios.items():
            scenario_env = StrategicCryptoEnv(config=cfg)
            results[name] = self._run_validation(agent, scenario_env, episodes_per_scenario)
        self._save_results(results, "strategic_validation_results.json")
        self._visualize_results(results, "strategic_validation")
        return results

    def _run_validation(self, agent: SafeQLearningAgent, env, num_episodes: int) -> Dict:
        episode_rewards, episode_lengths = [], []
        action_counts = np.zeros(env.action_space.n)
        terminal_states = []
        for _ in tqdm(range(num_episodes)):
            state, _ = env.reset()
            done = False
            truncated = False
            ep_rew = 0.0
            ep_len = 0
            info = {}
            while not (done or truncated):
                action = agent.choose_action(state, training=False)
                action_counts[action] += 1
                next_state, reward, done, truncated, info = env.step(action)
                ep_rew += float(reward)
                ep_len += 1
                state = next_state
            episode_rewards.append(ep_rew)
            episode_lengths.append(ep_len)
            if done:
                terminal_states.append({k: info.get(k, None) for k in ("battery_percent", "temperature", "threat_level")})
        action_dist = (action_counts / action_counts.sum()).tolist() if action_counts.sum() else action_counts.tolist()
        return {
            "mean_reward": float(np.mean(episode_rewards)),
            "std_reward": float(np.std(episode_rewards)),
            "min_reward": float(np.min(episode_rewards)),
            "max_reward": float(np.max(episode_rewards)),
            "mean_episode_length": float(np.mean(episode_lengths)),
            "std_episode_length": float(np.std(episode_lengths)),
            "action_distribution": action_counts.tolist(),
            "action_distribution_normalized": action_dist,
            "terminal_states": terminal_states[:10],
            "num_episodes": int(num_episodes),
        }

    def _save_results(self, results: Dict, filename: str):
        with open(os.path.join(self.output_dir, filename), "w") as f:
            json.dump(results, f, indent=2)

    def _visualize_results(self, results: Dict, prefix: str):
        if plt is None or sns is None:
            return
        self._plot_scenario_bar(results, "mean_reward", "Mean Reward", f"{prefix}_rewards.png")
        self._plot_scenario_bar(results, "mean_episode_length", "Mean Episode Length", f"{prefix}_episode_lengths.png")
        self._plot_action_distributions(results, f"{prefix}_actions.png")

    def _plot_scenario_bar(self, results: Dict, metric: str, ylabel: str, filename: str):
        if plt is None or sns is None:
            return
        scenarios = list(results.keys())
        values = [results[s][metric] for s in scenarios]
        plt.figure(figsize=(10, 6))
        sns.barplot(x=scenarios, y=values)
        plt.xlabel("Scenario")
        plt.ylabel(ylabel)
        plt.title(f"{ylabel} by Scenario")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, filename))
        plt.close()

    def _plot_action_distributions(self, results: Dict, filename: str):
        if plt is None:
            return
        num = len(results)
        fig, axs = plt.subplots(1, num, figsize=(4 * num, 6), sharey=True)
        for i, (name, res) in enumerate(results.items()):
            ax = axs[i] if num > 1 else axs
            dist = res["action_distribution_normalized"]
            ax.bar(range(len(dist)), dist)
            ax.set_title(name)
            ax.set_xlabel("Action")
            if i == 0:
                ax.set_ylabel("Frequency")
        plt.tight_layout()
        plt.savefig(os.path.join(self.output_dir, filename))
        plt.close()
