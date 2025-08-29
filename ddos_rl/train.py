from __future__ import annotations

import os
import time
from typing import Dict, Tuple

import numpy as np

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None  # optional

try:
    from tqdm import tqdm
except Exception:
    def tqdm(x):
        return x

from ddos_rl.agents import SafeQLearningAgent
from ddos_rl.uav_security_env import UAVSecurityEnv, StrategicCryptoEnv


def evaluate_agent(agent: SafeQLearningAgent, env, num_episodes: int = 10):
    eval_rewards = []
    eval_lengths = []
    action_counts = np.zeros(env.action_space.n)
    for _ in range(num_episodes):
        state, _ = env.reset()
        episode_reward = 0
        episode_length = 0
        done = False
        truncated = False
        while not (done or truncated):
            action = agent.choose_action(state, training=False)
            action_counts[action] += 1
            next_state, reward, done, truncated, _ = env.step(action)
            state = next_state
            episode_reward += reward
            episode_length += 1
        eval_rewards.append(episode_reward)
        eval_lengths.append(episode_length)
    mean_reward = float(np.mean(eval_rewards))
    mean_length = float(np.mean(eval_lengths))
    return mean_reward, mean_length


def save_training_data(episode_rewards, episode_lengths, eval_steps, eval_rewards, filepath):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    np.savez(
        filepath,
        episode_rewards=np.array(episode_rewards),
        episode_lengths=np.array(episode_lengths),
        eval_steps=np.array(eval_steps),
        eval_rewards=np.array(eval_rewards),
        timestamp=time.time(),
    )


def plot_training_curves(episode_rewards, eval_steps, eval_rewards, filepath):
    if plt is None:
        return
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12), sharex=True)
    episodes = np.arange(len(episode_rewards))
    ax1.plot(episodes, episode_rewards, alpha=0.3, label="Episode rewards")
    window_size = min(100, len(episode_rewards)) if episode_rewards else 1
    if window_size > 1:
        moving_avg = np.convolve(episode_rewards, np.ones(window_size) / window_size, mode="valid")
        ax1.plot(np.arange(len(moving_avg)) + window_size - 1, moving_avg, label=f"Moving avg ({window_size})")
    ax1.set_title("Training Rewards")
    ax1.set_ylabel("Episode Reward")
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    ax2.plot(eval_steps, eval_rewards, "o-", label="Evaluation rewards")
    ax2.set_title("Evaluation Rewards")
    ax2.set_xlabel("Episode")
    ax2.set_ylabel("Average Reward")
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(filepath)
    plt.close()


def train_tactical_agent(env_config: Dict | None = None, num_episodes: int = 1000, eval_interval: int = 100, log_dir: str = "logs", save_dir: str = "models"):
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(save_dir, exist_ok=True)
    env = UAVSecurityEnv(config=env_config)
    state_dims = env.observation_space.nvec
    action_dim = env.action_space.n
    agent = SafeQLearningAgent(list(state_dims), int(action_dim))
    agent.start_learning_thread()
    episode_rewards = []
    episode_lengths = []
    eval_rewards = []
    eval_steps = []
    best_eval_reward = float("-inf")
    start_time = time.time()
    for episode in tqdm(range(num_episodes)):
        state, _ = env.reset()
        episode_reward = 0.0
        episode_length = 0
        done = False
        truncated = False
        while not (done or truncated):
            action = agent.choose_action(state, training=True)
            next_state, reward, done, truncated, _ = env.step(action)
            agent.learn(state, int(action), float(reward), next_state, bool(done or truncated))
            state = next_state
            episode_reward += float(reward)
            episode_length += 1
        episode_rewards.append(episode_reward)
        episode_lengths.append(episode_length)
        agent.episode_count += 1
        if episode % eval_interval == 0:
            eval_reward, _ = evaluate_agent(agent, env, num_episodes=10)
            eval_rewards.append(eval_reward)
            eval_steps.append(episode)
            if eval_reward > best_eval_reward:
                best_eval_reward = eval_reward
                agent.save_policy(os.path.join(save_dir, "tactical_best"))
        if episode % (eval_interval * 5) == 0 and episode > 0:
            agent.save_policy(os.path.join(save_dir, f"tactical_checkpoint_{episode}"))
    agent.save_policy(os.path.join(save_dir, "tactical_final"))
    agent.stop_learning_thread()
    total_time = time.time() - start_time
    plot_training_curves(episode_rewards, eval_steps, eval_rewards, os.path.join(log_dir, "tactical_training_curves.png"))
    save_training_data(episode_rewards, episode_lengths, eval_steps, eval_rewards, os.path.join(log_dir, "tactical_training_data.npz"))
    return agent, total_time


def train_strategic_agent(env_config: Dict | None = None, num_episodes: int = 1000, eval_interval: int = 100, log_dir: str = "logs", save_dir: str = "models"):
    os.makedirs(log_dir, exist_ok=True)
    os.makedirs(save_dir, exist_ok=True)
    env = StrategicCryptoEnv(config=env_config)
    state_dims = env.observation_space.nvec
    action_dim = env.action_space.n
    agent = SafeQLearningAgent(list(state_dims), int(action_dim))
    agent.start_learning_thread()
    episode_rewards = []
    episode_lengths = []
    eval_rewards = []
    eval_steps = []
    best_eval_reward = float("-inf")
    start_time = time.time()
    for episode in tqdm(range(num_episodes)):
        state, _ = env.reset()
        episode_reward = 0.0
        episode_length = 0
        done = False
        truncated = False
        while not (done or truncated):
            action = agent.choose_action(state, training=True)
            next_state, reward, done, truncated, _ = env.step(action)
            agent.learn(state, int(action), float(reward), next_state, bool(done or truncated))
            state = next_state
            episode_reward += float(reward)
            episode_length += 1
        episode_rewards.append(episode_reward)
        episode_lengths.append(episode_length)
        agent.episode_count += 1
        if episode % eval_interval == 0:
            eval_reward, _ = evaluate_agent(agent, env, num_episodes=10)
            eval_rewards.append(eval_reward)
            eval_steps.append(episode)
            if eval_reward > best_eval_reward:
                best_eval_reward = eval_reward
                agent.save_policy(os.path.join(save_dir, "strategic_best"))
        if episode % (eval_interval * 5) == 0 and episode > 0:
            agent.save_policy(os.path.join(save_dir, f"strategic_checkpoint_{episode}"))
    agent.save_policy(os.path.join(save_dir, "strategic_final"))
    agent.stop_learning_thread()
    total_time = time.time() - start_time
    plot_training_curves(episode_rewards, eval_steps, eval_rewards, os.path.join(log_dir, "strategic_training_curves.png"))
    save_training_data(episode_rewards, episode_lengths, eval_steps, eval_rewards, os.path.join(log_dir, "strategic_training_data.npz"))
    return agent, total_time
