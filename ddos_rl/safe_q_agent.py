"""
Thread-safe, persistence-friendly Q-learning agent used by ddos_rl training and validation.
Implements the API expected by train.py and validation.py.
"""
from __future__ import annotations

from typing import List, Tuple, Optional
import threading
import queue
import os
import json
import numpy as np


class SafeQLearningAgent:
    def __init__(
        self,
        state_dims: List[int],
        action_dim: int,
        epsilon: float = 1.0,
        min_epsilon: float = 0.05,
        epsilon_decay: float = 0.995,
        gamma: float = 0.98,
        alpha: float = 0.1,
    ):
        self.state_dims = state_dims
        self.action_dim = action_dim
        self.q_table = np.zeros(state_dims + [action_dim], dtype=np.float32)

        # Learning params
        self.epsilon = float(epsilon)
        self.min_epsilon = float(min_epsilon)
        self.epsilon_decay = float(epsilon_decay)
        self.gamma = float(gamma)
        self.alpha = float(alpha)

        # Async learning
        self._queue: "queue.Queue[Tuple[Tuple[int, ...], int, float, Tuple[int, ...], bool]]" = queue.Queue(
            maxsize=20000
        )
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None

        # Bookkeeping
        self.episode_count: int = 0

    # --- Thread control (train.py expects these names) ---
    def start_learning_thread(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop.clear()
        self._worker = threading.Thread(target=self._learning_worker, daemon=True)
        self._worker.start()

    def stop_learning_thread(self) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=2)
            self._worker = None

    # --- Interaction API ---
    def choose_action(self, state: Tuple[int, ...] | np.ndarray, training: bool = True) -> int:
        s = self._to_index(state)
        if training and np.random.rand() < self.epsilon:
            return int(np.random.randint(0, self.action_dim))
        return int(np.argmax(self.q_table[s]))

    def learn(
        self,
        state: Tuple[int, ...] | np.ndarray,
        action: int,
        reward: float,
        next_state: Tuple[int, ...] | np.ndarray,
        done: bool,
    ) -> None:
        s = self._to_index(state)
        sp = self._to_index(next_state)
        try:
            self._queue.put_nowait((s, int(action), float(reward), sp, bool(done)))
        except queue.Full:
            # In overload, drop the oldest to keep learning responsive
            try:
                _ = self._queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._queue.put_nowait((s, int(action), float(reward), sp, bool(done)))
            except queue.Full:
                pass

        # Decay epsilon on each learn call when training
        if self.epsilon > self.min_epsilon:
            self.epsilon = max(self.min_epsilon, self.epsilon * self.epsilon_decay)

    # --- Persistence ---
    def save_policy(self, directory: str) -> bool:
        try:
            os.makedirs(directory, exist_ok=True)
            # Save Q-table
            np.save(os.path.join(directory, "q_table.npy"), self.q_table)
            # Write meta atomically to reduce risk of truncation
            meta = {
                "state_dims": self.state_dims,
                "action_dim": self.action_dim,
                "epsilon": self.epsilon,
                "min_epsilon": self.min_epsilon,
                "epsilon_decay": self.epsilon_decay,
                "gamma": self.gamma,
                "alpha": self.alpha,
                "episode_count": self.episode_count,
            }
            tmp_path = os.path.join(directory, "meta.json.tmp")
            final_path = os.path.join(directory, "meta.json")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(meta, f)
            os.replace(tmp_path, final_path)
            return True
        except Exception:
            return False

    def load_policy(self, directory: str) -> bool:
        try:
            q_path = os.path.join(directory, "q_table.npy")
            if not os.path.exists(q_path):
                return False
            q = np.load(q_path)
            if list(q.shape[:-1]) != self.state_dims or q.shape[-1] != self.action_dim:
                # shape mismatch
                return False
            self.q_table = q
            meta_path = os.path.join(directory, "meta.json")
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                    # Restore selected fields if present
                    self.epsilon = float(meta.get("epsilon", self.epsilon))
                    self.min_epsilon = float(meta.get("min_epsilon", self.min_epsilon))
                    self.epsilon_decay = float(meta.get("epsilon_decay", self.epsilon_decay))
                    self.gamma = float(meta.get("gamma", self.gamma))
                    self.alpha = float(meta.get("alpha", self.alpha))
                    self.episode_count = int(meta.get("episode_count", self.episode_count))
                except Exception:
                    # Ignore corrupted meta; keep q_table and defaults
                    pass
            return True
        except Exception:
            return False

    # --- Internal helpers ---
    def _to_index(self, state: Tuple[int, ...] | np.ndarray) -> Tuple[int, ...]:
        if isinstance(state, tuple):
            return state
        # Assume ndarray of ints
        return tuple(int(x) for x in np.asarray(state, dtype=np.int64).tolist())

    def _learning_worker(self) -> None:
        while not self._stop.is_set():
            try:
                s, a, r, sp, done = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            best_next = 0.0 if done else float(np.max(self.q_table[sp]))
            td_target = r + self.gamma * best_next
            td_error = td_target - float(self.q_table[s + (a,)])
            self.q_table[s + (a,)] += self.alpha * td_error
