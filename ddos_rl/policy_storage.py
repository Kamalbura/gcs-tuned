"""
FaultTolerantPolicyStorage placeholder.
Fill in later with the full implementation from your plan.
"""
from __future__ import annotations
import os
import numpy as np
from typing import List

class FaultTolerantPolicyStorage:
    def __init__(self, out_dir: str, state_dims: List[int], action_dim: int):
        self.out_dir = out_dir
        self.path = os.path.join(out_dir, 'tactical_q_table.npy')
        os.makedirs(out_dir, exist_ok=True)
        self.state_dims = state_dims
        self.action_dim = action_dim

    def load_policy(self) -> np.ndarray:
        # Try main then backup
        if os.path.exists(self.path):
            try:
                arr = np.load(self.path)
                if list(arr.shape) == self.state_dims + [self.action_dim]:
                    return arr
            except Exception:
                pass
        bak = self.path + '.bak'
        if os.path.exists(bak):
            try:
                arr = np.load(bak)
                if list(arr.shape) == self.state_dims + [self.action_dim]:
                    return arr
            except Exception:
                pass
        # Default safe policy: all zeros
        return np.zeros(self.state_dims + [self.action_dim], dtype=np.float32)

    def save_policy(self, table: np.ndarray) -> None:
        if not isinstance(table, np.ndarray):
            return
        if os.path.exists(self.path):
            try:
                os.replace(self.path, self.path + '.bak')
            except Exception:
                pass
        np.save(self.path, table)
