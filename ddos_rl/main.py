from __future__ import annotations

import argparse
import logging
import os

from ddos_rl.train import train_tactical_agent, train_strategic_agent
from ddos_rl.validation import ValidationFramework


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("ddos_rl.main")


def parse_args():
    p = argparse.ArgumentParser(description="UAV Security RL Framework")
    p.add_argument("--mode", choices=["train", "validate"], default="train")
    p.add_argument("--agent", choices=["tactical", "strategic", "both"], default="tactical")
    p.add_argument("--episodes", type=int, default=200)
    p.add_argument("--eval-episodes", type=int, default=20)
    p.add_argument("--model-dir", type=str, default="models")
    p.add_argument("--log-dir", type=str, default="logs")
    p.add_argument("--output-dir", type=str, default="results")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.model_dir, exist_ok=True)
    os.makedirs(args.log_dir, exist_ok=True)
    if args.mode == "train":
        if args.agent in ("tactical", "both"):
            logger.info("Training tactical agent...")
            train_tactical_agent(num_episodes=args.episodes, eval_interval=max(10, args.episodes // 10), log_dir=args.log_dir, save_dir=args.model_dir)
        if args.agent in ("strategic", "both"):
            logger.info("Training strategic agent...")
            train_strategic_agent(num_episodes=args.episodes, eval_interval=max(10, args.episodes // 10), log_dir=args.log_dir, save_dir=args.model_dir)
    elif args.mode == "validate":
        vf = ValidationFramework(output_dir=args.output_dir)
        if args.agent in ("tactical", "both"):
            vf.validate_tactical_agent(os.path.join(args.model_dir, "tactical_best"), episodes_per_scenario=args.eval_episodes)
        if args.agent in ("strategic", "both"):
            vf.validate_strategic_agent(os.path.join(args.model_dir, "strategic_best"), episodes_per_scenario=args.eval_episodes)
    else:
        logger.error("Unknown mode")


if __name__ == "__main__":
    main()
