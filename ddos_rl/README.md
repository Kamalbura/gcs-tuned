# ddos_rl: UAV Security RL Framework

Quick start (Windows PowerShell):
- Activate your conda env: conda activate rl_env
- Install deps: pip install -r ddos_rl/requirements.txt
- Train a tiny smoke run: python -m ddos_rl.main --mode train --agent tactical --episodes 50
- Validate: python -m ddos_rl.main --mode validate --agent tactical --eval-episodes 10

Artifacts:
- Models in ./models (q_table.npy + meta.json)
- Logs/plots in ./logs and ./validation_results