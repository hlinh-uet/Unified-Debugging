import json

with open('experiments/tarantula_results.json', 'r') as f:
    data = json.load(f)

for bug, meta in data.items():
    if meta.get('ground_truth') and not meta.get('scores'):
        print(f"Bug {bug} has GT but no scores!")
