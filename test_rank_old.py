import json

with open('experiments/fault_localization_results.json', 'r') as f:
    data = json.load(f)

for bug, meta in data.items():
    if not meta.get('ground_truth') or not meta.get('scores'):
        continue
    scores = meta['scores']
    print(f"Bug {bug}: total funcs {len(scores)}")
