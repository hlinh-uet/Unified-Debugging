import json

with open('experiments/fault_localization_results.json', 'r') as f:
    data = json.load(f)

for bug, meta in data.items():
    if not meta.get('ground_truth') or not meta.get('scores'):
        continue
    scores = meta['scores']
    gt = meta['ground_truth'][0] if meta['ground_truth'] else None
    if gt and gt in scores:
        print(f"Bug {bug}: GT {gt} score {scores[gt]}")
        # Count how many scores are strictly greater
        greater = sum(1 for s in scores.values() if s > scores[gt])
        # Count how many scores are equal
        equal = sum(1 for s in scores.values() if s == scores[gt])
        print(f"  Greater: {greater}, Equal: {equal}, Rank: {greater + equal}")
