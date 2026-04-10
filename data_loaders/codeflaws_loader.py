import os
import json
from configs.path import CODEFLAWS_RESULTS_DIR

def load_all_bugs():
    """
    Loads all bug test results from the CODEFLAWS_RESULTS_DIR directory.
    Returns: list of dicts [{ 'bug_id': str, 'test_data': list }]
    """
    bugs = []
    
    if not os.path.exists(CODEFLAWS_RESULTS_DIR):
        print(f"Directory not found: {CODEFLAWS_RESULTS_DIR}")
        return bugs
        
    for filename in os.listdir(CODEFLAWS_RESULTS_DIR):
        if filename.endswith(".json"):
            file_path = os.path.join(CODEFLAWS_RESULTS_DIR, filename)
            try:
                with open(file_path, 'r') as f:
                    test_data = json.load(f)
                    
                bug_id = filename.replace('.json', '')
                bugs.append({
                    'bug_id': bug_id,
                    'test_data': test_data
                })
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
                
    return bugs
