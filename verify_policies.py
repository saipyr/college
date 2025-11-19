import yaml
import sys

def check_yaml(path):
    try:
        with open(path, 'r') as f:
            yaml.safe_load(f)
        print(f"OK: {path}")
        return True
    except Exception as e:
        print(f"FAIL: {path} - {e}")
        return False

files = [
    'remotecli/policies/windows_policy_full.yaml',
    'remotecli/policies/linux_policy_full.yaml'
]

success = True
for f in files:
    if not check_yaml(f):
        success = False

if not success:
    sys.exit(1)
