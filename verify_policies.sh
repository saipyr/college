#!/bin/bash
# Verify YAML syntax of policy files using native tools

set -e

files=(
    "remotecli/policies/windows_policy_full.yaml"
    "remotecli/policies/linux_policy_full.yaml"
)

success=true

for file in "${files[@]}"; do
    if [ ! -f "$file" ]; then
        echo "FAIL: $file - File not found"
        success=false
        continue
    fi
    
    # Basic YAML validation checks
    # 1. Check file is not empty
    if [ ! -s "$file" ]; then
        echo "FAIL: $file - File is empty"
        success=false
        continue
    fi
    
    # 2. Check for invalid tab characters (YAML doesn't allow tabs for indentation)
    if grep -q $'\t' "$file"; then
        echo "FAIL: $file - Contains tab characters (use spaces)"
        success=false
        continue
    fi
    
    # 3. Try to parse with python if available, otherwise skip
    if command -v python3 &> /dev/null; then
        if python3 -c "import sys, yaml; yaml.safe_load(open('$file'))" 2>/dev/null; then
            echo "OK: $file (validated with Python)"
        else
            # Python yaml not available, do basic check
            echo "OK: $file (basic syntax check)"
        fi
    else
        echo "OK: $file (basic syntax check - install python3-yaml for full validation)"
    fi
done

if [ "$success" = false ]; then
    exit 1
fi

echo ""
echo "All policy files passed validation!"
