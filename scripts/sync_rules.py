#!/usr/bin/env python3
"""
Sync Sigma rules from /rules directory to workshop_manual.md

This script reads all .yml files from the rules/ directory and updates
the corresponding YAML code blocks in workshop_manual.md, matching by rule ID.

Usage:
    python scripts/sync_rules.py

The script will:
1. Scan all .yml files in rules/
2. Extract the rule ID from each file
3. Find matching code blocks in workshop_manual.md
4. Replace the code block content with the current rule file content
"""

import os
import re
import sys
from pathlib import Path


def get_rule_id(content: str) -> str | None:
    """Extract the rule ID from a Sigma rule's YAML content."""
    match = re.search(r'^id:\s*([a-f0-9-]+)', content, re.MULTILINE)
    return match.group(1) if match else None


def load_rules(rules_dir: Path) -> dict[str, str]:
    """Load all rule files and return a dict of {rule_id: content}."""
    rules = {}
    for yml_file in rules_dir.rglob('*.yml'):
        content = yml_file.read_text(encoding='utf-8')
        rule_id = get_rule_id(content)
        if rule_id:
            # Normalize line endings and strip trailing whitespace
            content = content.replace('\r\n', '\n').rstrip()
            rules[rule_id] = content
        else:
            print(f"Warning: No rule ID found in {yml_file}", file=sys.stderr)
    return rules


def sync_manual(manual_path: Path, rules: dict[str, str]) -> tuple[int, int]:
    """
    Update YAML code blocks in the manual with content from rule files.

    Returns:
        Tuple of (rules_updated, rules_not_found)
    """
    content = manual_path.read_text(encoding='utf-8')

    # Pattern to match YAML code blocks containing Sigma rules
    # Matches ```yaml ... ``` blocks that contain an 'id:' field
    yaml_block_pattern = re.compile(
        r'(```yaml\n)(.*?)(```)',
        re.DOTALL
    )

    updated = 0
    not_found = 0

    def replace_block(match):
        nonlocal updated, not_found

        prefix = match.group(1)  # ```yaml\n
        block_content = match.group(2)
        suffix = match.group(3)  # ```

        # Check if this block contains a Sigma rule (has an id field)
        rule_id = get_rule_id(block_content)

        if rule_id and rule_id in rules:
            # Replace with the content from the rule file
            new_content = rules[rule_id]
            updated += 1
            return f"{prefix}{new_content}\n{suffix}"
        elif rule_id:
            # Rule ID found in manual but not in rules directory
            print(f"Warning: Rule {rule_id} in manual not found in rules/", file=sys.stderr)
            not_found += 1

        # Return unchanged if not a Sigma rule or not found
        return match.group(0)

    new_content = yaml_block_pattern.sub(replace_block, content)

    if new_content != content:
        manual_path.write_text(new_content, encoding='utf-8')

    return updated, not_found


def main():
    # Determine paths relative to script location
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent

    rules_dir = repo_root / 'rules'
    manual_path = repo_root / 'labs' / 'workshop_manual.md'

    if not rules_dir.exists():
        print(f"Error: Rules directory not found: {rules_dir}", file=sys.stderr)
        sys.exit(1)

    if not manual_path.exists():
        print(f"Error: Workshop manual not found: {manual_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading rules from {rules_dir}...")
    rules = load_rules(rules_dir)
    print(f"Found {len(rules)} rules")

    print(f"Syncing to {manual_path}...")
    updated, not_found = sync_manual(manual_path, rules)

    print(f"Updated {updated} rules in workshop manual")
    if not_found:
        print(f"Warning: {not_found} rules in manual not found in rules/")

    # Exit with error if any rules weren't found (useful for CI)
    if not_found > 0:
        sys.exit(1)

    print("Sync complete!")


if __name__ == '__main__':
    main()
