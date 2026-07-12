#!/usr/bin/env python3
"""
Establish baseline script for WhoisRefresh.

This script:
1. Reads refresh-results.json to know which domains succeeded/failed
2. Reads domains.jsonc to know the domain→server→status mapping
3. For each server/tld/status directory:
   - Maps old-named sample files to domains via test assertions
   - For successful servers: deletes old files (new domain-named files already exist)
   - For static (all-failed) servers: renames old files to domain names (or deletes if
     domain-named file already exists from partial download)
4. Updates test files to use domain-named filenames
5. Marks failed servers as static: true in domains.jsonc

Usage:
    python3 tools/establish-baseline.py [--dry-run]
"""

import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_FILE = os.path.join(REPO_ROOT, "tools/WhoisRefresh/refresh-results.json")
DOMAINS_FILE = os.path.join(REPO_ROOT, "tools/WhoisRefresh/domains.jsonc")
SAMPLES_DIR = os.path.join(REPO_ROOT, "tests/Whois.Tests/Samples")
PARSING_DIR = os.path.join(REPO_ROOT, "tests/Whois.Tests/Parsing")

DRY_RUN = "--dry-run" in sys.argv

# ── helpers ───────────────────────────────────────────────────────────────────

def strip_jsonc_comments(text):
    """Remove // line comments from JSONC text."""
    return re.sub(r"//[^\n]*", "", text)


def load_results():
    with open(RESULTS_FILE) as f:
        return json.load(f)


def load_domains():
    content = open(DOMAINS_FILE).read()
    return json.loads(strip_jsonc_comments(content))


def find_fully_failed_servers(results):
    """Return server names where ALL domain queries failed (connection or parse)."""
    failed = set()
    for server, tlds in results["results"].items():
        all_fail = True
        for tld, statuses in tlds.items():
            for status, domains in statuses.items():
                for domain, result in domains.items():
                    if result.get("error") is None:
                        all_fail = False
        if all_fail:
            failed.add(server)
    return failed


def find_test_file(server, tld):
    """Find the single *ParsingTests.cs file for this server/tld combination."""
    tld_dir = os.path.join(PARSING_DIR, server, tld)
    if not os.path.isdir(tld_dir):
        return None
    for fname in os.listdir(tld_dir):
        if fname.endswith("ParsingTests.cs"):
            return os.path.join(tld_dir, fname)
    return None


def extract_filename_to_domain_map(test_file, server, tld, status):
    """
    Parse test file and return {old_filename: domain_name}.

    Finds pairs of:
        SampleReader.Read(server, tld, status, "old_filename")
    and (in the same test method body):
        Assert.Equal("domain.name", response.DomainName...)

    Returns only the FIRST old_filename that maps to each domain (for duplicates).
    """
    content = open(test_file).read()

    # Split by [Fact] to isolate each test method
    method_pattern = re.compile(r'\[Fact\].*?(?=\[Fact\]|\Z)', re.DOTALL)

    # Build pattern for SampleReader.Read with this specific server/tld/status
    read_pattern = re.compile(
        r'SampleReader\.Read\s*\(\s*"' + re.escape(server) + r'"\s*,\s*"'
        + re.escape(tld) + r'"\s*,\s*"' + re.escape(status) + r'"\s*,\s*"([^"]+)"\s*\)',
        re.IGNORECASE
    )

    # Pattern for DomainName assertion: Assert.Equal("domain.name", response.DomainName...)
    domain_pattern = re.compile(
        r'Assert\.Equal\s*\(\s*"([^"]+)"\s*,\s*response\.DomainName'
    )

    # Track which domains are already claimed (for duplicate handling)
    claimed_domains = set()
    mapping = {}

    for method_match in method_pattern.finditer(content):
        method_body = method_match.group(0)

        read_match = read_pattern.search(method_body)
        if not read_match:
            continue

        old_filename = read_match.group(1)

        domain_match = domain_pattern.search(method_body)
        if not domain_match:
            continue

        domain_name = domain_match.group(1)

        if domain_name in claimed_domains:
            # Two tests use the same domain — only the first one gets renamed/deleted.
            # The others are left as-is (their old name stays, test reference stays).
            print(f"  SKIP (duplicate domain {domain_name}): {server}/{tld}/{status}/{old_filename}")
            continue

        claimed_domains.add(domain_name)
        mapping[old_filename] = domain_name

    return mapping


def is_domain_named_file(filename):
    """
    A domain-named file looks like 'google.co.uk.txt' or 'google.se.txt'.
    Old-named files look like 'found.txt', 'found_status_registered.txt', etc.
    Heuristic: contains at least one dot before '.txt'.
    """
    base = filename[:-4] if filename.endswith(".txt") else filename
    return "." in base


def update_test_file(test_file, server, tld, status, old_filename, new_filename):
    """Replace SampleReader.Read(..., old_filename) with new_filename in test file."""
    content = open(test_file).read()

    old_call = f'SampleReader.Read("{server}", "{tld}", "{status}", "{old_filename}")'
    new_call = f'SampleReader.Read("{server}", "{tld}", "{status}", "{new_filename}")'

    if old_call not in content:
        return False

    new_content = content.replace(old_call, new_call)
    if not DRY_RUN:
        with open(test_file, "w") as f:
            f.write(new_content)
    return True


def mark_server_static(server):
    """Add 'static': true to a server entry in domains.jsonc."""
    content = open(DOMAINS_FILE).read()

    # Find the opening brace of this server's entry
    pattern = re.compile(r'("' + re.escape(server) + r'"\s*:\s*\{)')
    match = pattern.search(content)
    if not match:
        print(f"  WARNING: Could not find {server} in domains.jsonc to mark static")
        return

    # Find the end of this server's block by looking for the next top-level entry.
    # The next entry starts with '    "servername"' at 4 spaces indent, or closing '  }'.
    # We use a simple heuristic: find the next closing brace at 4-space indent.
    rest = content[match.end():]
    block_end_match = re.search(r'\n    \}', rest)
    block_content = rest[:block_end_match.end()] if block_end_match else rest[:200]

    if '"static"' in block_content:
        print(f"  {server} already has static field")
        return

    insert_pos = match.end()
    new_content = content[:insert_pos] + '\n      "static": true,' + content[insert_pos:]

    if not DRY_RUN:
        with open(DOMAINS_FILE, "w") as f:
            f.write(new_content)


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    prefix = "DRY RUN: " if DRY_RUN else ""
    print(f"{prefix}Loading data...")

    results = load_results()
    domains_data = load_domains()
    failed_servers = find_fully_failed_servers(results)

    print(f"  Fully-failed (static) servers: {len(failed_servers)}")

    # Build: (server, tld, status) -> set of domains from domains.jsonc
    domain_registry = {}
    for server, srv in domains_data["servers"].items():
        tld = srv["tld"]
        for status, domains in srv.get("domains", {}).items():
            domain_registry[(server, tld, status)] = set(domains)

    stats = {
        "files_deleted": 0,
        "files_renamed": 0,
        "tests_updated": 0,
        "servers_marked_static": 0,
        "skipped_no_domain_mapping": 0,
        "skipped_domain_not_in_registry": 0,
        "skipped_duplicate_domain": 0,
        "warnings": 0,
    }

    # Process each server/tld/status directory in Samples
    for server in sorted(os.listdir(SAMPLES_DIR)):
        server_dir = os.path.join(SAMPLES_DIR, server)
        if not os.path.isdir(server_dir):
            continue

        is_static = server in failed_servers

        for tld in sorted(os.listdir(server_dir)):
            tld_dir = os.path.join(server_dir, tld)
            if not os.path.isdir(tld_dir):
                continue

            for status in sorted(os.listdir(tld_dir)):
                status_dir = os.path.join(tld_dir, status)
                if not os.path.isdir(status_dir):
                    continue

                # Find the test file for this server/tld
                test_file = find_test_file(server, tld)
                if test_file is None:
                    continue

                # Get filename→domain mapping from test assertions
                filename_to_domain = extract_filename_to_domain_map(
                    test_file, server, tld, status
                )

                # List old-named files (those without dots in basename)
                files = os.listdir(status_dir)
                old_files = [f for f in files if not is_domain_named_file(f) and f.endswith(".txt")]

                for old_file in sorted(old_files):
                    domain = filename_to_domain.get(old_file)

                    if domain is None:
                        # No domain mapping found in test assertions — leave alone
                        stats["skipped_no_domain_mapping"] += 1
                        print(f"  SKIP (no domain mapping): {server}/{tld}/{status}/{old_file}")
                        continue

                    # Check if this domain is in the domains.jsonc registry
                    registry_domains = domain_registry.get((server, tld, status), set())
                    if domain not in registry_domains:
                        # Domain tested but not in registry — leave alone
                        stats["skipped_domain_not_in_registry"] += 1
                        print(f"  SKIP (domain not in registry): {server}/{tld}/{status}/{old_file} → {domain}")
                        continue

                    new_filename = f"{domain}.txt"
                    old_path = os.path.join(status_dir, old_file)
                    new_path = os.path.join(status_dir, new_filename)

                    # Skip if old file and new file are the same (domain has no extension,
                    # e.g. domain="be" → new_filename="be.txt" = old_filename)
                    if old_file == new_filename:
                        stats["skipped_no_domain_mapping"] += 1
                        print(f"  SKIP (same name): {server}/{tld}/{status}/{old_file}")
                        continue

                    if is_static:
                        # Static server: old file needs to become domain-named
                        if os.path.exists(new_path):
                            # Domain-named file already exists (refresh downloaded it
                            # even though parsing failed). Delete the old file.
                            print(f"  DELETE (static, new exists): {server}/{tld}/{status}/{old_file}")
                            if not DRY_RUN:
                                os.remove(old_path)
                            stats["files_deleted"] += 1
                        else:
                            # Rename old file to domain-named file
                            print(f"  RENAME (static): {server}/{tld}/{status}/{old_file} → {new_filename}")
                            if not DRY_RUN:
                                os.rename(old_path, new_path)
                            stats["files_renamed"] += 1
                    else:
                        # Successful server: domain-named file should already exist
                        if not os.path.exists(new_path):
                            print(f"  WARNING: {new_path} missing for successful server")
                            stats["warnings"] += 1
                            continue
                        # Delete the old file (superseded by domain-named file)
                        print(f"  DELETE (success): {server}/{tld}/{status}/{old_file}")
                        if not DRY_RUN:
                            os.remove(old_path)
                        stats["files_deleted"] += 1

                    # Update the test file reference
                    updated = update_test_file(test_file, server, tld, status, old_file, new_filename)
                    if updated:
                        print(f"  TEST UPDATE: {os.path.basename(test_file)}: {old_file} → {new_filename}")
                        stats["tests_updated"] += 1
                    else:
                        print(f"  WARNING: could not update test file for {old_file}")
                        stats["warnings"] += 1

    # Mark static servers in domains.jsonc
    print("\nMarking static servers in domains.jsonc...")
    for server in sorted(failed_servers):
        if server in domains_data["servers"]:
            print(f"  static: {server}")
            mark_server_static(server)
            stats["servers_marked_static"] += 1
        else:
            print(f"  SKIP (not in domains.jsonc): {server}")

    print("\n=== STATS ===")
    for k, v in stats.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
