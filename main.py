#!/usr/bin/env python3
"""
main.py (first‐segment padding only)

1) Downloads the CIS Microsoft Windows Server 2022 .audit file.
2) Extracts each <custom_item> … </custom_item> block.
3) For each block, parses out:
     - Section            (only first segment zero‐padded to 2 digits)
     - Level
     - Name
     - Description        (full multiline info)
     - Remediation Procedure (full multiline solution)
     - NIST               (every 800‐53* reference, each on its own line)
4) Writes:
     • cis_win2022_from_audit.csv
     • cis_win2022_from_audit.xlsx
"""

import requests
import pandas as pd
import re
import sys

# ─────────────────────────────────────────────────────────────────────────────
# 1) CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

AUDIT_URL = (
    "https://www.tenable.com/audits/api/v1/files/"
    "CIS_Microsoft_Windows_Server_2022_v3.0.0_L1_Member_Server/download"
)
LOCAL_AUDIT_FILE = "cis_win2022.audit"
CSV_OUTPUT = "cis_win2022_from_audit.csv"
XLSX_OUTPUT = "cis_win2022_from_audit.xlsx"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/100.0.4896.75 Safari/537.36"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2) DOWNLOAD THE .audit FILE
# ─────────────────────────────────────────────────────────────────────────────

print(f"1) Downloading .audit file from:\n   {AUDIT_URL}")
try:
    resp = requests.get(AUDIT_URL, headers=HEADERS)
    resp.raise_for_status()
except requests.exceptions.RequestException as e:
    print(f"ERROR: Failed to download .audit file:\n  {e}")
    sys.exit(1)

with open(LOCAL_AUDIT_FILE, "wb") as f:
    f.write(resp.content)

print(f"   ✔ Saved to: {LOCAL_AUDIT_FILE}\n")

# ─────────────────────────────────────────────────────────────────────────────
# 3) EXTRACT <custom_item> BLOCKS FROM RAW TEXT
# ─────────────────────────────────────────────────────────────────────────────

print("2) Extracting <custom_item> blocks…")
try:
    raw_text = open(LOCAL_AUDIT_FILE, "r", encoding="utf-8", errors="replace").read()
except Exception as e:
    print(f"ERROR: Could not read {LOCAL_AUDIT_FILE}:\n  {e}")
    sys.exit(1)

pattern = re.compile(r"<custom_item>(.*?)</custom_item>", re.DOTALL)
matches = pattern.findall(raw_text)

if not matches:
    print("ERROR: No <custom_item> blocks found in the .audit file.")
    sys.exit(1)

print(f"   • Found {len(matches)} <custom_item> blocks.\n")

# ─────────────────────────────────────────────────────────────────────────────
# 4) HELPERS TO PARSE ONE <custom_item> BLOCK
# ─────────────────────────────────────────────────────────────────────────────

def parse_description_field(desc_field: str):
    """
    Input example:
      1.1.7 (L1) Ensure '…'
    Pad only the first segment:
      '1.1.7' → '01.1.7'
      '9.9.9' → '09.9.9'
      '1.12.3'→ '01.12.3'
      '10.2.4'→ '10.2.4' (no change)
    """
    desc_field = desc_field.strip().strip('"')
    m = re.match(r"^(\d+)(\.\d+(?:\.\d+)*)\s*\(L(\d+)\)\s*(.+)$", desc_field)
    if not m:
        # fallback if regex fails
        return "", "", desc_field

    first_seg     = m.group(1)         # e.g. "1" or "9" or "10"
    rest_segments = m.group(2)         # e.g. ".1.7" or ".12.3" or ".2.4"
    level         = m.group(3).strip() # e.g. "1"
    name          = m.group(4).strip() # e.g. "Ensure '…'"

    # Pad only the first segment to two digits if < 10
    if len(first_seg) < 2:
        padded_first = first_seg.zfill(2)  # "1"→"01", "9"→"09"
    else:
        padded_first = first_seg             # "10" stays "10", "19" stays "19"

    section = padded_first + rest_segments  # e.g. "01" + ".1.7" → "01.1.7"
    return section, level, name


def extract_nist_each_line(ref_field: str):
    """
    Given a comma-separated string of controls, e.g.:
      "800-171|3.5.2,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|16.10,…"
    Return a string where each 800-53* token is on its own line:
      "800-53|IA-5(1)\n800-53r5|IA-5(1)"
    """
    parts = [p.strip() for p in ref_field.split(",") if p.strip()]
    nist_list = [p for p in parts if p.startswith("800-53")]
    return "\n".join(nist_list)


def parse_custom_item_block(block_text: str):
    """
    Given everything inside <custom_item>…</custom_item>, parse out:
      - description
      - info
      - solution
      - reference
    Return dict with:
      Section, Level, Name,
      Description (full info),
      Remediation Procedure (full solution),
      NIST (800-53 lines)
    """
    data = {}
    lines = block_text.splitlines()
    idx = 0
    total = len(lines)

    while idx < total:
        line = lines[idx]
        idx += 1
        if ":" not in line:
            continue

        key_part, val_part = line.split(":", 1)
        key = key_part.strip()
        val = val_part.lstrip()

        # If it starts with " but doesn’t end with " → multiline
        if val.startswith('"') and not val.rstrip().endswith('"'):
            val_accum = val[1:]  # drop opening "
            while idx < total:
                next_line = lines[idx]
                idx += 1
                val_accum += "\n" + next_line
                if next_line.rstrip().endswith('"'):
                    break
            if val_accum.endswith('"'):
                val_accum = val_accum[:-1]
            data[key] = val_accum.strip()
        else:
            data[key] = val.strip().strip('"')

    desc_field = data.get("description", "")
    section, level, name = parse_description_field(desc_field)

    description_text = data.get("info", "")
    remediation_text = data.get("solution", "")
    reference_field = data.get("reference", "")

    nist_multiline = extract_nist_each_line(reference_field)

    return {
        "Section": section,
        "Level": level,
        "Name": name,
        "Description": description_text,
        "Remediation Procedure": remediation_text,
        "NIST": nist_multiline
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5) PARSE ALL MATCHES INTO ROWS
# ─────────────────────────────────────────────────────────────────────────────

print("3) Parsing each <custom_item> block into structured rows…")
rows = []
for idx, block_inner in enumerate(matches, start=1):
    entry = parse_custom_item_block(block_inner)
    rows.append(entry)
print(f"   • Parsed {len(rows)} rows.\n")

# ─────────────────────────────────────────────────────────────────────────────
# 6) DUMP TO CSV & EXCEL
# ─────────────────────────────────────────────────────────────────────────────

print("4) Writing to CSV and Excel…")
df = pd.DataFrame(
    rows,
    columns=[
        "Section",
        "Level",
        "Name",
        "Description",
        "Remediation Procedure",
        "NIST"
    ]
)

df.to_csv(CSV_OUTPUT, index=False, encoding="utf-8")
df.to_excel(XLSX_OUTPUT, index=False)

print(f"   ✔ {CSV_OUTPUT}")
print(f"   ✔ {XLSX_OUTPUT}\n")

print("✅ All done!")
