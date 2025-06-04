#!/usr/bin/env python3
"""
main.py

1) Downloads the CIS Microsoft Windows Server 2022 v3.0.0 L1 Member Server .audit file
   from Tenable (using the provided API URL).
2) Reads it as plain text and extracts each <custom_item> … </custom_item> block.
3) For each block, parses out:
     - Section        (first segment zero-padded if <10)
     - Level
     - Name
     - Description    (all text in the `info : "…"` field, multiline)
     - Remediation Procedure (all text in the `solution : "…"` field, multiline)
     - NIST           (all `800-53|…` entries from `reference : "…"` field)
4) Writes results into:
     • cis_win2022_from_audit.csv
     • cis_win2022_from_audit.xlsx
"""

import requests
import pandas as pd
import re
import sys

# ─────────────────────────────────────────────────────────────────────────────
# 1) CONFIGURATION: URL & FILENAMES
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
# 2) STEP 1: DOWNLOAD THE .audit FILE (RAW TEXT)
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
# 3) STEP 2: READ THE FILE AS TEXT AND EXTRACT <custom_item> BLOCKS
# ─────────────────────────────────────────────────────────────────────────────

print("2) Extracting <custom_item> blocks…")

try:
    raw_text = open(LOCAL_AUDIT_FILE, "r", encoding="utf-8", errors="replace").read()
except Exception as e:
    print(f"ERROR: Could not read {LOCAL_AUDIT_FILE}:\n  {e}")
    sys.exit(1)

# Use a regex with DOTALL to find everything between <custom_item> and </custom_item>
pattern = re.compile(r"<custom_item>(.*?)</custom_item>", re.DOTALL)
matches = pattern.findall(raw_text)

if not matches:
    print("ERROR: No <custom_item> blocks found in the .audit file.")
    sys.exit(1)

print(f"   • Found {len(matches)} <custom_item> blocks.\n")


# ─────────────────────────────────────────────────────────────────────────────
# 4) UTILITY FUNCTIONS TO PARSE ONE <custom_item> BLOCK INTO FIELDS
# ─────────────────────────────────────────────────────────────────────────────

def parse_description_field(desc_field: str):
    """
    Given a string like:
      1.1.7 (L1) Ensure 'Store passwords using reversible encryption' is set to 'Disabled'
    Return:
      - section = "01.1.7"   (zero‐padded if the first segment <10)
      - level   = "1"
      - name    = "Ensure 'Store passwords using reversible encryption' is set to 'Disabled'"
    """
    m = re.match(r"^\s*([\d\.]+)\s*\(L(\d+)\)\s*(.+)$", desc_field.strip())
    if not m:
        return "", "", desc_field.strip().strip('"')

    section_raw = m.group(1).strip()  # e.g. "1.1.7"
    level = m.group(2).strip()        # e.g. "1"
    name = m.group(3).strip().strip('"')

    # Zero-pad the first segment if <10:
    # Split at the first dot
    if "." in section_raw:
        first_seg, rest = section_raw.split(".", 1)
        if first_seg.isdigit() and int(first_seg) < 10:
            first_seg = first_seg.zfill(2)  # e.g. "1" -> "01"
        section = first_seg + "." + rest
    else:
        # No dot present (unlikely), but handle single‐segment sections:
        if section_raw.isdigit() and int(section_raw) < 10:
            section = section_raw.zfill(2)
        else:
            section = section_raw

    return section, level, name


def split_reference_for_nist(ref_field: str):
    """
    Given a comma-separated reference string, e.g.:
      "800-171|3.5.2,800-53|IA-5(1),800-53r5|IA-5(1),CSCv7|16.2,…"
    Return only the parts that start with "800-53", joined by ", ".
    """
    parts = [p.strip() for p in ref_field.split(",") if p.strip()]
    nist_only = [p for p in parts if p.startswith("800-53")]
    return ", ".join(nist_only)


def parse_custom_item_block(block_text: str):
    """
    Given the *inner* text of a <custom_item>…</custom_item> block, parse out
    keys and their (possibly multiline) quoted values. Extract:
      - description : "…"
      - info        : "…"
      - solution    : "…"
      - reference   : "…"
    Then build and return a dict with:
      Section, Level, Name, Description, Remediation Procedure, NIST
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

        # If the value starts with a quote but does NOT end with a quote on this line,
        # accumulate subsequent lines until we find the closing quote.
        if val.startswith('"') and not val.rstrip().endswith('"'):
            # Remove the opening quote
            val_accum = val[1:]  # everything after the first "
            # Accumulate until closing quote
            while idx < total:
                next_line = lines[idx]
                idx += 1
                val_accum += "\n" + next_line
                if next_line.rstrip().endswith('"'):
                    break
            # Now val_accum ends with a closing quote
            if val_accum.endswith('"'):
                val_accum = val_accum[:-1]
            data[key] = val_accum.strip()
        else:
            # Entire value is on this line (possibly quoted or not)
            data[key] = val.strip().strip('"')

    desc_field = data.get("description", "")
    section, level, name = parse_description_field(desc_field)

    description_text = data.get("info", "")
    remediation_text = data.get("solution", "")
    reference_field = data.get("reference", "")
    nist_field = split_reference_for_nist(reference_field)

    return {
        "Section": section,
        "Level": level,
        "Name": name,
        "Description": description_text,
        "Remediation Procedure": remediation_text,
        "NIST": nist_field
    }


# ─────────────────────────────────────────────────────────────────────────────
# 5) STEP 3: PARSE ALL MATCHES INTO ROWS
# ─────────────────────────────────────────────────────────────────────────────

print("3) Parsing each <custom_item> block into structured rows…")
rows = []
for idx, block_inner in enumerate(matches, start=1):
    entry = parse_custom_item_block(block_inner)
    rows.append(entry)
print(f"   • Parsed {len(rows)} rows.\n")


# ─────────────────────────────────────────────────────────────────────────────
# 6) STEP 4: DUMP TO CSV & EXCEL
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

print("✅ All done! You now have a CSV and an Excel file with the six requested columns.")