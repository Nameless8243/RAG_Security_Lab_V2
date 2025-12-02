# security/pipeline/output_formatter.py

import shutil
from datetime import datetime

class OutputFormatter:
    """
    Enterprise-style output formatter for the RAG Security Lab V2.
    Produces clean, screenshot-ready terminal blocks with consistent layout.
    """

    def __init__(self):
        self.width = shutil.get_terminal_size((80, 20)).columns
        self.separator = "═" * self.width
        self.line = "─" * self.width

    def header(self, title: str):
        print("")
        print(self.separator)
        print(f"  {title}")
        print(self.separator)

    def scenario_block(self, scenario_name: str, info: dict):
        print(f"\n[{scenario_name}]")
        print(f"  document_id: {info['document_id']}")
        print(f"  status      : {info['status']}")
        print(f"  reason      : {info['reason']}")
        if info.get("bundle_path"):
            print(f"  evidence    : {info['bundle_path']}")
        if info.get("semantic_scores") is not None:
            print(f"  semantic_scores: {info['semantic_scores']}")

    def summary_block(self, stats: dict):
        print("\n" + self.separator)
        print(" SUMMARY")
        print(self.line)

        print(f"  Total documents : {stats['total_docs']}")
        print(f"  Accepted        : {stats['accepted']}")
        print(f"  Quarantined     : {stats['quarantined']}")
        print(f"  Lineage blocked : {stats['lineage_blocked']}")
        print(f"  Semantic blocked: {stats['semantic_blocked']}")

        print("\n  Audit log       : data/audit/audit_log.jsonl")
        print("  Quarantine folder: data/quarantine/")
        print(self.separator)

    def timestamp(self):
        now = datetime.utcnow().isoformat() + "Z"
        print(f"Timestamp: {now}")
