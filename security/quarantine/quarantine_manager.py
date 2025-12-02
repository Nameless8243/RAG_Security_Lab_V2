import os
import json
import hashlib
from datetime import datetime
from typing import Any, Dict, Optional


class QuarantineManager:
    """
    Handles storing suspicious documents, lineage records, semantic scores,
    and metadata inside bundles located under a configured quarantine directory.
    """

    def __init__(self, quarantine_dir: str = "data/quarantine"):
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def _bundle_path(self, document_id: str) -> str:
        timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        safe_id = document_id.replace(" ", "_")
        path = os.path.join(self.quarantine_dir, f"{timestamp}_{safe_id}")
        os.makedirs(path, exist_ok=True)
        return path

    def _write_text(self, path: str, content: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

    def _write_json(self, path: str, data: Dict[str, Any]):
        # Safely convert numpy types to native Python types
        def default(o):
            try:
                return o.item()
            except Exception:
                raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=default)

    def save_evidence_bundle(
        self,
        document_id: str,
        content: str,
        reason: str,
        lineage_record: Optional[Dict[str, Any]] = None,
        detection_scores: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:

        bundle_path = self._bundle_path(document_id)

        # content
        self._write_text(os.path.join(bundle_path, "content.txt"), content)

        # reason
        self._write_text(os.path.join(bundle_path, "reason.txt"), reason)

        # lineage record
        if lineage_record:
            self._write_json(os.path.join(bundle_path, "lineage_record.json"), lineage_record)

        # semantic / detection scores
        if detection_scores:
            self._write_json(os.path.join(bundle_path, "detection_scores.json"), detection_scores)

        # metadata
        if metadata:
            self._write_json(os.path.join(bundle_path, "metadata.json"), metadata)

        return bundle_path
