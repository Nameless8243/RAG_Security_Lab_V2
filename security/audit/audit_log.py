import json
import hashlib
import time
from dataclasses import dataclass, asdict
from typing import Optional


def sha256_hex(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


@dataclass
class AuditLogEntry:
    index: int
    timestamp: str
    event_type: str
    document_id: str
    stage: str
    status: str
    reason: str
    details: dict
    prev_hash: Optional[str]
    entry_hash: Optional[str] = None


class AuditLog:
    """
    Tamper-evident hash-chain audit log.
    Each entry includes:
      - prev_hash
      - entry_hash = SHA256(entry_without_hash + prev_hash)
    """

    def __init__(self, path: str = "data/audit/audit_log.jsonl"):
        self.path = path
        self._last_hash = None
        self._counter = 0

    def _compute_entry_hash(self, entry_dict: dict) -> str:
        payload = json.dumps(entry_dict, sort_keys=True).encode("utf-8")
        return sha256_hex(payload)

    def write_event(
        self,
        event_type: str,
        document_id: str,
        stage: str,
        status: str,
        reason: str,
        details: dict,
    ):
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = AuditLogEntry(
            index=self._counter,
            timestamp=ts,
            event_type=event_type,
            document_id=document_id,
            stage=stage,
            status=status,
            reason=reason,
            details=details,
            prev_hash=self._last_hash,
        )

        entry_dict = asdict(entry)
        entry_dict["entry_hash"] = self._compute_entry_hash(entry_dict)

        # Update chain head
        self._last_hash = entry_dict["entry_hash"]
        self._counter += 1

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry_dict, ensure_ascii=False) + "\n")
