# security/lineage/lineage_chain.py

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional


def sha256_hex(content: bytes) -> str:
    """
    Compute SHA-256 hexdigest for given bytes.
    """
    h = hashlib.sha256()
    h.update(content)
    return h.hexdigest()


@dataclass
class LineageRecord:
    """
    Represents a single step in a document's lineage chain.

    Fields:
      - document_id: stable ID for the logical document
      - version: monotonically increasing version number
      - content_hash: SHA-256 hash of the raw document content
      - prev_hash: hash of the previous lineage record (chain link)
      - created_at: ISO timestamp
      - author: who introduced/approved this version
      - source: ingestion source (e.g., "github", "confluence", "manual-review")
      - signature: HMAC or digital signature over this record's core fields
    """
    document_id: str
    version: int
    content_hash: str
    prev_hash: Optional[str]
    created_at: str
    author: str
    source: str
    signature: Optional[str] = None  # filled in by signer

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    @staticmethod
    def compute_content_hash(content: str) -> str:
        """
        Helper to compute SHA-256 hash of a document's raw content.
        """
        return sha256_hex(content.encode("utf-8"))

    def core_payload_bytes(self) -> bytes:
        """
        Core fields that are covered by the signature.

        We do NOT include 'signature' itself in the signed payload.
        """
        payload = {
            "document_id": self.document_id,
            "version": self.version,
            "content_hash": self.content_hash,
            "prev_hash": self.prev_hash,
            "created_at": self.created_at,
            "author": self.author,
            "source": self.source,
        }
        # Sorted keys for deterministic encoding
        return json.dumps(payload, sort_keys=True).encode("utf-8")


def create_lineage_record(
    document_id: str,
    content: str,
    author: str,
    source: str,
    prev_hash: Optional[str] = None,
    version: int = 1,
) -> LineageRecord:
    """
    Factory function to create a new LineageRecord for a given document content.
    """
    created_at = datetime.utcnow().isoformat() + "Z"
    content_hash = LineageRecord.compute_content_hash(content)

    record = LineageRecord(
        document_id=document_id,
        version=version,
        content_hash=content_hash,
        prev_hash=prev_hash,
        created_at=created_at,
        author=author,
        source=source,
        signature=None,
    )
    return record
