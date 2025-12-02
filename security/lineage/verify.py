# security/lineage/verify.py

from typing import Tuple

from security.lineage.lineage_chain import LineageRecord
from security.lineage.signer import HMACSigner


class LineageVerifier:
    """
    Verifier for document lineage and integrity.

    Responsibilities:
      - verify that the document content matches the stored content_hash
      - verify that the lineage record was signed by a trusted signer
      - optionally verify that the lineage chain (prev_hash) is intact
    """

    def __init__(self, signer: HMACSigner) -> None:
        self.signer = signer

    def verify_content_hash(self, record: LineageRecord, content: str) -> bool:
        """
        Check that the stored content_hash matches the actual content.
        """
        actual_hash = LineageRecord.compute_content_hash(content)
        return actual_hash == record.content_hash

    def verify_signature(self, record: LineageRecord) -> bool:
        """
        Check that the stored signature matches the record's core payload.
        """
        if record.signature is None:
            return False
        payload = record.core_payload_bytes()
        return self.signer.verify(payload, record.signature)

    def verify_record(
        self,
        record: LineageRecord,
        content: str,
    ) -> Tuple[bool, str]:
        """
        Run full verification on a single lineage record.

        :return: (is_valid, reason)
        """
        if not self.verify_content_hash(record, content):
            return False, "Content hash mismatch."

        if not self.verify_signature(record):
            return False, "Invalid signature."

        # At this stage we assume prev_hash chain handling is done
        # by a higher-level component that stores and checks the chain.
        return True, "Lineage and integrity verified."
