from typing import Optional, Dict, Any

from security.lineage.verify import LineageVerifier
from security.semantic.semantic_scanner import SemanticScanner
from security.quarantine.quarantine_manager import QuarantineManager
from security.lineage.lineage_chain import LineageRecord
from security.audit.audit_log import AuditLog


class RAGSecurityPipeline:
    """
    Enterprise ingestion pipeline:
      - lineage verification
      - semantic anomaly detection
      - quarantine
      - tamper-evident audit logging
    """

    def __init__(
        self,
        lineage_verifier: LineageVerifier,
        semantic_scanner: SemanticScanner,
        quarantine_manager: QuarantineManager,
        audit_log: AuditLog,
    ):
        self.lineage_verifier = lineage_verifier
        self.semantic_scanner = semantic_scanner
        self.quarantine_manager = quarantine_manager
        self.audit_log = audit_log

    def _normalize_lineage_record(
        self, lineage_record: Optional[Dict[str, Any]]
    ) -> Optional[LineageRecord]:
        if lineage_record is None:
            return None
        if isinstance(lineage_record, LineageRecord):
            return lineage_record
        if isinstance(lineage_record, dict):
            try:
                return LineageRecord(**lineage_record)
            except TypeError:
                return None
        return None

    def process_document(
        self,
        document_id: str,
        content: str,
        lineage_record: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:

        self.audit_log.write_event(
            event_type="ingest_start",
            document_id=document_id,
            stage="start",
            status="processing",
            reason="Document ingest started",
            details={"metadata": metadata or {}},
        )

        # STEP 0 — lineage normalize
        normalized_record = self._normalize_lineage_record(lineage_record)
        if lineage_record is not None and normalized_record is None:
            self.audit_log.write_event(
                "lineage_fail", document_id, "lineage_deserialization",
                "quarantined", "Invalid lineage structure",
                {"raw_lineage": lineage_record},
            )
            bundle_path = self.quarantine_manager.save_evidence_bundle(
                document_id=document_id,
                content=content,
                reason="Lineage record deserialization failure.",
                lineage_record=lineage_record,
                detection_scores=None,
                metadata=metadata or {"stage": "lineage_deserialization"},
            )
            return {
                "status": "quarantined",
                "reason": "Invalid lineage record structure.",
                "bundle_path": bundle_path,
                "semantic_scores": None,
            }

        # STEP 1 — lineage verify
        if normalized_record is not None:
            ok, reason = self.lineage_verifier.verify_record(
                normalized_record, content
            )
            if not ok:
                self.audit_log.write_event(
                    "lineage_fail", document_id, "lineage",
                    "quarantined", reason,
                    {"lineage_record": normalized_record.__dict__},
                )
                bundle_path = self.quarantine_manager.save_evidence_bundle(
                    document_id=document_id,
                    content=content,
                    reason=f"Lineage/Integrity failed: {reason}",
                    lineage_record=normalized_record.__dict__,
                    detection_scores=None,
                    metadata=metadata or {"stage": "lineage"},
                )
                return {
                    "status": "quarantined",
                    "reason": reason,
                    "bundle_path": bundle_path,
                    "semantic_scores": None,
                }

            self.audit_log.write_event(
                "lineage_ok", document_id, "lineage",
                "accepted", "Lineage valid",
                {"version": normalized_record.version}
            )

        # STEP 2 — semantic
        semantic_result = self.semantic_scanner.detect(content)
        if semantic_result["is_suspicious"]:
            self.audit_log.write_event(
                "semantic_fail", document_id, "semantic",
                "quarantined", "Semantic anomaly detected",
                {"scores": semantic_result},
            )
            bundle_path = self.quarantine_manager.save_evidence_bundle(
                document_id=document_id,
                content=content,
                reason="Semantic anomaly detected.",
                lineage_record=normalized_record.__dict__ if normalized_record else None,
                detection_scores=semantic_result,
                metadata=metadata or {"stage": "semantic"},
            )
            return {
                "status": "quarantined",
                "reason": "Semantic anomaly.",
                "bundle_path": bundle_path,
                "semantic_scores": semantic_result,
            }

        self.audit_log.write_event(
            "semantic_ok", document_id, "semantic",
            "accepted", "Semantic clean",
            {"scores": semantic_result},
        )

        # Final ACCEPT
        self.audit_log.write_event(
            "accept", document_id, "pipeline_end",
            "accepted", "Document fully clean",
            {"scores": semantic_result},
        )

        return {
            "status": "accepted",
            "reason": "Clean document.",
            "bundle_path": None,
            "semantic_scores": semantic_result,
        }
