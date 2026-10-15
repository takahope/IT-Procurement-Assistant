import logging
import uuid
from typing import Any

from procurement_review.domain.models import DetectedSpan, SourceSpan
from procurement_review.masking.detector import Detector, RuleBasedDetector

logger = logging.getLogger(__name__)


def _adapt_item_to_detected_span(item: Any, text: str) -> DetectedSpan | None:
    if isinstance(item, DetectedSpan):
        return item

    dummy_id = "00000000-0000-0000-0000-000000000000"
    if isinstance(item, dict):
        sp_type = item.get("span_type") or item.get("type") or item.get("entity_type", "PII")
        start = item.get("start_offset", item.get("start", 0))
        end = item.get("end_offset", item.get("end", 0))
        orig = item.get("original_text", item.get("text", text[start:end]))
        group = item.get(
            "entity_group",
            item.get("group", "SECRET" if sp_type == "SECRET" else "PII"),
        )
        conf = float(item.get("confidence", item.get("score", 1.0)))
        raw_id = item.get("span_id")
        try:
            span_id = str(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError):
            span_id = str(uuid.uuid4())

        return DetectedSpan(
            span_id=span_id,
            span_type=str(sp_type),
            entity_group=str(group),
            source_span=SourceSpan(
                document_id=dummy_id,
                block_id=dummy_id,
                start_offset=int(start),
                end_offset=int(end),
            ),
            original_text=str(orig),
            masked_token=item.get("masked_token", ""),
            confidence=conf,
        )

    if hasattr(item, "start") and hasattr(item, "end"):
        start = item.start
        end = item.end
        sp_type = getattr(item, "entity_type", getattr(item, "type", "PII"))
        group = getattr(
            item, "entity_group", getattr(item, "group", "SECRET" if sp_type == "SECRET" else "PII")
        )
        orig = getattr(item, "text", text[start:end])
        conf = float(getattr(item, "confidence", getattr(item, "score", 1.0)))
        raw_id = getattr(item, "span_id", None)
        try:
            span_id = str(uuid.UUID(str(raw_id)))
        except (ValueError, TypeError):
            span_id = str(uuid.uuid4())

        return DetectedSpan(
            span_id=span_id,
            span_type=str(sp_type),
            entity_group=str(group),
            source_span=SourceSpan(
                document_id=dummy_id,
                block_id=dummy_id,
                start_offset=int(start),
                end_offset=int(end),
            ),
            original_text=str(orig),
            masked_token=getattr(item, "masked_token", ""),
            confidence=conf,
        )

    return None


class PIIGuardAdapter:
    """pii-guard 偵測器轉接器。

    隔離 pii-guard 套件依賴；當套件或重型模型不可用時，具備明確 Real Gate 與
    優雅降級至離線繁中 RuleBasedDetector，並詳實記錄選型與版本。
    """

    def __init__(
        self,
        fallback_detector: Detector | None = None,
        enable_pii_guard: bool = True,
        model_name: str | None = None,
    ) -> None:
        self.fallback = fallback_detector or RuleBasedDetector()
        self.enable_pii_guard = enable_pii_guard
        self.model_name = model_name or "pii-guard-zh-base"
        self._pii_guard_module: Any | None = None
        self._pii_guard_available = False

        if self.enable_pii_guard:
            try:
                import pii_guard  # type: ignore[import-not-found]

                self._pii_guard_module = pii_guard
                self._pii_guard_available = True
            except (ImportError, ModuleNotFoundError):
                self._pii_guard_module = None
                self._pii_guard_available = False

    def is_pii_guard_available(self) -> bool:
        return self._pii_guard_available

    def get_detector_info(self) -> dict[str, Any]:
        return {
            "engine": "pii-guard" if self._pii_guard_available else "rule-based-zh-tw-fallback",
            "version": "0.1.0",
            "model_name": self.model_name,
            "offline": True,
            "fallback_active": not self._pii_guard_available,
        }

    def detect(self, text: str) -> list[DetectedSpan]:
        if self._pii_guard_available and self._pii_guard_module is not None:
            try:
                # If pii-guard is available, invoke its detect API
                # and map to standard DetectedSpan objects
                if hasattr(self._pii_guard_module, "detect"):
                    results = self._pii_guard_module.detect(text)
                    if isinstance(results, list):
                        spans: list[DetectedSpan] = []
                        for r in results:
                            span = _adapt_item_to_detected_span(r, text)
                            if span is not None:
                                spans.append(span)
                        if spans:
                            return spans
            except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
                logger.warning("pii-guard detection error, falling back to rule-based: %s", exc)

        return self.fallback.detect(text)
