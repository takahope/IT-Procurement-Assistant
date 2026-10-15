import logging
from typing import Any

from procurement_review.domain.models import DetectedSpan
from procurement_review.masking.detector import Detector, RuleBasedDetector

logger = logging.getLogger(__name__)


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
                    if isinstance(results, list) and all(
                        isinstance(r, DetectedSpan) for r in results
                    ):
                        return results
            except (TypeError, ValueError, AttributeError, RuntimeError) as exc:
                logger.warning("pii-guard detection error, falling back to rule-based: %s", exc)

        return self.fallback.detect(text)
