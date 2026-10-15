from enum import Enum


class ResultEnum(str, Enum):
    """審查結果狀態"""

    COMPLIANT = "compliant"
    CONCERN = "concern"
    MISSING = "missing"
    NEEDS_CONFIRMATION = "needs_confirmation"
    NOT_APPLICABLE = "not_applicable"
    UNCOVERED = "uncovered"

    @property
    def label_zh(self) -> str:
        labels = {
            "compliant": "符合",
            "concern": "疑慮",
            "missing": "缺漏",
            "needs_confirmation": "待確認",
            "not_applicable": "不適用",
            "uncovered": "未涵蓋",
        }
        return labels[self.value]


class RiskLevel(str, Enum):
    """風險分級"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def label_zh(self) -> str:
        labels = {
            "critical": "極高/重大",
            "high": "高",
            "medium": "中",
            "low": "低",
            "info": "資訊",
        }
        return labels[self.value]


class ProcurementFamily(str, Enum):
    """採購類別情境"""

    SERVICES = "services"
    CLOUD = "cloud"
    COTS = "cots"
    DEVELOPMENT = "development"

    @property
    def label_zh(self) -> str:
        labels = {
            "services": "資訊服務勞務",
            "cloud": "雲端服務",
            "cots": "套裝軟體",
            "development": "委外開發",
        }
        return labels[self.value]


class SourceNature(str, Enum):
    """來源性質"""

    APPLICABLE_LAW = "applicable_law"
    INSTITUTION_POLICY = "institution_policy"
    STANDARD_TEMPLATE = "standard_template"
    GUIDELINE_RECOMMENDATION = "guideline_recommendation"

    @property
    def label_zh(self) -> str:
        labels = {
            "applicable_law": "適用法令",
            "institution_policy": "院／單位規範",
            "standard_template": "指定契約範本",
            "guideline_recommendation": "作業指南／建議",
        }
        return labels[self.value]


class ReviewState(str, Enum):
    """審查案件狀態"""

    IMPORTED = "imported"
    NEEDS_INPUT_CONFIRMATION = "needs_input_confirmation"
    READY = "ready"
    REVIEWING = "reviewing"
    DRAFT_READY = "draft_ready"
    HUMAN_REVIEW = "human_review"
    APPROVED = "approved"
    NEEDS_REVISION = "needs_revision"
    ARCHIVED = "archived"


class RunState(str, Enum):
    """執行管線狀態"""

    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    DONE = "done"
    BLOCKED = "blocked"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class RuleStatus(str, Enum):
    """規則狀態"""

    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


class ApplicabilityState(str, Enum):
    """適用性狀態"""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class HumanDecisionAction(str, Enum):
    """人工決定動作"""

    ADOPT = "adopt"
    MODIFY = "modify"
    REJECT = "reject"


class ValidationStatus(str, Enum):
    """校驗狀態"""

    PENDING = "pending"
    PASSED = "passed"
    FLAGGED = "flagged"
    FAILED = "failed"


class RedactionMode(str, Enum):
    """匯出遮罩模式"""

    MASKED = "masked"
    PLAINTEXT = "plaintext"


class RuntimeMode(str, Enum):
    """執行環境模式"""

    SYNTHETIC = "synthetic"
    REAL = "real"
