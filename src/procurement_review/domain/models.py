import json
import uuid
from datetime import date, datetime
from decimal import Decimal
from typing import Annotated, Any

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from procurement_review.domain.enums import (
    ApplicabilityState,
    HumanDecisionAction,
    ProcurementFamily,
    RedactionMode,
    ResultEnum,
    ReviewState,
    RiskLevel,
    RuleStatus,
    RunState,
    RuntimeMode,
    SourceNature,
)


def _validate_uuid_str(v: str) -> str:
    if not isinstance(v, str):
        raise TypeError(f"UUID must be a string, got {type(v).__name__}")
    try:
        val = uuid.UUID(v)
        return str(val)
    except Exception as e:
        raise ValueError(f"Invalid UUID string: {v}") from e


UUIDStr = Annotated[str, AfterValidator(_validate_uuid_str)]


class StrictBaseModel(BaseModel):
    """基礎嚴格模型：禁止多餘欄位 (extra='forbid')"""

    model_config = ConfigDict(extra="forbid")


class VersionRef(StrictBaseModel):
    """不可變版本參照"""

    id: UUIDStr
    version: str
    sha256: str


class CaseFacts(StrictBaseModel):
    """案件背景事實（規格 §3.1）

    未知值使用 None 並列於 unknown_fields，不把空值判定為 False。
    金額欄位嚴格禁止二進位浮點數。
    """

    procurement_unit: str | None = None
    procurement_system: str | None = None
    procurement_system_confirmed: bool | None = None
    statutory_category: str | None = None
    procurement_families: list[ProcurementFamily] = Field(default_factory=list)
    service_scope: str | None = None
    personal_data_involved: bool | None = None
    sensitive_data_involved: bool | None = None
    data_flow_cross_border: bool | None = None
    data_locations: list[str] = Field(default_factory=list)
    remote_access: bool | None = None
    core_system: bool | None = None
    security_level: str | None = None
    budget_amount: Decimal | None = None
    currency: str = "TWD"
    period_start: date | None = None
    period_end: date | None = None
    expected_signing_date: date | None = None
    expected_delivery_date: date | None = None
    review_baseline_date: date
    unknown_fields: list[str] = Field(default_factory=list)

    @field_validator("budget_amount", mode="before")
    @classmethod
    def reject_float_amount(cls, v: Any) -> Any:
        if isinstance(v, float):
            raise ValueError(  # noqa: TRY004
                "Binary float is forbidden for monetary amounts; use Decimal, int, or string"
            )
        return v


class RuntimePolicy(StrictBaseModel):
    """執行期政策與核准參照"""

    mode: RuntimeMode = RuntimeMode.SYNTHETIC
    data_root: str
    provider_approval_ref: VersionRef | None = None
    storage_approval_ref: VersionRef | None = None
    retention_approval_ref: VersionRef | None = None
    masking_approval_ref: VersionRef | None = None
    rules_approval_ref: VersionRef | None = None
    allowed_endpoints: list[str] = Field(default_factory=list)


class SourceReference(StrictBaseModel):
    """法規、內規、範本或建議來源參照"""

    source_id: UUIDStr
    kind: SourceNature
    title: str
    issuer: str
    locator: str
    section: str
    version: str
    published_at: date | None = None
    effective_from: date | None = None
    effective_to: date | None = None
    verified_at: datetime | None = None
    verified_by: str | None = None
    content_hash: str
    access_class: str = "internal"


class Rule(StrictBaseModel):
    """核准規則定義"""

    rule_id: UUIDStr
    version: str
    status: RuleStatus = RuleStatus.DRAFT
    title: str
    category: ProcurementFamily
    requirement_text: str
    source_refs: list[VersionRef] = Field(default_factory=list)
    applicability: dict[str, Any] = Field(default_factory=dict)
    mandatory: bool = True
    severity: RiskLevel = RiskLevel.MEDIUM
    non_negotiable: bool = False
    company_position: str | None = None
    fallback_positions: list[str] = Field(default_factory=list)
    deterministic_checks: list[dict[str, Any]] = Field(default_factory=list)
    target_sentences: list[str] = Field(default_factory=list)
    example_clauses: list[str] = Field(default_factory=list)
    conflicts_with: list[str] = Field(default_factory=list)
    supersedes: list[str] = Field(default_factory=list)
    approved_by: str | None = None
    approved_at: datetime | None = None
    effective_from: date | None = None
    effective_to: date | None = None
    change_reason: str | None = None
    test_case_ids: list[str] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return self.rule_id


class Requirement(StrictBaseModel):
    """單一可判斷資安要求契約"""

    requirement_id: UUIDStr
    version: str
    rule_ref: VersionRef
    obligation: str
    obligor: str
    condition: str | None = None
    mandatory: bool = True
    evidence_requirements: list[str] = Field(default_factory=list)
    deterministic_checks: list[dict[str, Any]] = Field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    required_documents: list[str] = Field(default_factory=list)
    protected_constraints: list[str] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return self.requirement_id


class ApplicabilityDecision(StrictBaseModel):
    """單一要求適用性判定"""

    requirement_ref: VersionRef
    state: ApplicabilityState
    reasons: list[str] = Field(default_factory=list)


class SourceSpan(StrictBaseModel):
    """文字片段在原始文件或區塊的定位"""

    document_id: UUIDStr
    block_id: UUIDStr
    start_offset: int
    end_offset: int
    page_number: int | None = None
    structural_path: str = ""
    text: str | None = None

    @property
    def start(self) -> int:
        return self.start_offset

    @property
    def end(self) -> int:
        return self.end_offset


class DocumentSnapshot(StrictBaseModel):
    """不可變文件文字與結構快照"""

    document_id: UUIDStr
    snapshot_id: UUIDStr
    original_filename: str
    content_sha256: str
    blocks: list[dict[str, Any]] = Field(default_factory=list)
    clauses: list[dict[str, Any]] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    manifest: dict[str, Any] = Field(default_factory=dict)
    confirmation_ref: VersionRef | None = None


class Review(StrictBaseModel):
    """審查案件契約"""

    case_id: UUIDStr
    title: str
    contract_type: ProcurementFamily
    contract_version: str = "1.0"
    original_file_hash: str
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    facts: CaseFacts
    sensitivity_level: str = "confidential"
    created_by: str
    created_at: datetime
    state: ReviewState = ReviewState.IMPORTED
    document_snapshot_ref: VersionRef | None = None
    confirmation_history: list[dict[str, Any]] = Field(default_factory=list)
    revision: int = 1

    @property
    def id(self) -> str:
        return str(self.case_id)

    @property
    def review_id(self) -> str:
        return str(self.case_id)


class ReviewRun(StrictBaseModel):
    """單次審查執行管線記錄"""

    run_id: UUIDStr
    case_id: UUIDStr
    input_version: VersionRef
    rule_set_snapshot: VersionRef
    case_index_ref: VersionRef | None = None
    engine_version: str
    ocr_version: str | None = None
    masking_version: str
    prompt_version: str
    schema_version: str
    provider_id: str
    model_id: str
    route: str = "default"
    state: RunState = RunState.PLANNED
    parent_run_id: UUIDStr | None = None
    stale: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    cost_usd: Decimal | None = None
    latency_ms: int | None = None
    attempts: int = 0
    egress_approval_ref: VersionRef | None = None
    error_message: str | None = None

    @property
    def id(self) -> str:
        return str(self.run_id)

    @field_validator("cost_usd", mode="before")
    @classmethod
    def reject_float_cost(cls, v: Any) -> Any:
        if isinstance(v, float):
            raise ValueError(  # noqa: TRY004
                "Binary float is forbidden for cost amounts; use Decimal or string"
            )
        return v


class ContextBundle(StrictBaseModel):
    """審查推論上下文組合"""

    requirement_ref: VersionRef
    source_spans: list[SourceSpan] = Field(default_factory=list)
    definitions: dict[str, str] = Field(default_factory=dict)
    exceptions: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    document_retrieval_status: dict[str, str] = Field(default_factory=dict)
    complete: bool = True
    unknowns: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def remap_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "matched_spans" in data and "source_spans" not in data:
                data["source_spans"] = data.pop("matched_spans")
            if "cross_references" in data and "citations" not in data:
                data["citations"] = data.pop("cross_references")
        return data

    @property
    def matched_spans(self) -> list[SourceSpan]:
        return self.source_spans

    @property
    def cross_references(self) -> list[str]:
        return self.citations


class CoverageEntry(StrictBaseModel):
    """覆蓋矩陣項目"""

    item_id: str
    item_type: str
    run_id: UUIDStr
    status: str
    details: str = ""
    scope: str | None = None

    @property
    def version(self) -> str | None:
        if self.details:
            try:
                data = json.loads(self.details)
                if isinstance(data, dict):
                    return data.get("version")
            except (json.JSONDecodeError, TypeError, ValueError):
                return None
        return None

    @property
    def result(self) -> str | None:
        if self.details:
            try:
                data = json.loads(self.details)
                if isinstance(data, dict):
                    return data.get("result")
            except (json.JSONDecodeError, TypeError, ValueError):
                return None
        return None

    @property
    def processing(self) -> str | None:
        if self.details:
            try:
                data = json.loads(self.details)
                if isinstance(data, dict):
                    return data.get("processing")
            except (json.JSONDecodeError, TypeError, ValueError):
                return None
        return None

    def __getitem__(self, item: str) -> Any:
        if item in ("version", "result", "processing"):
            return getattr(self, item)
        if hasattr(self, item):
            return getattr(self, item)
        raise KeyError(item)


class CoverageMatrix(StrictBaseModel):
    """全份覆蓋矩陣：同時列舉條款與適用要求"""

    run_id: UUIDStr
    clause_entries: list[CoverageEntry] = Field(default_factory=list)
    requirement_entries: list[CoverageEntry] = Field(default_factory=list)
    unprocessed_clause_ids: list[str] = Field(default_factory=list)
    unresolved_requirement_ids: list[str] = Field(default_factory=list)

    @property
    def requirements(self) -> dict[str, CoverageEntry]:
        return {e.item_id: e for e in self.requirement_entries}

    @property
    def clauses(self) -> dict[str, CoverageEntry]:
        return {e.item_id: e for e in self.clause_entries}

    @property
    def unprocessed_ids(self) -> list[str]:
        return self.unprocessed_clause_ids

    @property
    def unresolved_ids(self) -> list[str]:
        return self.unresolved_requirement_ids


class DetectedSpan(StrictBaseModel):
    """PII 或機敏資訊偵測區間"""

    span_id: UUIDStr
    span_type: str
    entity_group: str
    source_span: SourceSpan
    original_text: str
    masked_token: str
    confidence: float = 1.0


class MaskingSession(StrictBaseModel):
    """本機遮罩會話紀錄"""

    session_id: UUIDStr
    case_id: UUIDStr
    detector_version: str
    manual_tagging_version: str | None = None
    mapping_vault_ref: str
    outbound_hash: str
    human_reviewed: bool = False
    roundtrip_ok: bool = False
    blocking_reasons: list[str] = Field(default_factory=list)
    retention_expire_at: datetime | None = None


class RestorationResult(StrictBaseModel):
    """本機還原結果"""

    text: str | None = None
    unknown_tokens: list[str] = Field(default_factory=list)
    wrong_case_tokens: list[str] = Field(default_factory=list)
    adoptable: bool = False


class OutboundDraft(StrictBaseModel):
    """出站草稿（本機未遮罩組裝物）"""

    draft_id: UUIDStr
    run_id: UUIDStr
    plaintext_body: str
    sensitive_token_count: int = 0
    assembled_at: datetime


class PreparedRequest(StrictBaseModel):
    """已遮罩出站請求"""

    request_id: UUIDStr
    run_id: UUIDStr
    endpoint: str
    model: str
    body: bytes
    sha256: str
    masking_ref: VersionRef
    rule_refs: list[VersionRef] = Field(default_factory=list)


class EgressApproval(StrictBaseModel):
    """不可變出站核准 artifact"""

    approval_id: UUIDStr
    request_id: UUIDStr
    request_sha256: str
    endpoint: str
    model: str
    approved_by: str
    approved_at: datetime
    scope: str
    max_resend_count: int = 1
    current_send_count: int = 0
    revocation_reason: str | None = None


class ProviderReply(StrictBaseModel):
    """模型供應商原始受控回應紀錄"""

    reply_id: UUIDStr
    request_id: UUIDStr
    artifact_ref: str
    usage: dict[str, int] = Field(default_factory=dict)
    finish_reason: str = "stop"
    latency_ms: int = 0
    provider_request_id: str | None = None


class Finding(StrictBaseModel):
    """審查發現契約

    安全規則：若結果為 missing 且無具體條款 ID，必填查核範圍 review_scope。
    """

    finding_id: UUIDStr
    run_id: UUIDStr
    clause_ids: list[str] = Field(default_factory=list)
    requirement_id: str
    result: ResultEnum
    risk: RiskLevel
    evidence: list[SourceSpan] = Field(default_factory=list)
    rule_refs: list[VersionRef] = Field(default_factory=list)
    case_refs: list[VersionRef] = Field(default_factory=list)
    reason: str
    unknowns: list[str] = Field(default_factory=list)
    suggested_action: str | None = None
    suggested_clause: str | None = None
    validation_status: str = "pending"
    human_status: str = "unreviewed"
    conclusion_nature: list[SourceNature] = Field(default_factory=list)
    review_scope: str | None = None
    citations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_missing_finding_scope(self) -> "Finding":
        if (
            self.result == ResultEnum.MISSING
            and not self.clause_ids
            and (not self.review_scope or not self.review_scope.strip())
        ):
            raise ValueError(
                "Finding with result='missing' and no clause_ids requires a non-empty review_scope"
            )
        return self

    @property
    def id(self) -> str:
        return str(self.finding_id)


class ValidationReport(StrictBaseModel):
    """校驗報告：分層檢查結構、來源與實質"""

    report_id: UUIDStr
    run_id: UUIDStr
    structure_ok: bool = True
    source_ok: bool = True
    substance_ok: bool = True
    issues: list[str] = Field(default_factory=list)
    checked_at: datetime

    @property
    def structure(self) -> "GateReport":
        issues = [i for i in self.issues if i.startswith("[structure]")]
        return GateReport(
            ok=self.structure_ok,
            operation="structure_validation",
            issues=issues,
            checked_at=self.checked_at,
        )

    @property
    def source(self) -> "GateReport":
        issues = [i for i in self.issues if i.startswith("[source]")]
        return GateReport(
            ok=self.source_ok,
            operation="source_validation",
            issues=issues,
            checked_at=self.checked_at,
        )

    @property
    def substance(self) -> "GateReport":
        issues = [i for i in self.issues if i.startswith("[substance]")]
        return GateReport(
            ok=self.substance_ok,
            operation="substance_validation",
            issues=issues,
            checked_at=self.checked_at,
        )


class SuggestedChange(StrictBaseModel):
    """條款修改建議"""

    change_id: UUIDStr
    finding_id: UUIDStr
    run_id: UUIDStr
    purpose: str
    basis_rule_refs: list[VersionRef] = Field(default_factory=list)
    proposed_text: str
    affected_clause_ids: list[str] = Field(default_factory=list)
    protected_field_modifications: list[str] = Field(default_factory=list)
    fill_in_placeholders: list[str] = Field(default_factory=list)


class HumanDecision(StrictBaseModel):
    """人工決定"""

    decision_id: UUIDStr
    finding_id: UUIDStr
    action: HumanDecisionAction
    final_text: str | None = None
    reason: str
    decided_by: str
    decided_at: datetime


class Feedback(StrictBaseModel):
    """審查回饋紀錄"""

    feedback_id: UUIDStr
    finding_id: UUIDStr
    run_id: UUIDStr
    original_result: ResultEnum
    human_decision: HumanDecision
    exception_scope: str | None = None
    approved_for_case_base: bool = False
    operator: str
    created_at: datetime
    version: int = 1

    @property
    def id(self) -> str:
        return str(self.feedback_id)


class ReviewReport(StrictBaseModel):
    """最終審查報告契約"""

    report_id: UUIDStr
    case_id: UUIDStr
    run_id: UUIDStr
    case_version: str
    sensitivity_level: str
    source_manifest: list[VersionRef] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    coverage: CoverageMatrix
    unresolved_issues: list[str] = Field(default_factory=list)
    human_decisions: list[HumanDecision] = Field(default_factory=list)
    generated_at: datetime


class ExportPaths(StrictBaseModel):
    """匯出路徑與模式"""

    markdown_path: str
    json_path: str
    redaction_mode: RedactionMode = RedactionMode.MASKED


class GateReport(StrictBaseModel):
    """安全檢核門報告"""

    ok: bool
    operation: str
    issues: list[str] = Field(default_factory=list)
    checked_at: datetime


class EvaluationReport(StrictBaseModel):
    """評測報告"""

    eval_id: UUIDStr
    timestamp: datetime
    metrics: dict[str, Any] = Field(default_factory=dict)
    denominators: dict[str, int] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)


class PurgePlan(StrictBaseModel):
    """安全刪除計畫"""

    case_id: UUIDStr
    purge_targets: list[str] = Field(default_factory=list)
    retention_expired: bool
    approved_by: str | None = None
    planned_at: datetime


class ProviderConfig(StrictBaseModel):
    """模型供應商設定"""

    provider: str
    endpoint: str
    model: str
    credential_ref: str
    rate_limits: dict[str, Any] = Field(default_factory=dict)
    price_version: str
    approval_ref: VersionRef | None = None


class AuditEvent(StrictBaseModel):
    """安全稽核事件"""

    event_id: UUIDStr
    timestamp: datetime
    operator: str
    action: str
    target_type: str
    target_version: str | None = None
    result: str
    evidence_hashes: list[str] = Field(default_factory=list)


ALL_DOMAIN_MODELS = [
    VersionRef,
    CaseFacts,
    RuntimePolicy,
    SourceReference,
    Rule,
    Requirement,
    ApplicabilityDecision,
    SourceSpan,
    DocumentSnapshot,
    Review,
    ReviewRun,
    ContextBundle,
    CoverageEntry,
    CoverageMatrix,
    DetectedSpan,
    MaskingSession,
    RestorationResult,
    OutboundDraft,
    PreparedRequest,
    EgressApproval,
    ProviderReply,
    Finding,
    ValidationReport,
    SuggestedChange,
    HumanDecision,
    Feedback,
    ReviewReport,
    ExportPaths,
    GateReport,
    EvaluationReport,
    PurgePlan,
    ProviderConfig,
    AuditEvent,
]


def validate_case(data: dict[str, Any]) -> Review:
    """驗證並轉換字典資料為 Review 實例"""
    return Review.model_validate(data)


def export_domain_schemas() -> dict[str, Any]:
    """匯出所有領域模型的 JSON Schema 字典"""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "ProcurementReviewDomainSchemas",
        "description": "JSON Schemas for Central Research Institute Security Procurement Review Assistant",
        "version": "0.1.0",
        "models": {model.__name__: model.model_json_schema() for model in ALL_DOMAIN_MODELS},
    }
