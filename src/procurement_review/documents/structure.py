from typing import Any

from pydantic import Field

from procurement_review.domain.models import (
    DocumentSnapshot as DomainDocumentSnapshot,
)
from procurement_review.domain.models import (
    SourceSpan as DomainSourceSpan,
)
from procurement_review.domain.models import (
    StrictBaseModel,
    VersionRef,
)

SourceSpan = DomainSourceSpan


class QualityIssue(StrictBaseModel):
    """文件擷取與結構品質問題記錄

    固定包含 code, block_id, safe_message。
    safe_message 絕不包含明文機敏內容。
    """

    code: str
    block_id: str | None = None
    safe_message: str

    def __str__(self) -> str:
        return f"[{self.code}] {self.safe_message}"


class DocumentBlock(StrictBaseModel):
    """結構化文件區塊，保留精確 Unicode 原始文字與結構路徑"""

    block_id: str
    block_type: str = "paragraph"
    raw_text: str
    page_number: int | None = None
    structural_path: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)


class Clause(StrictBaseModel):
    """契約條款結構化單元"""

    clause_id: str
    clause_number: str | None = None
    title: str | None = None
    text: str
    block_ids: list[str] = Field(default_factory=list)
    spans: list[SourceSpan] = Field(default_factory=list)


class DocumentSnapshot(DomainDocumentSnapshot):
    """文件文字與結構快照

    繼承自領域模型 DocumentSnapshot，具備強型別 DocumentBlock、Clause 與 QualityIssue。
    """

    blocks: list[DocumentBlock] = Field(default_factory=list)  # type: ignore[assignment]
    clauses: list[Clause] = Field(default_factory=list)  # type: ignore[assignment]
    issues: list[QualityIssue] = Field(default_factory=list)  # type: ignore[assignment]
    confirmation_ref: VersionRef | str | None = None  # type: ignore[assignment]
