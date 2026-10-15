import uuid

from procurement_review.documents.structure import (
    Clause,
    DocumentBlock,
    DocumentSnapshot,
    SourceSpan,
)
from procurement_review.domain.enums import RiskLevel
from procurement_review.domain.models import (
    Requirement,
    VersionRef,
)
from procurement_review.review.context import build_context


def make_test_requirement(
    requirement_id: str | None = None,
    obligation: str = "廠商應採取必要資安防護措施並遵守保密義務",
    evidence_requirements: list[str] | None = None,
    required_documents: list[str] | None = None,
    condition: str | None = None,
) -> Requirement:
    req_id = requirement_id or str(uuid.uuid4())
    rule_id = str(uuid.uuid4())
    return Requirement(
        requirement_id=req_id,
        version="1.0",
        rule_ref=VersionRef(id=rule_id, version="1.0", sha256="abc" * 21 + "a"),
        obligation=obligation,
        obligor="廠商",
        condition=condition,
        evidence_requirements=evidence_requirements or ["保密義務", "資安防護"],
        required_documents=required_documents or [],
        mandatory=True,
        risk_level=RiskLevel.HIGH,
    )


def make_test_snapshot(
    document_id: str | None = None,
    filename: str = "main_contract.docx",
    clauses: list[Clause] | None = None,
    doc_type: str = "main_contract",
    confirmed: bool = True,
) -> DocumentSnapshot:
    doc_id = document_id or str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    conf_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="cde" * 21 + "c") if confirmed else None

    cl_list = clauses or []
    blocks = [
        DocumentBlock(
            block_id=c.block_ids[0] if c.block_ids else f"block-{i}",
            block_type="paragraph",
            raw_text=c.text,
            page_number=1,
            structural_path=c.clause_number or "",
        )
        for i, c in enumerate(cl_list)
    ]

    return DocumentSnapshot(
        document_id=doc_id,
        snapshot_id=snap_id,
        original_filename=filename,
        content_sha256="123" * 21 + "1",
        blocks=blocks,
        clauses=cl_list,
        issues=[],
        manifest={"document_type": doc_type, "original_filename": filename},
        confirmation_ref=conf_ref,
    )


def test_build_context_basic_matching():
    """驗證依據要求關鍵字於已確認文件中檢索條款並擷取 SourceSpan。"""
    clause1 = Clause(
        clause_id="c-1",
        clause_number="第十條",
        title="保密義務",
        text="第十條 保密義務：廠商對於機密資訊應採取嚴密資安防護措施，非經書面同意不得洩漏。",
        block_ids=["b-1"],
        spans=[
            SourceSpan(
                document_id=str(uuid.uuid4()),
                block_id=str(uuid.uuid4()),
                start_offset=0,
                end_offset=38,
                page_number=1,
                structural_path="第十條",
            )
        ],
    )
    doc = make_test_snapshot(clauses=[clause1])
    req = make_test_requirement(obligation="廠商應負保密義務並落實資安防護措施")

    bundle = build_context(req, [doc], max_chars=12000)

    assert bundle.complete is True
    assert len(bundle.source_spans) >= 1
    assert bundle.matched_spans == bundle.source_spans
    assert bundle.unknowns == []
    assert bundle.requirement_ref.id == req.requirement_id


def test_build_context_no_match_returns_complete_empty_spans():
    """驗證在文件齊備但無任何相關條款時，回傳 complete=True 且 spans 為空，以支援後續 missing 結論。"""
    clause1 = Clause(
        clause_id="c-1",
        clause_number="第一條",
        title="總則",
        text="第一條 總則：本契約為一般採購通用條款。",
        block_ids=["b-1"],
        spans=[],
    )
    doc = make_test_snapshot(clauses=[clause1])
    req = make_test_requirement(
        obligation="廠商應提供原始碼託管第三方公證證明",
        evidence_requirements=["原始碼託管", "第三方公證"],
    )

    bundle = build_context(req, [doc], max_chars=12000)

    assert bundle.complete is True
    assert len(bundle.source_spans) == 0
    assert bundle.unknowns == []


def test_build_context_missing_required_document_incomplete():
    """核心斷言：缺少必要文件時 complete 為 False，且 unknowns 記錄缺件。"""
    eula_requirement = make_test_requirement(
        obligation="套裝軟體終端使用者授權應符合原廠授權書與EULA條款",
        required_documents=["EULA"],
    )
    doc = make_test_snapshot(filename="main_contract.docx", doc_type="main_contract")
    documents_without_eula = [doc]

    bundle = build_context(eula_requirement, documents_without_eula, 12000)

    assert not bundle.complete
    assert any("EULA" in u for u in bundle.unknowns)
    assert bundle.document_retrieval_status.get("EULA") == "missing"


def test_mixed_cloud_cots_missing_eula_is_localized():
    """Review Focus 4:

    混合 Cloud+COTS 採購在缺少 EULA 時：
    - 共用資安要求（無缺件）上下文完整 (complete == True)
    - 依賴 EULA 之要求 (complete == False)，且缺件局部化於該要求，不污染其他要求。
    """
    main_clause = Clause(
        clause_id="c-sec",
        clause_number="第七條",
        title="資安事件通報",
        text="第七條 資安事件通報：廠商於知悉資安事件發生後應於一小時內通報機關。",
        block_ids=["b-sec"],
        spans=[
            SourceSpan(
                document_id=str(uuid.uuid4()),
                block_id=str(uuid.uuid4()),
                start_offset=0,
                end_offset=38,
                page_number=1,
            )
        ],
    )
    main_contract = make_test_snapshot(
        filename="main_contract.docx",
        doc_type="main_contract",
        clauses=[main_clause],
    )
    cloud_appendix = make_test_snapshot(
        filename="cloud_security_appendix.docx",
        doc_type="cloud_appendix",
        clauses=[],
    )
    documents_without_eula = [main_contract, cloud_appendix]

    common_req = make_test_requirement(
        obligation="廠商應於資安事件發生後即時通報機關",
        evidence_requirements=["事件通報", "一小時"],
        required_documents=[],
    )
    eula_req = make_test_requirement(
        obligation="套裝軟體須附原廠終端使用者授權合約 (EULA)",
        evidence_requirements=["原廠授權", "EULA"],
        required_documents=["EULA"],
    )

    ctx_common = build_context(common_req, documents_without_eula, max_chars=12000)
    ctx_eula = build_context(eula_req, documents_without_eula, max_chars=12000)

    assert ctx_common.complete is True
    assert len(ctx_common.source_spans) >= 1
    assert ctx_common.unknowns == []

    assert ctx_eula.complete is False
    assert any("EULA" in u for u in ctx_eula.unknowns)
    assert ctx_eula.document_retrieval_status.get("EULA") == "missing"


def test_build_context_cross_reference_resolution():
    """驗證跨條款與跨文件交叉引用解析，並追蹤 citations / cross_references。"""
    clause_referencing = Clause(
        clause_id="c-ref",
        clause_number="第十二條",
        title="委外複委託",
        text="第十二條 委外複委託：廠商複委託應依第十五條規定辦理並簽署保密切結。",
        block_ids=["b-ref"],
        spans=[],
    )
    clause_referenced = Clause(
        clause_id="c-target",
        clause_number="第十五條",
        title="實地稽核與複委託查核",
        text="第十五條 實地稽核：機關得對受託廠商進行定期資安稽核。",
        block_ids=["b-target"],
        spans=[],
    )
    doc = make_test_snapshot(clauses=[clause_referencing, clause_referenced])
    req = make_test_requirement(obligation="廠商複委託應受實地資安稽核規範")

    bundle = build_context(req, [doc], max_chars=12000)

    assert bundle.complete is True
    assert any("第十五條" in c for c in bundle.citations)
    assert bundle.cross_references == bundle.citations
    assert any("第十五條" in (s.structural_path or "") or s.block_id == "b-target" for s in bundle.source_spans)


def test_build_context_circular_reference_prevention():
    """驗證條款循環引用（如第三條引第五條，第五條引第三條）安全防護，避免無窮迴圈且標記待確認。"""
    clause_a = Clause(
        clause_id="c-circ-a",
        clause_number="第三條",
        title="定義與準用",
        text="第三條 定義：機敏資訊之認定準用第五條之規定。",
        block_ids=["b-ca"],
        spans=[],
    )
    clause_b = Clause(
        clause_id="c-circ-b",
        clause_number="第五條",
        title="機密標示",
        text="第五條 機密標示：除第三條另有規定外，所有資料均屬機密。",
        block_ids=["b-cb"],
        spans=[],
    )
    doc = make_test_snapshot(clauses=[clause_a, clause_b])
    req = make_test_requirement(obligation="機密與機敏資訊應依規定標示")

    bundle = build_context(req, [doc], max_chars=12000)

    # 不會因循環引用卡死且正確偵測出循環，complete 標為 False 以待人工確認
    assert not bundle.complete
    assert any("循環引用" in u for u in bundle.unknowns)


def test_build_context_definition_and_exception_extraction():
    """驗證合約中定義與例外（但書）條款之萃取。"""
    clause_def = Clause(
        clause_id="c-def",
        clause_number="第二條",
        title="名詞定義",
        text="第二條 名詞定義：「機敏資料」指個人資料及機關業務秘密。",
        block_ids=["b-def"],
        spans=[],
    )
    clause_main = Clause(
        clause_id="c-main",
        clause_number="第八條",
        title="資料外洩防護",
        text="第八條 資料防護：廠商不得洩漏機敏資料。但經機關事前書面許可者不在此限。",
        block_ids=["b-main"],
        spans=[],
    )
    doc = make_test_snapshot(clauses=[clause_def, clause_main])
    req = make_test_requirement(obligation="廠商不得洩漏機敏資料")

    bundle = build_context(req, [doc], max_chars=12000)

    assert "機敏資料" in bundle.definitions
    assert any("但經機關事前書面許可者不在此限" in exp for exp in bundle.exceptions)


def test_build_context_budget_exceeded_incomplete():
    """驗證內文超出 max_chars 預算上限時，不截斷後宣稱完整，標記 complete=False 並記錄於 unknowns。"""
    long_text = "第十條 保密義務：" + "廠商應嚴格保密機密資訊。" * 100
    clause = Clause(
        clause_id="c-long",
        clause_number="第十條",
        title="保密義務",
        text=long_text,
        block_ids=["b-long"],
        spans=[],
    )
    doc = make_test_snapshot(clauses=[clause])
    req = make_test_requirement(obligation="廠商應負保密義務")

    # 設定極小預算上限（例如 50 字元）
    bundle = build_context(req, [doc], max_chars=50)

    assert bundle.complete is False
    assert any("預算上限" in u or "超出" in u for u in bundle.unknowns)


def test_build_context_missing_referenced_appendix_incomplete():
    """驗證條款引用未取得之附件時，標記 complete=False 並於 unknowns 與狀態記錄缺件。"""
    clause = Clause(
        clause_id="c-app",
        clause_number="第四條",
        title="安全維護規格",
        text="第四條 安全規格：廠商應符合附件三資通安全維護計畫書之各項要求。",
        block_ids=["b-app"],
        spans=[],
    )
    doc = make_test_snapshot(clauses=[clause])
    req = make_test_requirement(obligation="廠商應符合資通安全維護規範")

    bundle = build_context(req, [doc], max_chars=12000)

    assert bundle.complete is False
    assert any("附件三" in u for u in bundle.unknowns)
    assert bundle.document_retrieval_status.get("附件三") == "missing"
