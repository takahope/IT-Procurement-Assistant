import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from procurement_review.domain.enums import ProcurementFamily, RiskLevel, RuleStatus
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import Rule, SourceReference, VersionRef
from procurement_review.rules.releases import release_rules
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
MANIFEST_PATH = PROJECT_ROOT / "rules" / "sources" / "manifest.json"
DRAFTS_DIR = PROJECT_ROOT / "rules" / "drafts"

VALID_OBLIGORS = {"vendor", "contractor", "agency"}


@pytest.fixture
def repo(tmp_path: Path) -> Repository:
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    artifacts = ArtifactStore(root=vault_root, secrets=secrets)
    db_path = tmp_path / "app.db"
    return Repository(db=db_path, artifacts=artifacts)


def load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found: {MANIFEST_PATH}")
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def load_manifest_sources() -> list[SourceReference]:
    data = load_manifest()
    sources = []
    for s in data["sources"]:
        source_kwargs = {k: v for k, v in s.items() if k != "retrieval_status"}
        sources.append(SourceReference(**source_kwargs))
    return sources


def load_draft_packs() -> dict[str, dict]:
    pack_names = ["common", "services", "cloud", "cots", "development"]
    packs = {}
    for name in pack_names:
        p = DRAFTS_DIR / f"{name}.json"
        if not p.exists():
            raise FileNotFoundError(f"Draft pack not found: {p}")
        with open(p, "r", encoding="utf-8") as f:
            packs[name] = json.load(f)
    return packs


def load_all_draft_rules() -> list[Rule]:
    packs = load_draft_packs()
    rules = []
    for pack_data in packs.values():
        for r_dict in pack_data.get("rules", []):
            rules.append(Rule.model_validate(r_dict))
    return rules


def load_all_draft_requirements() -> list[dict]:
    packs = load_draft_packs()
    requirements = []
    for pack_data in packs.values():
        requirements.extend(pack_data.get("requirements", []))
    return requirements


def test_manifest_file_exists_and_valid():
    """驗證 rules/sources/manifest.json 存在且包含必要來源資訊。"""
    manifest = load_manifest()
    assert "version" in manifest
    assert "sources" in manifest
    assert len(manifest["sources"]) >= 6

    source_ids = set()
    for s in manifest["sources"]:
        assert "source_id" in s
        assert "title" in s
        assert "kind" in s
        assert "locator" in s
        assert "section" in s
        assert "version" in s
        assert "content_hash" in s
        assert "retrieval_status" in s
        assert s["retrieval_status"] in {"verified_full_text", "index_only"}
        source_ids.add(s["source_id"])

    # 確保 source_id 唯一
    assert len(source_ids) == len(manifest["sources"])


def test_release_rejects_unverified_source(repo: Repository):
    """未取得全文或未經實質查核之來源，嘗試發布時必須拋出 UNVERIFIED_SOURCE 領域錯誤。"""
    manifest = load_manifest()
    unverified_entries = [
        s for s in manifest["sources"] if s.get("retrieval_status") == "index_only"
    ]
    assert len(unverified_entries) > 0, "Manifest 應記錄僅查索引尚未取得全文之未查核來源"

    # 將未查核來源轉為 SourceReference
    unverified_sources = []
    for entry in unverified_entries:
        kwargs = {k: v for k, v in entry.items() if k != "retrieval_status"}
        unverified_sources.append(SourceReference(**kwargs))

    # 構造引用該來源之 pending_approval 測試規則
    target_source = unverified_sources[0]
    rule = Rule(
        rule_id="99999999-9999-4999-8999-999999999999",
        version="1.0",
        status=RuleStatus.PENDING_APPROVAL,
        title="雲端服務未查核法源測試規則",
        category=ProcurementFamily.SERVICES,
        requirement_text="測試未查核法源阻擋",
        source_refs=[
            VersionRef(
                id=target_source.source_id,
                version=target_source.version,
                sha256=target_source.content_hash,
            )
        ],
        mandatory=True,
        severity=RiskLevel.HIGH,
    )

    actor = "資安管理員A"
    now = datetime.now(UTC)

    with pytest.raises(DomainError) as exc_info:
        release_rules([rule], unverified_sources, actor, now, repo)
    assert exc_info.value.code == "UNVERIFIED_SOURCE"


def test_requirement_has_exact_source_and_obligor():
    """驗證所有五包草稿要求均具備精確來源條號與合法義務主體 (vendor/contractor/agency)。

    總量應在 20-30 條原子要求之間，五包均有清單，不得以數量代替完整性。
    """
    manifest = load_manifest()
    valid_source_ids = {s["source_id"]: s for s in manifest["sources"]}

    requirements = load_all_draft_requirements()
    rules = load_all_draft_rules()
    rule_map = {r.rule_id: r for r in rules}

    # 檢核原子要求數量落於 20-30 之間（符合規格 §4 建議）
    assert (
        20 <= len(requirements) <= 30
    ), f"Expected 20-30 atomic requirements, found {len(requirements)}"

    # 五包均有要求
    packs = load_draft_packs()
    for pack_name, pack_data in packs.items():
        reqs = pack_data.get("requirements", [])
        assert len(reqs) >= 3, f"Pack '{pack_name}' has too few requirements: {len(reqs)}"

    for req in requirements:
        assert req.get("requirement_id"), "Requirement ID cannot be empty"
        assert req.get("obligation"), "Obligation text cannot be empty"

        # 檢核義務主體 (obligor)
        obligor = req.get("obligor")
        assert (
            obligor in VALID_OBLIGORS
        ), f"Requirement {req['requirement_id']} has invalid obligor '{obligor}', expected one of {VALID_OBLIGORS}"

        # 檢核精確來源參照
        rule_id = req["rule_ref"]["id"]
        assert rule_id in rule_map, f"Requirement references non-existent rule '{rule_id}'"
        parent_rule = rule_map[rule_id]
        assert len(parent_rule.source_refs) > 0, f"Rule '{rule_id}' has no source_refs"

        primary_source_id = parent_rule.source_refs[0].id
        assert (
            primary_source_id in valid_source_ids
        ), f"Rule source '{primary_source_id}' not found in manifest"

        # 檢核精確條次/條款標記
        source_entry = valid_source_ids[primary_source_id]
        section = req.get("section") or source_entry.get("section")
        assert (
            section and len(section.strip()) > 0
        ), f"Requirement {req['requirement_id']} lacks exact section/locator"


def test_cots_is_not_unconditionally_required_to_supply_vendor_source():
    """驗證套裝軟體 (COTS) 不得無條件要求廠商交付核心原始碼或承擔無上限責任。"""
    packs = load_draft_packs()
    cots_pack = packs.get("cots")
    assert cots_pack is not None, "COTS pack missing"

    cots_requirements = cots_pack.get("requirements", [])
    cots_rules = {r["rule_id"]: r for r in cots_pack.get("rules", [])}

    # 尋找與原始碼相關之要求
    source_code_reqs = [
        req
        for req in cots_requirements
        if "原始碼" in req["obligation"] or "escrow" in req["obligation"].lower()
    ]
    assert (
        len(source_code_reqs) > 0
    ), "COTS pack must include source code / escrow handling requirement"

    cots_source_requirement = source_code_reqs[0]
    # 核心斷言：COTS 交付原始碼必須具備適用條件，不得無條件適用
    assert (
        cots_source_requirement.get("condition") is not None
    ), "COTS source code requirement condition must not be None"

    condition_str = cots_source_requirement["condition"]
    assert len(condition_str.strip()) > 0
    # 條件應包含客製需求或原始碼保管約定 (Escrow)，而非通用無條件索取
    assert any(
        kw in condition_str for kw in ["customization", "custom", "escrow", "客製", "託管"]
    ), f"COTS source condition must restrict unconditional demand: {condition_str}"

    # 檢核侵權擔保或賠償責任不應要求無上限責任
    liability_rules = [
        r
        for r in cots_rules.values()
        if "侵權" in r["title"] or "責任" in r["title"] or "賠償" in r["title"]
    ]
    assert len(liability_rules) > 0
    liability_rule = liability_rules[0]
    assert liability_rule.get("company_position") is not None
    assert any(
        kw in liability_rule["company_position"]
        for kw in ["上限", "合理", "cap", "限制", "非無上限"]
    )


def test_all_imported_candidates_are_draft():
    """核心斷言：匯入之候選規則與要求狀態必須全部為 'draft'。

    未經正式發布與使用者審查前，嚴禁假造為 active 或 pending_approval。
    """
    imported_candidates = load_all_draft_rules()
    assert (
        len(imported_candidates) > 0
    ), "Should import candidate rules from all 5 draft packs"

    # 核心斷言
    assert all(
        r.status == "draft" or r.status == RuleStatus.DRAFT for r in imported_candidates
    )

    # 檢核原始要求字典狀態亦為 draft
    requirements = load_all_draft_requirements()
    assert len(requirements) > 0
    assert all(req.get("status") == "draft" for req in requirements)


def test_source_reconciliation_anchors():
    """驗證官方來源比對與校正錨點（設計規格 §3.3 與 §13）：

    1. 資訊服務採購契約範本（1131226版）：第16條第17款為資通安全責任，第16條第3款為智慧財產權。
    2. 資通安全管理法施行細則（115-01-05修正版）：委外監督現行第7條（非舊版第4條）。
    3. 中研院資通安全實施要點（115-09-07修正版）：委外以到場為原則，遠端為例外嚴管。
    """
    manifest = load_manifest()
    sources_by_locator = {s["locator"]: s for s in manifest["sources"]}

    # 1. 資訊服務 1131226
    pcc_it = sources_by_locator.get("TEMPLATE-PCC-IT-1131226")
    assert pcc_it is not None
    assert "第16條第17款" in pcc_it["section"]
    assert "第16條第3款" in pcc_it["section"]
    assert pcc_it["retrieval_status"] == "verified_full_text"

    # 2. 資安法施行細則 115-01-05
    cs_enact = sources_by_locator.get("LAW-CS-ENACT-1150105")
    assert cs_enact is not None
    assert "第7條" in cs_enact["section"]
    assert cs_enact["retrieval_status"] == "verified_full_text"

    # 3. 中研院實施要點 115-09-07
    as_cs = sources_by_locator.get("POLICY-AS-CS-1150907")
    assert as_cs is not None
    assert "到場為原則" in as_cs["section"] or "到場" in as_cs["section"]
    assert "遠端為例外" in as_cs["section"] or "遠端" in as_cs["section"]
    assert as_cs["retrieval_status"] == "verified_full_text"
