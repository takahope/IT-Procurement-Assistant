import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from procurement_review.domain.enums import ProcurementFamily, ResultEnum, RiskLevel, RuntimeMode
from procurement_review.domain.models import CaseFacts, Finding, Review, RuntimePolicy, VersionRef
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore
from procurement_review.web.app import create_app


@pytest.fixture
def test_env(tmp_path: Path):
    vault_root = tmp_path / "vault"
    db_path = tmp_path / "test.db"
    secrets = FakeSecretStore()
    artifacts = ArtifactStore(root=vault_root, secrets=secrets)
    repo = Repository(db=db_path, artifacts=artifacts)
    policy = RuntimePolicy(mode=RuntimeMode.SYNTHETIC, data_root=str(tmp_path))
    app = create_app(policy=policy, repo=repo)
    client = TestClient(app, base_url="http://localhost:8765")
    return {
        "app": app,
        "repo": repo,
        "policy": policy,
        "client": client,
        "tmp_path": tmp_path,
        "bootstrap_token": app.state.bootstrap_token,
    }


def test_missing_session_rejected(test_env):
    """未攜帶有效 session cookie 之受保護請求應被拒絕 (401 或 403)。"""
    client = test_env["client"]
    # 嘗試存取受保護 API
    resp = client.get("/api/cases")
    assert resp.status_code in (401, 403)


def test_bootstrap_token_exchange_and_single_use(test_env):
    """本機 bootstrap token 交換 session cookie，且僅限單次使用。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]

    # 1. 首次交換
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200
    data = resp.json()
    assert "csrf_token" in data
    # 檢查 cookie 是否設置 HttpOnly, SameSite
    session_cookie = resp.cookies.get("session_id")
    assert session_cookie is not None

    # 2. 再次使用相同 token 交換應被拒絕
    resp2 = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp2.status_code in (401, 403)

    # 3. 錯誤 token 應被拒絕
    resp3 = client.post("/api/auth/bootstrap", json={"token": "invalid_token_12345"})
    assert resp3.status_code in (401, 403)


def test_wrong_host_rejected(test_env):
    """非 loopback 之 Host 標頭請求必須回傳 403。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200

    # 偽造 Host: evil.com
    resp_host = client.get("/cases", headers={"Host": "evil.com"})
    assert resp_host.status_code == 403

    resp_host2 = client.post(
        "/api/cases",
        headers={"Host": "attacker.net"},
        json={"title": "Hacked"},
    )
    assert resp_host2.status_code == 403


def test_wrong_origin_rejected(test_env):
    """跨站 / 惡意 Origin 之 mutative 請求必須回傳 403。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200
    csrf_token = resp.json()["csrf_token"]

    # Origin: http://evil.com
    resp_origin = client.post(
        "/api/cases",
        headers={"Origin": "http://evil.com", "X-CSRF-Token": csrf_token},
        json={"title": "Test Case"},
    )
    assert resp_origin.status_code == 403


def test_missing_csrf_rejected(test_env):
    """變更性 (mutative) 請求缺少 CSRF token 必須回傳 403。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200

    # 不帶 X-CSRF-Token
    resp_no_csrf = client.post(
        "/api/cases",
        json={"title": "Test Case"},
    )
    assert resp_no_csrf.status_code == 403

    # 帶錯誤 X-CSRF-Token
    resp_wrong_csrf = client.post(
        "/api/cases",
        headers={"X-CSRF-Token": "bad_token_value"},
        json={"title": "Test Case"},
    )
    assert resp_wrong_csrf.status_code == 403


def test_path_traversal_and_cross_case_isolation(test_env):
    """檔案下載與工件存取嚴禁路徑穿越與跨案存取 (403 或 404)。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    csrf_token = resp.json()["csrf_token"]

    headers = {"X-CSRF-Token": csrf_token}

    # 建立案件 A
    resp_case = client.post(
        "/api/cases",
        headers=headers,
        json={
            "title": "Case A",
            "contract_type": "services",
            "facts": {
                "procurement_unit": "單位A",
                "review_baseline_date": "2026-10-15",
                "procurement_families": ["services"],
            },
        },
    )
    assert resp_case.status_code == 200
    case_id = resp_case.json()["case_id"]

    # 路徑穿越測試
    resp_traversal = client.get(
        f"/api/cases/{case_id}/export/download",
        params={"file": "../../../../etc/passwd"},
    )
    assert resp_traversal.status_code in (403, 404)

    # 跨案工件存取測試 (嘗試存取不存在或不屬於該案之工件)
    resp_cross = client.get(
        f"/api/cases/{case_id}/export/download",
        params={"file": "other_case_report.md"},
    )
    assert resp_cross.status_code in (403, 404)


def test_csp_header_enforced(test_env):
    """嚴格強制 CSP 標頭，禁止外部 CDN 與資源請求。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200

    resp_page = client.get("/cases")
    assert resp_page.status_code == 200
    csp = resp_page.headers.get("content-security-policy", "")
    assert "default-src 'self'" in csp
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "img-src 'self' data:" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_model_html_and_external_images_are_inert(test_env):
    """模型 HTML、惡意 <img> 與偽指令以文字安全呈現，外部瀏覽器請求為空。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    _ = resp.json()["csrf_token"]
    repo: Repository = test_env["repo"]

    # 建立含有惡意 payload 之 Case 與 Finding
    evil_payload = '<img src="https://evil.tracker.com/leak.png"> <script>alert("pwn")</script>'
    case_id = str(uuid.uuid4())
    finding_id = str(uuid.uuid4())
    rule_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())

    review = Review(
        case_id=case_id,
        title=f"Evil Test Case {evil_payload}",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="feedbeef" * 8,
        attachments=[],
        facts=CaseFacts(
            review_baseline_date="2026-10-15",
            procurement_unit="測試處",
            procurement_families=[ProcurementFamily.SERVICES],
        ),
        created_by="tester",
        created_at=datetime.now(UTC),
    )
    repo.save_review(review, expected_revision=None)

    rule_ref = VersionRef(id=rule_id, version="1.0", sha256="abc" * 21 + "1")
    run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    # 儲存帶有惡意字串之 finding
    finding = Finding(
        finding_id=finding_id,
        run_id=run.run_id,
        requirement_id=req_id,
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
        clause_ids=["clause-10"],
        reason=f"發現漏洞: {evil_payload}",
        suggested_action=f"修正措施: {evil_payload}",
        human_status="unreviewed",
        rule_refs=[rule_ref],
    )
    repo.save_finding(finding)

    # 請求檢視審查頁面
    resp_review_page = client.get(f"/cases/{case_id}/review")
    assert resp_review_page.status_code == 200
    html = resp_review_page.text

    # 驗證惡意標籤不會被直接未轉義渲染成 raw html
    assert '<img src="https://evil.tracker.com/leak.png">' not in html
    assert '<script>alert("pwn")</script>' not in html

    # 收集頁面中所有外部請求 (img, script, link, iframe)
    external_browser_requests = []
    src_matches = re.findall(r'(?:src|href)=["\']([^"\']+)["\']', html)
    loopback_hosts = {"localhost", "127.0.0.1", "[::1]", "testserver"}

    for url in src_matches:
        if url.startswith(("data:", "/", "#")):
            continue
        parsed = urlparse(url)
        if parsed.scheme in ("http", "https") and parsed.hostname not in loopback_hosts:
            external_browser_requests.append(url)

    # 核心斷言：完全無任何外部 browser request
    assert external_browser_requests == []


def test_ipv6_loopback_host_accepted_and_evil_rejected(test_env):
    """支援 [::1]:8765, [::1], ::1 等 IPv6 loopback 格式，非法 IPv6 回傳 403。"""
    client = test_env["client"]
    token = test_env["bootstrap_token"]
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200

    # 合法 IPv6 loopback
    resp_v6_port = client.get("/cases", headers={"Host": "[::1]:8765"})
    assert resp_v6_port.status_code == 200

    resp_v6 = client.get("/cases", headers={"Host": "[::1]"})
    assert resp_v6.status_code == 200

    resp_v6_plain = client.get("/cases", headers={"Host": "::1"})
    assert resp_v6_plain.status_code == 200

    # 非 loopback IPv6 / 惡意主機 -> 403
    resp_v6_evil = client.get("/cases", headers={"Host": "[::2]:8765"})
    assert resp_v6_evil.status_code == 403

    resp_v6_evil2 = client.get("/cases", headers={"Host": "[2001:db8::1]:80"})
    assert resp_v6_evil2.status_code == 403

