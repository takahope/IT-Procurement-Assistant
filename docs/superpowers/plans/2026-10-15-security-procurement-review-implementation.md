# 中央研究院資訊採購合約資安審查助手 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立單人本機審查工具，依核准規則檢查中研院四類資訊採購的資安要求，經本機遮罩及人工出站確認後使用雲端模型，產出可追溯報告與修改草稿。

**Architecture:** Python 模組化單體，SQLite 保存版本／狀態，受控檔案庫保存加密文件及請求。明確工作管線同時列舉條款與適用要求，所有模型呼叫經不可變出站 artifact；本機網頁提供確認、補標、複核與匯出。先以合成資料與 MockProvider 完成端到端，再接一個核准供應商。

**Tech Stack:** Python 3.13、uv、Pydantic 2、sqlite3、FastAPI／Uvicorn、Jinja2＋原生 JavaScript／CSS、python-docx＋安全 XML 檢查、pypdf、cryptography、keyring、HTTPX、pytest／pytest-playwright、ruff。pii-guard 作可替換偵測候選，經相容性與效果驗證才啟用；所有實際依賴在執行時選穩定版本並鎖定，不使用開發版。Python 小版本與框架為本計畫的工程選擇，非使用者另行指定。

**Spec:** [已核准 v0.2](../specs/2026-10-15-security-procurement-review-design.md)。執行者先讀設計與本計畫；原始 v0.1 留作歷史，不以其單一類型範圍覆蓋 v0.2。

## Global Constraints

- 「單人、本機執行；Python 明確步驟管線、SQLite 紀錄、JSON 規則及 schema；不採自主工具呼叫、多代理或向量資料庫。」這是產品架構限制，開發協作方式另依使用者選擇。
- 「四類均可建案，但各規則包分別驗收；未驗收的類別明示『尚未支援正式審查』，不默默降級。」
- 「首版自動擷取支援無追蹤修訂的 DOCX 與文字型 PDF；舊 `.doc`、掃描、複雜版面先經本機轉換及人工確認文字，再送入同一管線。」
- 「首版單一核准雲端模型供應商。本地模型及其他供應商保留介面，不列首版完成條件。」
- 「不設獨立語氣模型、案例推薦或自動 Word 寫回；先交付繁中 Markdown 與 JSON 報告及可複製修改草稿。」
- 「模型自信不作可信度分數，不輸出『整份95%合規』。」
- 「一般日誌無原文、prompt、回覆、映射與秘密。」資料、金鑰及真實評測都在 repo 外；對外回報亦不得帶回原文給開發代理。
- 「真實資料模式在期限政策未確認前不啟用。」雲端同意不替代特定供應商及資料分類核准。
- 審查／風險 enum、不可變版本、兩條覆蓋路徑、人工實質複核及來源性質按規格 §3–9 落實。
- 本次僅交付計畫；未安裝套件、初始化 Git、呼叫付費模型或實作產品。工作目錄目前僅有設計與參考文件。

## Review Focus

1. 同名附件重新上傳但內容改變：以內容／快照判定，舊核准失效；T3 測 `test_same_filename_new_content_invalidates_run`。
2. 表格、全形字元或正規化讓否定詞／時限錯位：保留原文位置，無法對應即待確認；T6 測 `test_normalization_preserves_negation_and_source_offsets`。
3. 點兩次送出、timeout 後重試或程式崩潰：不可無紀錄重送，不能宣稱供應商端 exactly-once；T9 測 `test_duplicate_submit_and_uncertain_delivery`。
4. 多類型混合，缺一份 EULA 而其他條款完整：共用要求去重，只有相關項目待確認；T7 測 `test_mixed_cloud_cots_missing_eula_is_localized`。
5. 合約內含假的系統指令、外連圖片或看似遮罩 token 的原文：不執行、不外連、不錯換；T8／T10／T12 各測遮罩、推論輸入與瀏覽器行為。

---

## 執行順序與關卡

這是一個共用案件與核准狀態的產品，採單一計畫；解析、遮罩、審查與 UI 不能各自宣稱已完成產品。T1–T4 建安全資料基礎，T5 整理規則，T6–T10 完成 M1，T11–T12 完成 M2，T13–T16 完成真實接入與 M3。T5 的正式規則核准可以與合成資料開發錯開，但真實結論必須等待它。

| 狀態 | 可以做 | 不可聲稱 |
|---|---|---|
| 合成模式完成 | 本機假資料端到端、mock 呼叫、核准／版本／安全測試 | 模型判斷已可靠、四類正式可用 |
| 單類試跑完成 | 已核准供應商與規則下，人工複核該類樣本 | 其他三類同樣通過 |
| 四類首版完成 | 四包均通過 M3，保存還原與導入文件完整 | 所有法律問題已涵蓋、未來零漏判 |

執行方法未定；建議 Native 依序實作，因核心任務緊密共享資料契約，避免多人同時修改模型與狀態機。此建議不取代使用者的執行方式選擇。

## 檔案與責任

以下路徑為預計建立；不把現有真實文件移入測試或公開資料夾。首版開發在目前專案根目錄進行；如使用 Git，先建立安全 `.gitignore`，再初始化本機版本控制。每個任務僅 stage Files 所列的程式／合成測試／可版控文件，禁止 `git add .`、自動 push。沒有 Git 時記錄完成證據，不能為完成 commit 步驟中斷任務。

```text
pyproject.toml / uv.lock / .python-version / .gitignore
src/procurement_review/
  domain/        enums.py models.py errors.py
  storage/       vault.py secrets.py repository.py migrations/001_initial.sql
  runtime/       config.py gates.py audit.py lifecycle.py
  rules/         catalog.py applicability.py releases.py
  documents/     ingest.py docx_reader.py pdf_reader.py structure.py
  review/        context.py coverage.py workflow.py validation.py drafting.py
  masking/       detector.py pii_guard_adapter.py session.py restoration.py
  egress/        payload.py approvals.py dispatcher.py
  providers/     base.py mock.py cloud.py
  feedback/      service.py
  export/        reports.py
  web/           app.py security.py routes.py templates/ static/
  evaluation/    metrics.py runner.py
  cli.py
schemas/         domain.json provider-response.json
rules/           sources/manifest.json drafts/{common,services,cloud,cots,development}.json
tests/           unit/ integration/ e2e/ fixtures/synthetic/ conftest.py
evaluations/     synthetic-manifest.json acceptance-policy.example.json
docs/            operations.md rule-authoring.md source-reconciliation.md acceptance.md
```

`models.py` 只宣告資料契約與無副作用驗證；業務邏輯留各模組。若超過可讀範圍，可按 source／review／egress 拆檔並維持匯出名稱。公用測試 fixtures 按任務加入 `tests/conftest.py`；不建立假裝通過生產安全檢查的共用 bypass。

下列 Files 中以 `storage/`、`runtime/`、`rules/*.py`、`documents/`、`review/`、`masking/`、`egress/`、`providers/`、`feedback/`、`export/`、`web/`、`evaluation/` 及 `cli.py` 表示的程式路徑，均相對 `src/procurement_review/`；`tests/`、`docs/`、`schemas/`、`evaluations/` 與 `rules/` JSON 資料路徑相對專案根。各 package 補 `__init__.py`，不另列為獨立任務。

## 共用型別與介面約定

T1 定義以下型別，後續任務直接 import；ID 為 UUID 字串，日期使用明確 ISO 日期／UTC timestamp，數值底線使用 Decimal 與單位，禁止二進位浮點比較金額。完整欄位以規格 §9 為底。

| 型別 | 本計畫新增明確欄位／規則 |
|---|---|
| `VersionRef` | `id`, `version`, `sha256`；所有引用精確鎖版 |
| `CaseFacts` | 規格 §3.1 全部事實；未知用 `None` 並列 `unknown_fields`，不把空值當 false |
| `RuntimePolicy` | `mode: synthetic/real`, `data_root`, provider／storage／retention／masking／rules 的核准參照；缺項時回 gate 問題 |
| `SourceReference`, `Rule`, `Requirement` | 規格欄位；Requirement 加 `required_documents`, `condition`, `protected_constraints` |
| `ApplicabilityDecision` | `requirement_ref`, `state: applicable/not_applicable/unknown`, `reasons` |
| `DocumentSnapshot` | `blocks`, `clauses`, `issues`, `manifest`, `confirmation_ref`；位置用 `SourceSpan`，DOCX 不生成猜測頁碼 |
| `SourceSpan` | document／block ID、原始文字 start/end、PDF page 可選、結構路徑；offset 為 Python Unicode code point |
| `Review`, `ReviewRun` | 規格欄位；`revision`, `stale`, `parent_run_id`；狀態轉移 CAS，不能只信 UI |
| `ContextBundle` | 要求、原文片段、定義／例外／引用與每項取得情形；`complete`, `unknowns` |
| `CoverageMatrix` | clause／requirement 兩表；`unprocessed_ids`, `unresolved_ids` 分開，避免待確認被算未執行 |
| `DetectedSpan`, `MaskingSession` | 範圍、類型、實體群組、映射版本；`roundtrip_ok`、品質／機密阻擋原因 |
| `RestorationResult` | `text: str | None`, `unknown_tokens`, `wrong_case_tokens`, `adoptable` |
| `OutboundDraft`, `PreparedRequest` | 前者本機明文組裝物；後者僅遮罩的 `body: bytes`, endpoint／model／refs／hash／masking_ref |
| `EgressApproval`, `ProviderReply` | 核准綁請求與重送次數；回應保存受控 artifact ref、usage、finish_reason、request_id，不進日誌 |
| `Finding`, `ValidationReport` | enum 結果與風險、來源／理由／草稿；validation 分 structure／source／substance；人工實質狀態獨立 |
| `SuggestedChange`, `HumanDecision`, `Feedback` | 原發現與 run 版本、修改內容／目的／連動、採用／修改／退回、理由及核准案例旗標 |
| `ReviewReport`, `ExportPaths` | 案件版本、來源、覆蓋、未完成、草稿及人工紀錄；匯出模式 masked/plaintext |
| `GateReport`, `EvaluationReport`, `PurgePlan` | 結構化問題／指標分母／刪除清單，均不含需對外記錄的明文 |
| `ProviderConfig`, `AuditEvent` | 前者為 provider／endpoint／model／credential_ref／limits／price_version／approval_ref；後者依設計 §9 保存安全稽核欄位 |

`ArtifactStore`、`Repository`、`SecretStore` 為 T2–T3 建立的 class；`Detector`、`ProviderAdapter` 為 T8–T9 Protocol。錯誤統一繼承 `DomainError(code, safe_message)`，原始例外如需留證只進加密 artifact。

測試以合成資料、FakeSecretStore、HTTPX MockTransport 為預設；禁止意外網路，外部 live 測試須顯式選擇並經產品出站核准。每次測試用獨立暫存資料根，不讀使用者真實 Keychain 或資料庫。

以下測試斷言片段中的 `case`、`finding`、`request` 等，均由該任務的合成 fixture 建立；`repo`、`transport`、`policy` 由 conftest 注入。每個例子的 setup 必須使用 Interfaces 指定的方法；不得為符合斷言另建測試專用產品流程。

真實模式區分「受控試跑」與「正式使用」：前者須具備儲存、期限、供應商、來源規則及逐次出站核准，但可使用尚未通過M3的規則包並顯示試跑標示；正式使用再要求包的發布驗收。如此可取得真實評測證據，不形成必須先驗收才能評測的循環。

## Task 1: T1 型別契約與合成案件

**Files:** 建立 `pyproject.toml`, `.python-version`, `.gitignore`, `src/procurement_review/domain/{enums,models,errors}.py`, `schemas/domain.json`, `tests/conftest.py`, `tests/unit/test_domain.py`, `tests/fixtures/synthetic/cases.json`；產生 `uv.lock`。

**Interfaces:** 產出上表型別；`validate_case(data: dict) -> Review`；enum 的 Python 值使用 `compliant/concern/missing/needs_confirmation/not_applicable/uncovered`，UI 對應規格中文。所有 schema `extra=forbid`，ID／日期／版本嚴格驗證。

- [ ] 寫 `test_domain.py`：`test_unknown_is_not_false` 驗 `CaseFacts.remote_access is None` 不等同不適用；`test_missing_finding_requires_scope` 驗無 clause_ids 的 missing 必有查核範圍；`test_reject_unknown_result` 驗 `result='safe'` 拒絕。定義合成 cases：四類各一及 cloud+cots 混合一案，不使用現有指南的真實廠商資訊。
- [ ] 核心斷言：`assert validate_case(case_with_unknown_remote_access).facts.remote_access is None`；`with pytest.raises(ValidationError): Finding.model_validate(finding_with_result_safe)`。
- [ ] `uv run pytest tests/unit/test_domain.py -q`，確認尚缺模型／驗證而失敗，不把依賴安裝失敗當 RED。
- [ ] 建最小 package／測試設定與模型；schema 由模型產生，新增 `test_exported_schema_matches_models`。`.gitignore` 排除根目錄參考 DOC、原始指南、`.memsearch/`、私有資料、資料庫、明文匯出與 `.env`；公開設計文件可版控。
- [ ] 同一測試命令 PASS；`uv lock --check` 成功。依賴 license／平台不相容時調整選型紀錄，不能假裝鎖定完成。
- [ ] 審閱 staged diff 後提交 `feat: define review contracts and synthetic cases`。

## Task 2: T2 受控儲存與真實模式關卡

**Files:** 建立 `storage/{vault,secrets}.py`, `runtime/{config,gates,audit}.py`, `tests/unit/test_vault.py`, `tests/unit/test_runtime_gates.py`。

**Interfaces:** `SecretStore.get_or_create_key(name: str) -> bytes`；`ArtifactStore(root: Path, secrets: SecretStore)` 的 `put(case_id: str, kind: str, data: bytes) -> str`, `get(case_id: str, artifact_id: str) -> bytes`；`check_runtime(policy: RuntimePolicy, operation: str) -> GateReport`；`audit_event(event: AuditEvent) -> None`。

- [ ] 寫失敗測試：跨案 get 拒絕；密文篡改拒絕；資料根在 repo、symlink 跳出、檔名含 `../` 均拒絕。`test_real_ingest_requires_storage_retention_approval` 在原檔落盤前阻擋缺政策的 real 匯入；synthetic+mock 可正常工作。`test_no_plaintext_in_logs` 捕捉含 prompt 的模擬例外，確認日誌無其內容。
- [ ] 核心斷言：`with pytest.raises(DomainError): store.get(other_case_id, artifact_id)`；`assert secret_text not in caplog.text`。GateReport 固定有 `ok: bool`, `issues: list[str]`；`assert not check_runtime(unapproved_real_policy, 'ingest').ok`。
- [ ] `uv run pytest tests/unit/test_vault.py tests/unit/test_runtime_gates.py -q`，確認 RED。
- [ ] 實作 AES-GCM artifact 加密（每筆新 nonce，case_id／kind 作 AAD）、OS Keychain 與測試 FakeSecretStore；本機目錄0700、檔案0600、原子寫入及 ID 驗證。後續 Repository 的敏感 JSON 亦經此庫，SQLite 只留 opaque ID、版本／狀態、hash 與加密 artifact ref。日誌用白名單欄位，停用第三方 debug body。
- [ ] `get_or_create_key` 僅能在空資料庫首次初始化建立；既有 artifact 對應 key 遺失時回 `KEY_UNAVAILABLE`，不能重新產生 key 覆蓋。若指定儲存裝置無法保證權限，真實模式阻擋並顯示原因。
- [ ] 同命令 PASS，額外掃測試 root 確認唯一合成敏感字串不出現在密文、日誌或非加密檔案；不宣稱磁碟加密已驗證。
- [ ] 提交 `feat: add private artifact storage and runtime gates`。

## Task 3: T3 案件儲存、不可變版本與恢復

**Files:** 建立 `storage/repository.py`, `storage/migrations/001_initial.sql`, `tests/integration/test_repository.py`, `tests/integration/test_invalidation.py`。

**Interfaces:** `Repository(db: Path, artifacts: ArtifactStore)`；`save_review(review: Review, expected_revision: int | None) -> Review`；`get_review(id: str) -> Review`；`create_run(review_id: str, rule_refs: list[VersionRef], parent_run_id: str | None = None) -> ReviewRun`；`get_run(id: str) -> ReviewRun`；`invalidate(review_id: str, reason: str) -> list[str]`；`save_finding(finding: Finding) -> None`；`append_feedback(value: Feedback, idempotency_key: str) -> Feedback`。

- [ ] 測舊版本仍可查、CAS 衝突拒絕、同回饋 key 不重複。`test_same_filename_new_content_invalidates_run` 修改文件 hash 後，舊 run／核准／草稿均 stale；改 UI 排版不 stale。`test_interrupted_run_requires_new_run_id` 驗保留原失敗紀錄，新 run 不繼承人工核准。
- [ ] 核心斷言：`assert repo.get_run(old_run.id).stale is True`；`assert repo.append_feedback(feedback, 'click-1').id == repo.append_feedback(feedback, 'click-1').id`。
- [ ] `uv run pytest tests/integration/test_repository.py tests/integration/test_invalidation.py -q`，確認 RED。
- [ ] 實作 migration、foreign keys、單寫入交易、唯一性與 append-only 版本；有效性檢查與送出預約必須同一交易重新確認。來源／規則撤銷經反向引用使相關 active run 失效，歷史 artifact 不覆寫。新增查詢所需方法時同步維護此介面表。
- [ ] 同命令 PASS；用兩個 Repository connection 測併發 revision 衝突及重複操作，檢查 SQLite／WAL 無敏感明文。
- [ ] 提交 `feat: persist immutable reviews and invalidate stale approvals`。

## Task 4: T4 來源、規則生命週期與適用性

**Files:** 建立 `rules/{catalog,applicability,releases}.py`, `tests/unit/test_applicability.py`, `tests/integration/test_rule_release.py`。

**Interfaces:** `evaluate_applicability(requirement: Requirement, facts: CaseFacts) -> ApplicabilityDecision`；`release_rules(rules: list[Rule], sources: list[SourceReference], approver: str, at: datetime, repo: Repository) -> list[VersionRef]`；`select_requirements(refs: list[VersionRef], facts: CaseFacts, as_of: date, repo: Repository) -> list[ApplicabilityDecision]`；`revoke_rule(ref: VersionRef, reason: str, repo: Repository) -> list[str]`。

- [ ] 測 draft／未查核／未核准來源不得 release；同規則跨包去重；日期不適用、衝突及事實未知有明確結果。`test_guideline_is_not_law` 保留建議性質。`test_unknown_procurement_regime_does_not_block_confidentiality` 僅程序相關要求 unknown。撤銷規則必使 T3 的相關 run 失效。
- [ ] 核心斷言：`assert evaluate_applicability(procurement_rule, unknown_facts).state == 'unknown'`；`assert len({d.requirement_ref.id for d in decisions}) == len(decisions)`。release 僅接受 pending_approval 的有效版本與本機人工核准動作；草稿先送審，不允許呼叫端填任意名字即核准。
- [ ] `uv run pytest tests/unit/test_applicability.py tests/integration/test_rule_release.py -q`，確認 RED。
- [ ] 使用受限 declarative condition：`all/any/not/eq/in/gte/lte/exists`，三值邏輯；禁止 eval 或規則內執行程式。unknown 不等於 false；期限採半開區間 `[effective_from,effective_to)`，來源未知期限不得猜。數值檢查僅消費人工確認值，語意判斷不能標 deterministic。
- [ ] 同命令 PASS，加入來源更新待查時只阻擋相關要求的回歸案例。
- [ ] 提交 `feat: govern rule releases and applicability`。

## Task 5: T5 四類候選規則與來源核對（M0）

**Files:** 建立 `rules/sources/manifest.json`, `rules/drafts/{common,services,cloud,cots,development}.json`, `docs/source-reconciliation.md`, `docs/rule-authoring.md`, `tests/integration/test_rule_sources.py`；真實來源全文存受控庫，repo manifest 僅存允許版控的來源資訊。

**Interfaces:** 沿用 T4 release；產出各包 `Rule`／`Requirement` draft JSON。manifest 記 source ref、精確條次／定位、版本、查核時間、文件 hash 與取得狀態；正式 release 透過產品保存，不假造使用者核准。

- [ ] 寫 `test_rule_sources.py`：`test_release_rejects_unverified_source`、`test_requirement_has_exact_source_and_obligor`、`test_cots_is_not_unconditionally_required_to_supply_vendor_source`；來源引用錯款／未取得全文時驗證報錯。
- [ ] 核心斷言：`assert all(r.status == 'draft' for r in imported_candidates)`；`assert cots_source_requirement.condition is not None`；未取得來源全文時 `with pytest.raises(DomainError): release_rules(rules, unverified_sources, actor, now, repo)`。
- [ ] `uv run pytest tests/integration/test_rule_sources.py -q`，先以故意錯誤合成規則確認 RED。
- [ ] 依設計 §13 官方來源取得／核對完整資料：資訊服務1131226、雲端與財物範本、現行資安法及子法、採購／科研制度、院規及有個資時的依據。網路查核只用公開資訊；內部文件交由使用者本機匯入及確認。記錄指南錯款與各條件差異，整理初始約20–30個原子要求，五包均有清單，不能用數量代替完整性。
- [ ] 測試 PASS；人工逐項核對來源、義務主體、適用條件、風險與草稿底線，產出使用者可核准表。未核准仍 draft；開發續用獨立 synthetic release，不將其混入真實規則庫。
- [ ] 提交可版控 draft 與核對方法：`docs: prepare four procurement rule packs for approval`。M0正式完成以真實核准紀錄為證，不能把文件編寫完成等同核准。

## Task 6: T6 文件擷取、品質確認與位置映射

**Files:** 建立 `documents/{ingest,docx_reader,pdf_reader,structure}.py`, `tests/unit/test_ingest.py`, `tests/fixtures/synthetic/documents/`。

**Interfaces:** `ingest(path: Path, review_id: str, policy: RuntimePolicy, artifacts: ArtifactStore) -> DocumentSnapshot`；`confirm_text(snapshot: DocumentSnapshot, corrected_blocks: list[dict], actor: str) -> DocumentSnapshot`；`segment(snapshot: DocumentSnapshot) -> DocumentSnapshot`。

- [ ] 合成 fixtures 包含表格、頁首頁尾、文字方塊、插入／刪除修訂、隱藏字、掃描頁、混合文字／圖片 PDF、加密 PDF、損毀 ZIP、超大解壓量。驗修訂不默認接受；掃描／嵌入物未讀不靜默通過。`test_normalization_preserves_negation_and_source_offsets` 對「不得」「３０日」驗能回原文且不變義。
- [ ] 核心斷言：`assert block.raw_text[span.start:span.end] == '不得'`；`assert snapshot.confirmation_ref is None`；`assert any(issue.code == 'TRACKED_CHANGES' for issue in snapshot.issues)`。Issue 固定包含 `code`, `block_id`, `safe_message`。
- [ ] `uv run pytest tests/unit/test_ingest.py -q`，確認 RED。
- [ ] DOCX 以 python-docx 配安全 XML 掃描識別未支援結構；PDF 以 pypdf逐頁擷取，保留頁碼／block，座標無法可靠取得則留空且不假造。加入檔案大小、頁數／解壓量上限與明確錯誤，不執行宏、外連或密碼猜測。舊DOC／掃描提供「原檔＋人工文字＋確認」路徑；可記錄本機外部轉換工具版本，首版不要求自動OCR。
- [ ] 同命令 PASS；確認文字產生新 snapshot、原檔／人工改動歷程可查。對不支援內容必須顯示問題並要求確認，無法充分確認者保留 unknown。
- [ ] 提交 `feat: ingest documents with explicit quality and source mapping`。

## Task 7: T7 全量要求覆蓋與長文件上下文

**Files:** 建立 `review/{context,coverage}.py`, `tests/unit/test_context.py`, `tests/unit/test_coverage.py`。

**Interfaces:** `build_context(requirement: Requirement, documents: list[DocumentSnapshot], max_chars: int) -> ContextBundle`；`build_coverage(documents: list[DocumentSnapshot], decisions: list[ApplicabilityDecision], findings: list[Finding]) -> CoverageMatrix`。`max_chars` 僅為內部預算，adapter 另檢查供應商實際限制。

- [ ] 驗找不到搜尋命中仍列出每項要求；缺件不能 missing；無相關規則條款顯示 uncovered。`test_mixed_cloud_cots_missing_eula_is_localized` 驗共用要求只一筆，EULA 相關待確認而其他證據仍可用。定義／例外分處附件、引用迴圈及超長內容時，不截斷後宣稱完整。
- [ ] 核心斷言：`assert not build_context(eula_requirement, documents_without_eula, 12000).complete`；`assert set(matrix.requirements) == {d.requirement_ref.id for d in decisions}`。matrix 的兩表以snapshot內 clause ID／requirement ID為key，值含版本、處理與結果。
- [ ] `uv run pytest tests/unit/test_context.py tests/unit/test_coverage.py -q`，確認 RED。
- [ ] 建全文／標籤搜尋及引用圖；按要求查所有已確認文件，帶原文 spans。分批安排必須列所有條款，不能把 top-k 當完整證據。無法查完／範圍不足回 `complete=False`；只有文件齊備、所有相關批次與交叉引用已檢查才可支援缺漏結論。
- [ ] 同命令 PASS，驗 `unprocessed_ids` 為空與存在待確認可以同時成立；報告須分開呈現處理率與未解決數。
- [ ] 提交 `feat: enumerate requirement coverage and preserve cross references`。

## Task 8: T8 遮罩、人工補標與安全還原

**Files:** 建立 `masking/{detector,pii_guard_adapter,session,restoration}.py`, `tests/unit/test_masking.py`, `tests/integration/test_detector_contract.py`。

**Interfaces:** `Detector.detect(text: str) -> list[DetectedSpan]`；`mask(draft: OutboundDraft, session: MaskingSession, detector: Detector) -> tuple[OutboundDraft, MaskingSession]`；`apply_annotations(session: MaskingSession, spans: list[DetectedSpan]) -> MaskingSession`；`restore(text: str, session: MaskingSession) -> RestorationResult`。

- [ ] 測繁中同名／別名、重疊實體、公司與人名、商業詞典、數字過遮、原文假 token、模型新增 token、跨案 token。驗所有請求文字欄位均遮罩且 round-trip 相等；秘密阻擋而不是只替換後放行；改補標產生新 session 使舊出站核准失效。
- [ ] 核心斷言：`assert restore(masked_text, session).text == original_text`；`assert not restore(other_case_token, session).adoptable`；字串「<PERSON_1>」原本就存在時，還原必須仍是相同字串，不得換成人名。
- [ ] `uv run pytest tests/unit/test_masking.py tests/integration/test_detector_contract.py -q`，確認 RED。
- [ ] 以 Detector adapter 隔離 pii-guard，固定可驗證版本，檢查其依賴／本機模型及介面，不直接假設 README 的 API。若無法相容，保留 mock 測試及明確 real gate，評估本機 Presidio＋繁中 NER 替代後記錄選型；不能靜默換成只有 regex 卻宣稱等效。轉義 literal token，分案 token namespace與映射加密；人為補遮／放回記操作者及版本。
- [ ] 同命令 PASS；離線啟動整合測試確認權重預先安裝後執行時無出站。已知合成資料各類偵測指標分開呈現，不以單一總分宣稱零漏失。
- [ ] 提交 `feat: mask complete outbound content and validate restoration`。

## Task 9: T9 不可變出站核准與 MockProvider

**Files:** 建立 `egress/{payload,approvals,dispatcher}.py`, `providers/{base,mock}.py`, `tests/integration/test_egress.py`, `tests/unit/test_provider_contract.py`。

**Interfaces:** `ProviderAdapter.encode(draft: OutboundDraft) -> bytes` 與 `decode(body: bytes) -> ProviderReply`；adapter 只轉換、不自行連網，endpoint／model 來自其固定 ProviderConfig。`prepare_egress(run_id: str, draft: OutboundDraft, session: MaskingSession, detector: Detector, adapter: ProviderAdapter, repo: Repository) -> PreparedRequest`；`approve(request: PreparedRequest, actor: str, max_attempts: int, repo: Repository) -> EgressApproval`；`dispatch(request_id: str, approval_id: str, repo: Repository, transport: httpx.BaseTransport) -> ProviderReply`。

- [ ] 測無核准、body 改一字、改 endpoint／model、stale rule、改來源版本均零傳輸。`test_duplicate_submit_and_uncertain_delivery` 測兩個請求同時送、在已送未收到時 timeout，驗原子 attempts 預約、狀態 `delivery_unknown`，不自動重送。測 HTTP redirect、惡意 endpoint、provider 工具要求都不能開其他網路。
- [ ] 核心斷言：篡改後 `assert captured_requests == []`；成功傳輸 `assert captured_requests[0].content == prepared.body`；雙重點擊 `assert len(captured_requests) == 1`。MockProvider 使用固定 fixture，且 transport 只能是離線 MockTransport。
- [ ] 明確組裝次序：T8 遮罩全部 OutboundDraft → adapter encode → 檢查 encode 後全部資料文字欄位及敏感殘留 → 產生 PreparedRequest。encode 不得增加任意文件上下文；發現新敏感內容則拒絕並回上一階段處理，禁止對已雜湊 bytes 再作替換。
- [ ] `uv run pytest tests/integration/test_egress.py tests/unit/test_provider_contract.py -q`，確認 RED。
- [ ] 序列化完成後對實際 body bytes＋目的地／model／refs 作核准 digest，預覽讀同一 artifact，送出亦用同一 bytes。集中 HTTPX client `follow_redirects=False`, `trust_env=False`；只有設定核准的 HTTPS host／port／path 可用，禁 URL userinfo／query secret。預設 `max_attempts=1`，使用者明示可改最多3次；429 等可依核准範圍有限重試，timeout／取消後未知交付須人工決定。同一 request 不允許併發 attempts。
- [ ] 同命令 PASS；MockTransport 捕獲實際 bytes，驗與預覽 digest 完全一致；認證 key 僅送出時自 SecretStore 取，不進預覽／log。真實模式不能指定 MockProvider 來通過驗收。
- [ ] 提交 `feat: bind egress approval to immutable requests`。

## Task 10: T10 審查執行與三層驗證（M1）

**Files:** 建立 `review/{workflow,validation}.py`, `schemas/provider-response.json`, `tests/integration/test_review_workflow.py`, `tests/unit/test_validation.py`。

**Interfaces:** `plan_review(run: ReviewRun, contexts: list[ContextBundle]) -> list[OutboundDraft]`；`accept_review_reply(run_id: str, reply: ProviderReply, repo: Repository) -> list[Finding]`；`validate_findings(findings: list[Finding], contexts: list[ContextBundle]) -> ValidationReport`；`finalize_run(run_id: str, repo: Repository) -> CoverageMatrix`。

- [ ] 驗不存在的 source／rule／clause、錯版本、引文不符、未確認來源、truncated finish_reason、格式錯誤不產可採用結果。缺附件時模型回 missing 必轉待確認並記原因；未覆蓋要求不能被模型省略。`test_document_instruction_cannot_change_rules` 驗文件假指令只作資料，沒有工具執行路徑；不以 mock 通過證明模型抵抗注入品質。
- [ ] 核心斷言：`assert findings[0].result == 'needs_confirmation'`（缺EULA卻回missing）；有效引用仍 `assert findings[0].human_status == 'pending'`。請求進行中輸入改版時，回覆只保存於舊run且標stale，不可納入新報告。
- [ ] `uv run pytest tests/integration/test_review_workflow.py tests/unit/test_validation.py -q`，確認 RED。
- [ ] 明確批次任務狀態與進度：planned／awaiting_approval／running／done／blocked／failed。來源短引文以原始 spans 驗；三種 validation 分開，substance 始終保持人工 pending，直到 T11 決定。跨文件衝突另建待核准請求，保留兩側引用與效力未知；來源存在不能自動判 supports=True。
- [ ] 同命令 PASS；整體核准前檢查所有批次、條款及要求均有紀錄。未完成可匯出「未完成報告」，不能顯示審查完成。格式修正新 prompt 需新出站核准，不進無限自動修復迴圈。
- [ ] 提交 `feat: run traceable review batches with layered validation`。

## Task 11: T11 草稿、人工決定與匯出（M2 核心）

**Files:** 建立 `review/drafting.py`, `feedback/service.py`, `export/reports.py`, `tests/unit/test_drafting.py`, `tests/integration/test_feedback_export.py`。

**Interfaces:** `plan_changes(run: ReviewRun, findings: list[Finding]) -> list[OutboundDraft]`；`validate_change(change: SuggestedChange, finding: Finding, requirement: Requirement) -> ValidationReport`；`record_feedback(decision: HumanDecision, repo: Repository, idempotency_key: str) -> Feedback`；`export_review(report: ReviewReport, mode: str, output_dir: Path) -> ExportPaths`。

- [ ] 測草稿偷改30日成3日、主體交換、例外刪除、未核准責任／金額、unknown token 均不可直接採用；已核准底線允許有依據地修改並顯示差異。待填值明示「待填」，不是猜數值。測舊 run 回饋拒絕、重複點擊不重複寫、單案例外不更動規則、明文匯出需人工確認且路徑不覆寫原合約。
- [ ] 核心斷言：`assert not validate_change(unsupported_three_day_change, finding, requirement).structure.ok`；`assert report.run_id == decision.run_id`；遮罩匯出 `assert original_name not in exported_markdown`。ValidationReport 的 structure／source 為 GateReport，substance 為人工狀態與理由；數值／ID／token 可程式檢查，不等於語意已驗證。
- [ ] `uv run pytest tests/unit/test_drafting.py tests/integration/test_feedback_export.py -q`，確認 RED。
- [ ] 草稿亦經 T8–T9；本機數字／主體／定義詞保護加人工語意複核。Markdown 使用安全文字轉義，不嵌入模型提供的 HTML、圖片或可自動載入網址。JSON 帶版本、全部覆蓋／未知／失敗與人工決定；masked 模式再檢查整個報告，避免理由或回饋漏遮。保留採用文字歷程，案例只存候選。
- [ ] 同命令 PASS；plain 匯出0600並登記 artifact 生命週期，還原失敗只允許遮罩稿。全項採用仍不得產「整份合規」結論。
- [ ] 提交 `feat: draft review changes and preserve human decisions`。

## Task 12: T12 本機網頁與可恢復操作流程

**Files:** 建立 `web/{app,security,routes}.py`, `web/templates/{base,cases,scope,documents,masking,egress,review,rules,settings}.html`, `web/static/{app.js,app.css}`, `cli.py`, `tests/integration/test_web_security.py`, `tests/e2e/test_review_journey.py`。

**Interfaces:** `create_app(policy: RuntimePolicy, repo: Repository) -> FastAPI`；CLI `procurement-review serve --mode synthetic --data-dir PATH`。固定單一 process／worker，port 預設8765，所有操作呼叫既有服務，route 不重寫業務規則。

- [ ] 寫 localhost 安全測試：無 session、錯 Host／Origin、缺CSRF、跨案 artifact、路徑穿越拒絕；`test_model_html_and_external_images_are_inert` 驗惡意字串以文字顯示且 browser request 清單只有 loopback。E2E：建混合案件→匯入／確認→補遮→預覽核准→mock審查→草稿核准→人工決定→下載。
- [ ] 核心斷言：`assert response.status_code == 403`（錯Origin／缺CSRF）；`assert external_browser_requests == []`；`expect(page.get_by_text('待確認', exact=True).first).to_be_visible()`。另外測規則頁原文對照、人工送審／核准／撤銷會影響案件的適用規則與核准狀態。
- [ ] `uv run pytest tests/integration/test_web_security.py tests/e2e/test_review_journey.py -q`，確認 RED；缺瀏覽器須先完成工具安裝，不把環境失敗當功能 RED。
- [ ] 實作 local session bootstrap：啟動時產一次性 token，交本機瀏覽器 URL fragment，前端交換 HttpOnly／SameSite=Strict cookie 後清 fragment；token 不印日誌、不放 query、使用後失效。loopback 精確 Host／Origin 白名單、CSRF、防 XSS、CSP 禁外部資源；停用自帶外部CDN文件頁。UI 繁中，原文／證據／草稿並列，注音 composition 不觸發送出，缺件／待確認／stale 可見，未存變更有提醒。
- [ ] 規則頁提供來源／要求原文並列、適用性與底線編輯、送審及版本核准／撤銷；設定頁提供真實模式各核准項目、保留期限與供應商設定。操作者取自已驗證的本機會話，禁止由請求任意填 approved_by；所有實質修改建立新版本，不直接改JSON檔。
- [ ] 模型／解析工作放單一背景 executor，進度持久化、前端 polling；重啟將 running 標 interrupted，透過新 run 恢復。禁止重複按鈕只是 UX，服務端仍做 T3／T9 防重。
- [ ] 同命令 PASS；逐頁手動驗原文定位、可鍵盤操作、重新整理不丟已存紀錄、出站改動需重新核准及顯示未支援類別。保存合成畫面 QA，不保存真實畫面到 repo。
- [ ] 提交 `feat: add local review workspace and approval flow`。

## Task 13: T13 接入一個核准雲端供應商

**Files:** 建立 `providers/cloud.py`, `tests/integration/test_cloud_adapter.py`, `tests/live/test_approved_provider.py`, `docs/provider-onboarding.md`；修改 `runtime/config.py`, `web/templates/settings.html`。

**Interfaces:** `CloudAdapter(config: ProviderConfig)` 實作 T9 encode/decode；使用T1的 `ProviderConfig`。產品設定僅啟用一個 provider；供應商格式以選定時官方文件建立，不假設所有 API 相容 OpenAI。

- [ ] 用選定供應商去識別回應 fixtures 測 schema、tool-call 拒絕、429、5xx、timeout、拒答、截斷、usage 缺失；`test_cloud_adapter_uses_approved_exact_body` 捕捉 bytes。尚未選定時可完成 Protocol 契約測試，這個任務保持未完成，不虛構 adapter 已接通。
- [ ] 核心斷言：`assert captured_body == prepared.body`；`assert reply.usage is None`（未提供用量時）；`with pytest.raises(DomainError): adapter.decode(tool_call_response)`。錯誤不得帶原始response進一般日誌。
- [ ] `uv run pytest tests/integration/test_cloud_adapter.py -q`，確認 RED。
- [ ] 查核供應商訓練／留存／地區／次處理者／刪除條款，將使用者實際核准資訊存本機 ProviderConfig。依T9次序組裝、遮罩、encode、最終掃描及核准，不利用 SDK 自動改 prompt 或 tool schema。設定 request／response 大小、timeout 及預算上限；成本資料不明時顯示未知，不能當0。
- [ ] 同命令 PASS；經使用者於產品確認後，以合成 payload 跑 `uv run pytest tests/live/test_approved_provider.py -m live -q`。live 默認不執行，保存 request_id／模型／usage／核准 hash 及結果；未通過前不處理真實案件。
- [ ] 提交 `feat: connect the approved cloud provider through egress controls`。provider 未選或核准未完成時，繼續 T14、T15 的離線部分並清楚標此關卡未完成。

## Task 14: T14 備份還原、保存期限與刪除

**Files:** 建立 `runtime/lifecycle.py`, `tests/integration/test_lifecycle.py`, `docs/operations.md`；修改 `cli.py`。

**Interfaces:** `create_backup(repo: Repository, target: Path, recovery_key_ref: str) -> Path`；`restore_backup(backup: Path, target: Path, secrets: SecretStore) -> GateReport`；`plan_purge(review_id: str, repo: Repository, as_of: date) -> PurgePlan`；`execute_purge(plan: PurgePlan, confirmation_hash: str) -> GateReport`；CLI `backup`, `restore`, `purge --dry-run`。

- [ ] 測恢復到空目錄能讀原版本、來源及核准而不自動重送；錯 recovery key 拒絕；刪除清單包括原檔／轉換物／映射／輸出／cache／備份到期政策。`test_purge_cannot_delete_last_original_without_confirmation`、`test_missing_key_stops_without_reinitializing`。
- [ ] 核心斷言：`assert restored_repo.get_review(review.id) == review`；`assert captured_requests == []`（還原不送出）；`with pytest.raises(DomainError): execute_purge(plan, 'wrong-hash')`。
- [ ] `uv run pytest tests/integration/test_lifecycle.py -q`，確認 RED。
- [ ] 一致性 snapshot 暫停寫入或用 SQLite backup API，manifest 納 artifact hash與schema版本；備份加密，金鑰另外備援並在測試新機情境恢復。purge 預覽綁hash，受控刪除記 tombstone；不能宣稱SSD安全抹除或即時抹除未到期備份。外部匯出僅列已追蹤路徑與人工處理責任，不任意掃使用者硬碟。
- [ ] 還原設計須處理 artifact 資料金鑰：在加密備份內以獨立 recovery key 包裝資料金鑰，恢復時驗完整性後匯入新機 Keychain；recovery key 另行保存，不與備份明文放一起。只備份密文卻遺失原機金鑰不算恢復成功。
- [ ] 同命令 PASS，真實模式 gate 要求備份恢復演練與保存期限確認紀錄；synthetic fixture 不可偽造這些核准。
- [ ] 提交 `feat: manage encrypted backups and data lifecycle`。

## Task 15: T15 四類評測與發布判定（M3）

**Files:** 建立 `evaluation/{metrics,runner}.py`, `evaluations/{synthetic-manifest,acceptance-policy.example}.json`, `tests/unit/test_metrics.py`, `tests/integration/test_release_gates.py`, `docs/acceptance.md`；修改 `cli.py`。

**Interfaces:** `evaluate(expected: list[Finding], actual: list[Finding], artifacts: dict) -> EvaluationReport`；`check_release(report: EvaluationReport, policy: dict) -> GateReport`；CLI `evaluate --manifest PATH --output PATH`。manifest 標 family_id、development／holdout、synthetic／real、規則與模型版本；真實 manifest／答案位於受控庫。

- [ ] 用人工可算小樣本測 TP／FP／FN、各分類及四包分母、重疊標籤去重、零分母為 N/A。測全棄答、高風險誤判符合、不存在引用、漏遮、錯換／跨案、未授權出站、無據改數字均不能被平均分掩蓋。`test_all_abstentions_cannot_pass_release`；未設定人工接受率／工時門檻顯示未核准，不能默認PASS。
- [ ] 核心斷言：`assert not check_release(all_abstention_report, approved_policy).ok`；`assert not check_release(one_high_risk_false_compliant, approved_policy).ok`。對齊答案使用案件／Requirement版本及必要clause IDs，不用模型生成finding_id或列表順序配對。
- [ ] `uv run pytest tests/unit/test_metrics.py tests/integration/test_release_gates.py -q`，確認 RED。
- [ ] 實作規格 §11 指標：擷取、遮罩各類precision／recall、roundtrip、覆蓋、結果混淆、缺漏、引用存在與人工支持、草稿採用／重寫、待確認與人工時間／成本。已知高敏殘留／錯換／捏造／高風險判符合／未授權出站均0才通過；已處理分母必完整。非零品質／效率門檻與代表樣本最低量經M0基線另核准，不用合成模型結果充當真實品質。
- [ ] 同命令 PASS；每包含完整／缺件／衝突／例外及注入邊界樣本，按家族隔離。人工在本機標註與評測真實保留集；未知供應商、未核准規則、無真實代表樣本時，只產離線工程報告，不簽M3。每次模型／規則等升版重新比對並可回退。
- [ ] 提交 `test: evaluate each procurement pack and enforce release gates`。

## Task 16: T16 整合驗收與交接

**Files:** 建立 `README.md`, `tests/integration/test_end_to_end.py`；完成 `docs/operations.md`, `docs/acceptance.md`, `docs/rule-authoring.md`；修改 `cli.py` 提供 `doctor`。

**Interfaces:** CLI `procurement-review doctor --mode synthetic --data-dir PATH` 回傳工具／依賴／資料根／模型權重／核准關卡摘要，不輸出秘密；測試腳本以既有服務跑全流程，不另建第二套 pipeline。

- [ ] 寫 `test_end_to_end.py`：四類與混合案件各經建立、輸入確認、規則、遮罩、出站核准、審查、草稿、複核、匯出；插入一次缺附件、一次輸入更新與一次程序中斷，驗狀態及版本不混用。
- [ ] 核心斷言：`assert matrix.unprocessed_ids == []`；`assert matrix.unresolved_ids`（刻意缺件案）；`assert report.run_id != stale_run.id`；`assert export_paths.markdown.exists() and export_paths.json.exists()`。
- [ ] `uv run pytest tests/integration/test_end_to_end.py -q`，確認整合缺口 RED。
- [ ] 補齊 CLI／依賴接線，撰寫啟動、規則核准／停用、補遮、復原、未完成報告及真實啟用步驟。依賴清單、鎖檔、授權與已知限制附交接文件；有漏洞或相容性問題先判影響，不無聲忽略。
- [ ] 最終執行 `uv run pytest tests/unit tests/integration tests/e2e -q`、`uv lock --check`、`uv run ruff check src tests`、`uv run procurement-review doctor --mode synthetic --data-dir /private/tmp/procurement-review-acceptance`。預期測試全部 PASS、各命令退出碼0，寫入驗收紀錄；失敗不得稱完成。
- [ ] 完成合成端到端後，分別核對 M0/M1/M2/M3、T13及T14真實門檻，列「工程完成／待院內核准／待真實評測」；真實證據不足時維持試作標示。用五步人工驗收：建混合案→確認缺附件與文字→補遮並核對出站→查看引用與修改→更新輸入驗舊核准失效。
- [ ] 提交 `docs: deliver verified local review workflow and operations guide`；交接提供測試證據、限制及未完成關卡，不自動發佈或推送。

## 規格覆蓋自查

| 設計章節 | 實作任務 |
|---|---|
| §1 已確認需求／待定真實設定 | T1、T2、T12、T13、T16 |
| §2 目的／非目標／效益 | T7、T10、T15、T16 |
| §3 適用性與來源治理 | T3–T5 |
| §4 四包／雙路覆蓋／跨文件 | T4、T5、T7、T10、T15 |
| §5 格式／位置／長文 | T6、T7 |
| §6 流程與人工關卡 | T3、T9–T12 |
| §7 遮罩／出站／失敗 | T2、T8–T10、T13 |
| §8 結果／三層驗證／草稿 | T1、T10–T12 |
| §9 版本／失效／回饋 | T1、T3、T4、T9、T11 |
| §10 安全／保存／備份 | T2、T9、T12–T14 |
| §11 分期／評測／發布 | T5、T15、T16 |
| §12 低維運／實作裁量 | 檔案結構、T1、T12、T16 |
| §13 查核來源與限制 | T5、T13；沿用設計的查核紀錄，不宣稱本計畫已建正式法規庫 |

規劃自查：任務介面與型別以共用表為準；五項 Review Focus 均指定測試；每項有 RED／實作／GREEN／提交步驟。所有測試及命令目前是待執行驗收要求，並非已測試通過。此計畫自我審查，不另派代理審查。

## 技術選型參考與執行交接

2026-10-15 查閱官方文件：[FastAPI templates](https://fastapi.tiangolo.com/advanced/templates/)、[Pydantic strict mode](https://pydantic.dev/docs/validation/latest/concepts/strict_mode/)、[HTTPX transports](https://www.python-httpx.org/advanced/transports/)、[cryptography authenticated encryption](https://cryptography.io/en/latest/hazmat/primitives/aead/)。文件僅支持功能方向；執行時鎖定穩定版及相容組合，不能採文件開發版號作依賴版本。

使用者核准的是v0.2設計與撰寫計畫；實作方式待選。Native：同一代理逐任務完成，最後獨立審查；Subagent-driven：每任務由新代理實作及審查，再做整體審查。選定後沿用，不反覆詢問。
