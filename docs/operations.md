# 資訊採購合約資安審查助手 — 運維與災難復原手冊 (Operations & Disaster Recovery Guide)

本手冊規範中央研究院資訊採購合約資安審查助手系統之加密備份、災難復原、資料留存期限（Retention Policy）與受控清除（Purge）作業流程與安全規範。

---

## 1. 架構安全與金鑰管理原則

### 1.1 階層式金鑰架構
- **Artifact 資料金鑰 (Data Key)**:
  - 每個部署實例具備一組 256 位元 (32 bytes) 主資料金鑰，於首次初始化時隨機生成並安全儲存於本機作業系統安全金鑰庫（如 macOS Keychain、Windows Credential Manager 或 Linux Secret Service）。
  - 所有合約原始檔、結構快照、遮罩映射表與暫存回覆，皆以 AES-256-GCM 獨立隨機 Nonce 加密落盤於 Vault。
- **災難復原金鑰 (Recovery Key)**:
  - 於產製加密備份時由管理員提供或指定，透過 HKDF-SHA256 演算法衍生 256 位元金鑰。
  - 獨立包裝（Wrap）Artifact 主資料金鑰，與備份封包主體分離存放。
  - **嚴格禁則**：Recovery Key 絕不可與備份檔案存放在同一實體或邏輯儲存媒體中；若遺失 Recovery Key，備份檔案將無法解密還原。

### 1.2 零網路傳輸還原保證 (Zero Transmission Guarantee)
- 備份還原（Restore）為純粹的本機檔案系統與 SQLite 資料庫重構作業。
- 還原管線中**嚴格禁止**觸發任何外部 LLM 供應商、Webhook 或日誌上傳等外部傳輸動作。
- 測試環境以 `assert captured_requests == []` 強制落實驗證。

---

## 2. 備份程序 (Backup Procedures)

### 2.1 備份機制與特性
- **SQLite 交易一致性**：透過 SQLite `backup` API 產製唯讀快照，保證 WAL 模式下無任何未提交或毀損交易。
- **完整性清單 (Manifest)**：包含資料庫與每項 Vault 加密 Artifact 的 SHA-256 雜湊值與 Schema 遷移版本。
- **AES-256-GCM 封裝**：整體備份以 Recovery Key 加密封裝，具備端對端防篡改與機密性保護。

### 2.2 CLI 備份操作步驟
```bash
uv run python -m procurement_review.cli backup \
  --data-dir /path/to/data \
  --target /path/to/backup_bundle.bundle \
  --recovery-key "YOUR_HIGH_ENTROPY_RECOVERY_KEY"
```

參數說明：
- `--data-dir`: 現有資料目錄（內含 `procurement_review.db` 與 `vault/`）。
- `--target`: 產製之備份封包目的地路徑。
- `--recovery-key`: 復原專用高強度金鑰或密語。

---

## 3. 災難復原程序 (Disaster Recovery & Restore)

### 3.1 復原檢查點與防禦機制
1. **Recovery Key 完整性校驗**：使用 Recovery Key 解密時，AES-256-GCM 認證標籤（Auth Tag）若不符，立即拋出 `RECOVERY_KEY_INVALID` 並中止還原。
2. **防靜默重置 (No-Silent-Reinit)**：若 Recovery Key 遺失或未提供，系統立即中斷，絕不嘗試以空白庫覆寫或重新初始化目標目錄。
3. **Artifact 雜湊比對**：解壓縮還原後逐一比對 SHA-256 雜湊，任一檔案不符即拒絕放行。
4. **金鑰匯入新機**：成功驗證後，自動將解開的主資料金鑰安全匯入目標機器之 OS Keychain。

### 3.2 CLI 還原操作步驟
```bash
uv run python -m procurement_review.cli restore \
  --backup /path/to/backup_bundle.bundle \
  --target /path/to/new_data_dir \
  --recovery-key "YOUR_HIGH_ENTROPY_RECOVERY_KEY"
```

---

## 4. 資料保存期限與受控清除 (Retention & Controlled Purge)

### 4.1 保存政策（Retention Policy）
- 機敏合約產物與中間記錄之預設保存期限為 **30 天**（可依合約或機敏等級設定）。
- 基準日期（`as_of`）超過 `created_at + retention_days` 即屬過期（Expired）。
- 未屆滿保存期限之案件，**嚴格禁止**未經人工核准逕行刪除合約最後原檔；必須提供 `--approved-by` 審查紀錄。

### 4.2 盤點範圍與邊界聲明
受控清除計畫（`PurgePlan`）全面盤點以下標的：
1. **原始文件 (Original Documents)**：儲存於 Vault 之原始合約檔案。
2. **轉換產物 (Converted Snapshots)**：結構快照、條款分段與萃取文字。
3. **遮罩映射 (Masking Mappings)**：個資與機敏 Token 對照表。
4. **快取與傳輸 (Cache & Replies)**：模型回傳暫存與情境 Bundle。
5. **外部匯出追蹤 (Tracked Exports)**：系統記錄之匯出檔案路徑。
   > **注意**：系統僅列出已追蹤之匯出路徑與人工處理責任，絕不擅自全磁碟掃描使用者之個人目錄或未授權路徑。
6. **備份到期政策 (Backup Retention Policy)**：
   > **注意**：系統依政策標記過期備份退役，未到期備份持續保護保留。系統**絕不宣稱**能對底層 SSD/NVMe 進行即時硬體安全抹除（Secure Erase）。

### 4.3 雙階段確認機制 (Confirmation-Bound Purge)
為防範誤刪，清除作業嚴格實施二階段確認：
1. **第一階段：乾跑預覽 (`--dry-run`)**：
   產製 `PurgePlan`，輸出欲清除標的清單及專屬之 64 位元 SHA-256 `confirmation_hash`。
   ```bash
   uv run python -m procurement_review.cli purge \
     --case-id "11111111-1111-4111-8111-111111111111" \
     --data-dir /path/to/data \
     --dry-run
   ```
2. **第二階段：綁定 Hash 執行清除**：
   確認盤點清單無誤後，將輸出的 Hash 帶入執行：
   ```bash
   uv run python -m procurement_review.cli purge \
     --case-id "11111111-1111-4111-8111-111111111111" \
     --data-dir /path/to/data \
     --confirmation-hash "b8c34f...64char_hash..."
   ```
   若 Hash 有任何單一字元不符，系統拒絕刪除任何檔案。

### 4.4 墓碑紀錄 (Tombstone Record)
- 實體 Vault 檔案刪除後，資料庫會在 `reviews` 表將案件狀態更新為 `purged`。
- 同時於 `purge_tombstones` 資料表寫入不可篡改的清除審計紀錄（包含清除時間、確認 Hash、清除標的數量與核准者）。

---

## 5. 真實模式安全檢核門 (Disaster Recovery Gate)

- **合成模式 (Synthetic)**：供本機開發與自動化測試使用，無條件通過。
- **真實模式 (Production / Real)**：
  - 強制檢核災難復原演練記錄參照（`rehearsal_record_ref`）。
  - 嚴格拒絕以全零 UUID 或全零 SHA-256 偽造演練紀錄。
  - 強制檢核資料保存政策核准參照（`retention_approval_ref`）。

---

## 6. 系統健康檢查與環境診斷 (Doctor CLI)

維運人員在服務上線前、重大升級後或定期稽核時，應執行 `doctor` 命令檢查全系統各項環境參數與安全狀態：

```bash
uv run procurement-review doctor --mode synthetic --data-dir /path/to/data
```

### 診斷檢查項目清單：
1. **Python 執行環境**：驗證直譯器版本符合 `>= 3.11`（推薦 `3.13`）。
2. **核心相依套件**：驗證 `fastapi`, `pydantic`, `uvicorn`, `cryptography`, `httpx`, `docx`, `pypdf`, `sqlite3` 等模組完整安裝且可正常引用。
3. **資料目錄權限**：驗證資料根目錄與 `vault/` 實體權限為 `0700`，且目前使用者具備完整讀寫與鎖定權限。
4. **SecretStore 金鑰庫**：驗證金鑰存取正常，確認主資料金鑰已配置。**安全保證：命令輸出嚴禁揭露金鑰原文或十六進位敏感密文**。
5. **SQLite 資料庫連線**：測試連線並確保 WAL（Write-Ahead Logging）交易模式已就緒。
6. **規則包與法規清單**：檢查 `software_maintenance`, `custom_software`, `cloud_service`, `mixed` 四類採購分類規則包之可用性。
7. **供應商組態**：檢查適配器設定（合成模式下確認 `MockProviderAdapter`，真實模式下確認 `CloudAdapter` 憑證參照）。
8. **生命週期與受控清除**：確認 30 天留存期限配置、墓碑審計資料表及災難復原檢核門狀態。

若所有檢核項目皆正常，命令將以退出碼 `0` 結束。

---

## 7. 疑似外洩與資安事件應變作業 (Incident Response for Suspected Leaks)

若發生或懷疑發生個資機敏外洩、未授權連線或金鑰外洩情事，請立即依下列 SOP 應變：

### 7.1 狀況 A：出站草稿疑似機敏殘留 (Masking Residual Leak)
- **觸發情境**：在出站預覽中發現內部人名、伺服器 IP、金鑰或內部網址未被遮罩。
- **處置步驟**：
  1. **禁止點擊核准**：承辦人切勿點擊核准出站按鈕，系統出站守護機制在未取得合法簽署核准前維持 100% 阻斷。
  2. **手動補標**：在遮罩標記介面選取該機敏文字，手動指派實體類別（如 `SECRET`, `ORG`, `PERSON`）並儲存補標會話。
  3. **自動失效確認**：人工補標後，系統會自動生成全新 `session_id`，先前若有產出之出站草稿將立即自動失效，防止誤送。
  4. **通報與修正**：通知維護人員更新 `RuleBasedDetector` 規則或正規表達式庫，納入新特徵。

### 7.2 狀況 B：異常網路出站阻擋與警報 (Unauthorized Egress Attempt)
- **觸發情境**：系統攔截到指向非白名單網址、非 HTTPS 協定或含有 URL Query 敏感參數之連線請求。
- **處置步驟**：
  1. 系統派發器將立即拋出 `INVALID_ENDPOINT` 或 `DELIVERY_UNKNOWN_LOCKED` 阻斷連線。
  2. 檢查 `egress_dispatches` 資料庫紀錄，確認嘗試連線之端點與 `request_id`。
  3. 隔離該審查 Run，執行撤銷程序：
     ```python
     repo.invalidate(case_id, reason="SECURITY_ANOMALOUS_ENDPOINT")
     ```
  4. 確認伺服器主機網路防火牆僅放行核准之特定 LLM 供應商 IP / 網域名稱。

### 7.3 狀況 C：主資料金鑰洩漏之緊急處置 (Master Key Compromise)
- **觸發情境**：工程師本機遭入侵、OS Keychain 被匯出或金鑰備份疑遭竊取。
- **處置步驟**：
  1. **立即停止 Web 服務**：中止所有 `procurement-review serve` 處理程序。
  2. **產製緊急密封備份**：使用全新的高強度復原金鑰產製加密備份：
     ```bash
     uv run procurement-review backup --data-dir ~/.procurement_review/data --target /secure_storage/emergency.bundle --recovery-key "NEW_EMERGENCY_KEY"
     ```
  3. **清空舊金鑰與輪換**：從 Keychain 移除舊 `artifact_master_key`，重新生成 256 位元隨機金鑰。
  4. **全量 Artifact 重密**：依第 8 節金鑰輪換程序解密並以新金鑰重新加密。

---

## 8. 金鑰輪換作業程序 (Key Rotation Procedures)

為符合資安稽核要求，系統主資料金鑰（Data Key）與備援復原金鑰（Recovery Key）應定期（建議每年或有人員異動時）輪換：

### 8.1 Data Key 輪換（Vault 加密重構）
1. 建立全新備份封包確認目前資料完整無虞。
2. 啟動離線輪換腳本，讀取舊金鑰解密每項 Vault Artifact，隨後以全新生成之 32 bytes AES-256-GCM 金鑰重新加密寫入。
3. 更新作業系統 Keychain 中儲存之 `artifact_master_key`。
4. 執行 `uv run pytest tests/integration/test_end_to_end.py` 驗證所有資料可正確解密還原。

### 8.2 Recovery Key 輪換（備援封包重新包裝）
1. 解密現有備份之 Envelope Header（取得目前被 Wrap 之主金鑰）。
2. 提供新的高強度密語，使用 HKDF-SHA256 衍生新 Recovery Key。
3. 重新封裝主資料金鑰並寫回備份清單。
4. 廢止舊 Recovery Key 實體保管卡，登錄新金鑰保管紀錄。

---

## 9. 定期備份與災難復原演練 SOP (Rehearsal Drills)

為符合發布檢核門（Release Gate）要求，真實模式部署前必須完成災難復原演練，並將演練紀錄登錄於系統：

1. **準備隔離演練目錄**：建立 `/tmp/rehearsal_drill_data`。
2. **產製演練備份**：
   ```bash
   uv run procurement-review backup \
     --data-dir /path/to/data \
     --target /tmp/rehearsal_drill.bundle \
     --recovery-key "DRILL_PASS_KEY_2026"
   ```
3. **執行跨目錄還原**：
   ```bash
   uv run procurement-review restore \
     --backup /tmp/rehearsal_drill.bundle \
     --target /tmp/rehearsal_drill_data \
     --recovery-key "DRILL_PASS_KEY_2026"
   ```
4. **校驗還原產物**：
   - 檢查 `procurement_review.db` 可由 SQLite 讀取且資料筆數一致。
   - 檢查 `vault/` 內每項加密檔案之 SHA-256 雜湊與備份 Manifest 100% 吻合。
   - 記錄演練時間、執行人員與產物雜湊，產製合法 `rehearsal_record_ref`。
5. **演練資料安全銷毀**：清除演練產物並確認無機敏資料留存於暫存區。

