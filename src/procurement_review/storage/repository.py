import hashlib
import sqlite3
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from procurement_review.domain.enums import RunState
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    Feedback,
    Finding,
    Review,
    ReviewRun,
    VersionRef,
)
from procurement_review.storage.vault import ArtifactStore


def _hash_rule_refs(rule_refs: list[VersionRef]) -> str:
    """計算規則參照清單之確定性雜湊值。"""
    if not rule_refs:
        return "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    hasher = hashlib.sha256()
    for ref in sorted(rule_refs, key=lambda r: (r.id, r.version)):
        hasher.update(f"{ref.id}:{ref.version}:{ref.sha256}\n".encode())
    return hasher.hexdigest()


class Repository:
    """採購審查資料儲存庫。

    保證：
    - SQLite WAL 模式與 Foreign Keys 強制開啟。
    - 機敏 JSON 與內文由 ArtifactStore 加密落盤，SQLite 僅留不透明 ID、版本、雜湊與狀態。
    - 單寫入交易與 CAS (Compare-And-Swap) 樂觀鎖版本控制。
    - 不可變審查歷史與反向參照執行失效（run invalidation）。
    """

    def __init__(self, db: Path, artifacts: ArtifactStore) -> None:
        self.db = Path(db).resolve()
        self.artifacts = artifacts

        # 建立資料庫所在目錄
        self.db.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # 執行 migration
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db), timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection]:
        conn = self._get_conn()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        # Set journal mode to WAL outside of any transaction
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                """
            )
            cursor = conn.cursor()
            cursor.execute(
                "SELECT version FROM schema_migrations WHERE version = ?",
                ("001_initial.sql",),
            )
            if cursor.fetchone() is None:
                migration_file = Path(__file__).parent / "migrations" / "001_initial.sql"
                if not migration_file.exists():
                    raise DomainError(
                        "MIGRATION_NOT_FOUND",
                        f"Initial migration not found at {migration_file}",
                    )
                sql = migration_file.read_text(encoding="utf-8")
                conn.executescript(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    ("001_initial.sql", datetime.now(UTC).isoformat()),
                )

    def save_review(
        self,
        review: Review,
        expected_revision: int | None,
    ) -> Review:
        """使用 CAS (Compare-And-Swap) 儲存審查案件。

        - 若預期版本與資料庫現存版本不合，拋出 REVISION_CONFLICT。
        - 首次寫入時 expected_revision 須為 None 或 0。
        - 若文件內容雜湊 (original_file_hash) 變更，自動使該案所有 active runs 失效。
        """
        now_iso = datetime.now(UTC).isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT current_revision, original_file_hash FROM reviews WHERE case_id = ?",
                (review.case_id,),
            )
            row = cursor.fetchone()

            if row is None:
                # 首次建立
                if expected_revision is not None and expected_revision != 0:
                    conn.rollback()
                    raise DomainError(
                        "REVISION_CONFLICT",
                        f"Revision conflict: review does not exist, but expected {expected_revision}",
                    )
                new_revision = 1
                is_create = True
                hash_changed = False
            else:
                # 更新案件
                current_rev = row["current_revision"]
                if expected_revision != current_rev:
                    conn.rollback()
                    raise DomainError(
                        "REVISION_CONFLICT",
                        f"Revision conflict: expected revision {expected_revision}, current is {current_rev}",
                    )
                new_revision = current_rev + 1
                is_create = False
                hash_changed = row["original_file_hash"] != review.original_file_hash

            # 更新模型版本
            updated_review = review.model_copy(update={"revision": new_revision})

            # 敏感資料加密儲存至 ArtifactStore
            payload = updated_review.model_dump_json().encode("utf-8")
            artifact_id = self.artifacts.put(
                case_id=updated_review.case_id,
                kind="review_data",
                data=payload,
            )

            if is_create:
                cursor.execute(
                    """
                    INSERT INTO reviews (case_id, current_revision, state, original_file_hash, artifact_ref, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        updated_review.case_id,
                        new_revision,
                        updated_review.state.value,
                        updated_review.original_file_hash,
                        artifact_id,
                        now_iso,
                        now_iso,
                    ),
                )
            else:
                cursor.execute(
                    """
                    UPDATE reviews
                    SET current_revision = ?, state = ?, original_file_hash = ?, artifact_ref = ?, updated_at = ?
                    WHERE case_id = ?
                    """,
                    (
                        new_revision,
                        updated_review.state.value,
                        updated_review.original_file_hash,
                        artifact_id,
                        now_iso,
                        updated_review.case_id,
                    ),
                )

            # 寫入不可變版本紀錄
            cursor.execute(
                """
                INSERT INTO review_revisions (case_id, revision, state, original_file_hash, artifact_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    updated_review.case_id,
                    new_revision,
                    updated_review.state.value,
                    updated_review.original_file_hash,
                    artifact_id,
                    now_iso,
                ),
            )

            # 若合約內容雜湊變更，使舊 runs 自動失效
            if hash_changed:
                cursor.execute(
                    """
                    UPDATE runs
                    SET stale = 1, invalidation_reason = 'FILE_HASH_CHANGED', updated_at = ?
                    WHERE case_id = ? AND stale = 0
                    """,
                    (now_iso, updated_review.case_id),
                )

            conn.commit()
            return updated_review

    def get_review(self, id: str, revision: int | None = None) -> Review:
        """取得指定案件審查。若 revision 為 None 則回傳最新版本。"""
        with self._conn() as conn:
            cursor = conn.cursor()
            if revision is None:
                cursor.execute(
                    "SELECT artifact_ref FROM reviews WHERE case_id = ?",
                    (id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise DomainError("REVIEW_NOT_FOUND", f"Review '{id}' not found")
            else:
                cursor.execute(
                    "SELECT artifact_ref FROM review_revisions WHERE case_id = ? AND revision = ?",
                    (id, revision),
                )
                row = cursor.fetchone()
                if row is None:
                    raise DomainError(
                        "REVISION_NOT_FOUND",
                        f"Review '{id}' revision {revision} not found",
                    )

            artifact_ref = row["artifact_ref"]

        raw_data = self.artifacts.get(case_id=id, artifact_id=artifact_ref)
        return Review.model_validate_json(raw_data)

    def create_run(
        self,
        review_id: str,
        rule_refs: list[VersionRef],
        parent_run_id: str | None = None,
        **kwargs: Any,
    ) -> ReviewRun:
        """建立全新審查執行管線記錄。"""
        # 確認案件存在並取得最新快照
        review = self.get_review(review_id)
        run_id = str(uuid.uuid4())
        now_iso = datetime.now(UTC).isoformat()

        # 去除重複之 rule_refs (by id, version)
        seen_rules: set[tuple[str, str]] = set()
        deduped_rules: list[VersionRef] = []
        for r in rule_refs:
            key = (r.id, r.version)
            if key not in seen_rules:
                seen_rules.add(key)
                deduped_rules.append(r)

        input_version = VersionRef(
            id=review.case_id,
            version=str(review.revision),
            sha256=review.original_file_hash,
        )

        rules_hash = _hash_rule_refs(deduped_rules)
        rules_snapshot_id = str(
            uuid.uuid5(uuid.NAMESPACE_DNS, f"ruleset:{review_id}:{rules_hash}")
        )
        rule_set_snapshot = VersionRef(
            id=rules_snapshot_id,
            version="1.0",
            sha256=rules_hash,
        )

        run = ReviewRun(
            run_id=run_id,
            case_id=review_id,
            input_version=input_version,
            rule_set_snapshot=rule_set_snapshot,
            engine_version=kwargs.get("engine_version", "0.1.0"),
            ocr_version=kwargs.get("ocr_version", None),
            masking_version=kwargs.get("masking_version", "0.1.0"),
            prompt_version=kwargs.get("prompt_version", "0.1.0"),
            schema_version=kwargs.get("schema_version", "0.1.0"),
            provider_id=kwargs.get("provider_id", "internal"),
            model_id=kwargs.get("model_id", "default"),
            route=kwargs.get("route", "default"),
            state=RunState.PLANNED,
            parent_run_id=parent_run_id,
            stale=False,
            egress_approval_ref=None,
        )

        # 加密儲存至 ArtifactStore
        data = run.model_dump_json().encode("utf-8")
        artifact_id = self.artifacts.put(
            case_id=review_id,
            kind="run_data",
            data=data,
        )

        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO runs (run_id, case_id, parent_run_id, state, stale, artifact_ref, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.run_id,
                    run.case_id,
                    run.parent_run_id,
                    run.state.value,
                    0,
                    artifact_id,
                    now_iso,
                    now_iso,
                ),
            )
            for rule in deduped_rules:
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO run_rules (run_id, rule_id, rule_version, rule_sha256)
                    VALUES (?, ?, ?, ?)
                    """,
                    (run.run_id, rule.id, rule.version, rule.sha256),
                )
            conn.commit()

        return run

    def get_run(self, id: str) -> ReviewRun:
        """取得執行管線記錄，並疊加資料庫之即時狀態與 stale 標記。"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT case_id, state, stale, artifact_ref FROM runs WHERE run_id = ?",
                (id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise DomainError("RUN_NOT_FOUND", f"Run '{id}' not found")

            case_id = row["case_id"]
            db_state = RunState(row["state"])
            db_stale = bool(row["stale"])
            artifact_ref = row["artifact_ref"]

        raw_data = self.artifacts.get(case_id=case_id, artifact_id=artifact_ref)
        run = ReviewRun.model_validate_json(raw_data)
        # 疊加目前資料庫狀態與 stale 標記
        return run.model_copy(update={"state": db_state, "stale": db_stale})

    def save_run(self, run: ReviewRun) -> ReviewRun:
        """更新執行管線狀態與中繼屬性。"""
        now_iso = datetime.now(UTC).isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT case_id, stale FROM runs WHERE run_id = ?",
                (run.run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                conn.rollback()
                raise DomainError("RUN_NOT_FOUND", f"Run '{run.run_id}' not found")

            case_id = row["case_id"]
            db_stale = bool(row["stale"])
            effective_stale = db_stale or run.stale

            payload = (
                run.model_copy(update={"stale": effective_stale})
                .model_dump_json()
                .encode("utf-8")
            )
            artifact_id = self.artifacts.put(
                case_id=case_id,
                kind="run_data",
                data=payload,
            )

            cursor.execute(
                """
                UPDATE runs
                SET state = ?, stale = CASE WHEN stale = 1 THEN 1 ELSE ? END, artifact_ref = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    run.state.value,
                    1 if run.stale else 0,
                    artifact_id,
                    now_iso,
                    run.run_id,
                ),
            )
            conn.commit()
            return run.model_copy(update={"stale": effective_stale})

    def invalidate(self, review_id: str, reason: str) -> list[str]:
        """使特定案件之所有作用中執行管線 (stale=False) 失效，回傳被失效的 run ID 清單。"""
        now_iso = datetime.now(UTC).isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT run_id FROM runs WHERE case_id = ? AND stale = 0",
                (review_id,),
            )
            rows = cursor.fetchall()
            invalidated_ids = [row["run_id"] for row in rows]

            if invalidated_ids:
                cursor.execute(
                    """
                    UPDATE runs
                    SET stale = 1, invalidation_reason = ?, updated_at = ?
                    WHERE case_id = ? AND stale = 0
                    """,
                    (reason, now_iso, review_id),
                )
            conn.commit()
            return invalidated_ids

    def invalidate_runs_by_rule(self, rule_id: str, reason: str) -> list[str]:
        """依據規則 ID 反向查詢引用該規則之所有作用中執行管線，並標記為失效。"""
        now_iso = datetime.now(UTC).isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT DISTINCT r.run_id
                FROM runs r
                JOIN run_rules rr ON r.run_id = rr.run_id
                WHERE rr.rule_id = ? AND r.stale = 0
                """,
                (rule_id,),
            )
            rows = cursor.fetchall()
            invalidated_ids = [row["run_id"] for row in rows]

            if invalidated_ids:
                placeholders = ",".join("?" for _ in invalidated_ids)
                cursor.execute(
                    f"""
                    UPDATE runs
                    SET stale = 1, invalidation_reason = ?, updated_at = ?
                    WHERE run_id IN ({placeholders})
                    """,
                    [reason, now_iso, *invalidated_ids],
                )
            conn.commit()
            return invalidated_ids

    def save_finding(self, finding: Finding) -> None:
        """儲存審查發現至加密受控庫與索引庫。"""
        now_iso = datetime.now(UTC).isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT case_id FROM runs WHERE run_id = ?",
                (finding.run_id,),
            )
            row = cursor.fetchone()
            if row is None:
                conn.rollback()
                raise DomainError(
                    "RUN_NOT_FOUND",
                    f"Run '{finding.run_id}' not found for finding '{finding.finding_id}'",
                )
            case_id = row["case_id"]

            payload = finding.model_dump_json().encode("utf-8")
            artifact_id = self.artifacts.put(
                case_id=case_id,
                kind="finding_data",
                data=payload,
            )

            cursor.execute(
                """
                INSERT INTO findings (
                    finding_id, run_id, requirement_id, result, risk, human_status,
                    finding_artifact_id, artifact_ref, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(finding_id) DO UPDATE SET
                    run_id = excluded.run_id,
                    requirement_id = excluded.requirement_id,
                    result = excluded.result,
                    risk = excluded.risk,
                    human_status = excluded.human_status,
                    finding_artifact_id = excluded.finding_artifact_id,
                    artifact_ref = excluded.artifact_ref,
                    updated_at = excluded.updated_at
                """,
                (
                    finding.finding_id,
                    finding.run_id,
                    finding.requirement_id,
                    finding.result.value,
                    finding.risk.value,
                    finding.human_status,
                    artifact_id,
                    artifact_id,
                    now_iso,
                    now_iso,
                ),
            )
            conn.commit()

    def get_finding(self, finding_id: str) -> Finding:
        """取得單一審查發現。"""
        with self._conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT f.artifact_ref, r.case_id
                FROM findings f
                JOIN runs r ON f.run_id = r.run_id
                WHERE f.finding_id = ?
                """,
                (finding_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise DomainError(
                    "FINDING_NOT_FOUND",
                    f"Finding '{finding_id}' not found",
                )
            artifact_ref = row["artifact_ref"]
            case_id = row["case_id"]

        data = self.artifacts.get(case_id=case_id, artifact_id=artifact_ref)
        return Finding.model_validate_json(data)

    def append_feedback(self, value: Feedback, idempotency_key: str) -> Feedback:
        """冪等性附加人工審查回饋。

        若提供相同的 idempotency_key，則直接回傳既有回饋記錄，不產生重複記錄。
        """
        now_iso = datetime.now(UTC).isoformat()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE;")
            cursor = conn.cursor()

            # 檢查冪等鍵
            cursor.execute(
                """
                SELECT fb.artifact_ref, r.case_id
                FROM feedbacks fb
                JOIN runs r ON fb.run_id = r.run_id
                WHERE fb.idempotency_key = ?
                """,
                (idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                conn.commit()
                raw_bytes = self.artifacts.get(
                    case_id=existing["case_id"],
                    artifact_id=existing["artifact_ref"],
                )
                return Feedback.model_validate_json(raw_bytes)

            # 查詢對應 case_id
            cursor.execute(
                "SELECT case_id FROM runs WHERE run_id = ?",
                (value.run_id,),
            )
            run_row = cursor.fetchone()
            if run_row is None:
                conn.rollback()
                raise DomainError(
                    "RUN_NOT_FOUND",
                    f"Run '{value.run_id}' not found for feedback '{value.feedback_id}'",
                )
            case_id = run_row["case_id"]

            payload = value.model_dump_json().encode("utf-8")
            artifact_id = self.artifacts.put(
                case_id=case_id,
                kind="feedback_data",
                data=payload,
            )

            cursor.execute(
                """
                INSERT INTO feedbacks (feedback_id, finding_id, run_id, idempotency_key, artifact_ref, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    value.feedback_id,
                    value.finding_id,
                    value.run_id,
                    idempotency_key,
                    artifact_id,
                    now_iso,
                ),
            )
            conn.commit()
            return value
