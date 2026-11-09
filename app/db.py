from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _decode(row: sqlite3.Row, json_fields: tuple[str, ...] = ()) -> dict[str, Any]:
    result = dict(row)
    for field in json_fields:
        result[field] = json.loads(result[field]) if result.get(field) else []
    return result


class Database:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.init_schema()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def init_schema(self) -> None:
        schema = """
        CREATE TABLE IF NOT EXISTS assessments (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            client_name TEXT NOT NULL DEFAULT '',
            description TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL,
            profile TEXT NOT NULL,
            assessment_type TEXT NOT NULL DEFAULT 'external_unauthenticated',
            capabilities_json TEXT NOT NULL DEFAULT '[]',
            permissions_json TEXT NOT NULL DEFAULT '[]',
            credentials_available INTEGER NOT NULL DEFAULT 0,
            authorized INTEGER NOT NULL,
            authorization_note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            started_at TEXT,
            completed_at TEXT,
            target_count INTEGER NOT NULL,
            completed_units INTEGER NOT NULL DEFAULT 0,
            total_units INTEGER NOT NULL,
            found_count INTEGER NOT NULL DEFAULT 0,
            not_found_count INTEGER NOT NULL DEFAULT 0,
            na_count INTEGER NOT NULL DEFAULT 0,
            inconclusive_count INTEGER NOT NULL DEFAULT 0,
            applicable_count INTEGER NOT NULL DEFAULT 0,
            error_count INTEGER NOT NULL DEFAULT 0,
            current_phase TEXT NOT NULL DEFAULT 'Preflight',
            current_target TEXT,
            current_testcase TEXT,
            llm_enabled INTEGER NOT NULL DEFAULT 0,
            evidence_screenshots INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS targets (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            value TEXT NOT NULL,
            label TEXT NOT NULL,
            kind TEXT NOT NULL,
            host_count INTEGER NOT NULL,
            excluded INTEGER NOT NULL DEFAULT 0,
            UNIQUE(assessment_id, value)
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            event TEXT NOT NULL,
            phase TEXT NOT NULL,
            message TEXT NOT NULL,
            status TEXT,
            testcase_id TEXT,
            target_id TEXT,
            completed_units INTEGER NOT NULL DEFAULT 0,
            total_units INTEGER NOT NULL DEFAULT 0,
            payload_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS executions (
            id TEXT PRIMARY KEY,
            assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL,
            testcase_id TEXT NOT NULL,
            command_json TEXT NOT NULL,
            displayed_command TEXT NOT NULL,
            cwd TEXT NOT NULL,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            exit_code INTEGER,
            timed_out INTEGER NOT NULL DEFAULT 0,
            tool_version TEXT NOT NULL,
            stdout_path TEXT,
            stderr_path TEXT,
            stdout_sha256 TEXT,
            stderr_sha256 TEXT,
            combined_sha256 TEXT,
            execution_status TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
            target_id TEXT NOT NULL,
            target TEXT NOT NULL,
            target_label TEXT NOT NULL,
            testcase_id TEXT NOT NULL,
            testcase_name TEXT NOT NULL,
            status TEXT NOT NULL,
            applicability TEXT NOT NULL,
            conditions_tested_json TEXT NOT NULL,
            conditions_confirmed_json TEXT NOT NULL,
            conditions_not_found_json TEXT NOT NULL,
            inconclusive_conditions_json TEXT NOT NULL,
            severity TEXT NOT NULL,
            finding_ids_json TEXT NOT NULL,
            evidence_paths_json TEXT NOT NULL,
            poc_paths_json TEXT NOT NULL,
            tools_used_json TEXT NOT NULL,
            validation_state TEXT NOT NULL,
            failure_reason TEXT,
            evidence_id TEXT,
            command TEXT,
            output_preview TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(assessment_id, target_id, testcase_id)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id TEXT PRIMARY KEY,
            result_id INTEGER NOT NULL REFERENCES results(id) ON DELETE CASCADE,
            assessment_id TEXT NOT NULL,
            target_id TEXT NOT NULL,
            testcase_id TEXT NOT NULL,
            artifact_path TEXT NOT NULL,
            kind TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            provenance_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS llm_triage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            assessment_id TEXT NOT NULL,
            result_id INTEGER NOT NULL,
            model TEXT NOT NULL,
            prompt_version TEXT NOT NULL,
            response_json TEXT NOT NULL,
            validation_state TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_assessment ON events(assessment_id, id);
        CREATE INDEX IF NOT EXISTS idx_results_assessment ON results(assessment_id, target_id, testcase_id);
        """
        with self._lock, self.connect() as connection:
            connection.executescript(schema)
            columns = {row[1] for row in connection.execute("PRAGMA table_info(assessments)").fetchall()}
            migrations = {
                "client_name": "ALTER TABLE assessments ADD COLUMN client_name TEXT NOT NULL DEFAULT ''",
                "description": "ALTER TABLE assessments ADD COLUMN description TEXT NOT NULL DEFAULT ''",
                "assessment_type": "ALTER TABLE assessments ADD COLUMN assessment_type TEXT NOT NULL DEFAULT 'external_unauthenticated'",
                "capabilities_json": "ALTER TABLE assessments ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '[]'",
                "permissions_json": "ALTER TABLE assessments ADD COLUMN permissions_json TEXT NOT NULL DEFAULT '[]'",
                "credentials_available": "ALTER TABLE assessments ADD COLUMN credentials_available INTEGER NOT NULL DEFAULT 0",
                "applicable_count": "ALTER TABLE assessments ADD COLUMN applicable_count INTEGER NOT NULL DEFAULT 0",
            }
            for column, statement in migrations.items():
                if column not in columns:
                    connection.execute(statement)

    def create_assessment(self, assessment: dict[str, Any], targets: list[dict[str, Any]]) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO assessments
                (id,name,status,profile,assessment_type,capabilities_json,permissions_json,credentials_available,
                 client_name,description,
                 authorized,authorization_note,created_at,target_count,total_units,llm_enabled,evidence_screenshots)
                VALUES (:id,:name,:status,:profile,:assessment_type,:capabilities_json,:permissions_json,
                        :credentials_available,:client_name,:description,:authorized,:authorization_note,:created_at,:target_count,
                        :total_units,:llm_enabled,:evidence_screenshots)""",
                assessment,
            )
            connection.executemany(
                """INSERT INTO targets(id,assessment_id,value,label,kind,host_count,excluded)
                VALUES (:id,:assessment_id,:value,:label,:kind,:host_count,:excluded)""",
                targets,
            )

    def get_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self._lock, self.connect() as connection:
            row = connection.execute("SELECT * FROM assessments WHERE id=?", (assessment_id,)).fetchone()
            return _decode(row, ("capabilities_json", "permissions_json")) if row else None

    def list_assessments(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM assessments ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [_decode(row, ("capabilities_json", "permissions_json")) for row in rows]

    def get_targets(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM targets WHERE assessment_id=? ORDER BY id", (assessment_id,)
            ).fetchall()
            return [dict(row) for row in rows]

    def update_assessment(self, assessment_id: str, **fields: Any) -> None:
        if not fields:
            return
        allowed = {
            "status",
            "started_at",
            "completed_at",
            "completed_units",
            "found_count",
            "not_found_count",
            "na_count",
            "inconclusive_count",
            "applicable_count",
            "error_count",
            "current_phase",
            "current_target",
            "current_testcase",
        }
        invalid = set(fields) - allowed
        if invalid:
            raise ValueError(f"Unknown assessment fields: {sorted(invalid)}")
        assignments = ", ".join(f"{key}=?" for key in fields)
        values = list(fields.values()) + [assessment_id]
        with self._lock, self.connect() as connection:
            connection.execute(f"UPDATE assessments SET {assignments} WHERE id=?", values)

    def add_event(
        self,
        assessment_id: str,
        event: str,
        phase: str,
        message: str,
        *,
        status: str | None = None,
        testcase_id: str | None = None,
        target_id: str | None = None,
        completed_units: int = 0,
        total_units: int = 0,
        payload: dict[str, Any] | None = None,
    ) -> int:
        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO events
                (assessment_id,created_at,event,phase,message,status,testcase_id,target_id,
                 completed_units,total_units,payload_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    assessment_id,
                    now_iso(),
                    event,
                    phase,
                    message,
                    status,
                    testcase_id,
                    target_id,
                    completed_units,
                    total_units,
                    _json(payload or {}),
                ),
            )
            return int(cursor.lastrowid)

    def list_events(self, assessment_id: str, after_id: int = 0) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events WHERE assessment_id=? AND id>? ORDER BY id",
                (assessment_id, after_id),
            ).fetchall()
            return [_decode(row, ("payload_json",)) for row in rows]

    def add_execution(self, execution: dict[str, Any]) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO executions
                (id,assessment_id,target_id,testcase_id,command_json,displayed_command,cwd,started_at,
                 ended_at,exit_code,timed_out,tool_version,stdout_path,stderr_path,stdout_sha256,
                 stderr_sha256,combined_sha256,execution_status)
                VALUES (:id,:assessment_id,:target_id,:testcase_id,:command_json,:displayed_command,:cwd,
                        :started_at,:ended_at,:exit_code,:timed_out,:tool_version,:stdout_path,:stderr_path,
                        :stdout_sha256,:stderr_sha256,:combined_sha256,:execution_status)""",
                execution,
            )

    def list_executions(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM executions WHERE assessment_id=? ORDER BY started_at, id",
                (assessment_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def add_result(self, result: dict[str, Any]) -> int:
        fields = {
            key: _json(result[key]) if key.endswith("_json") else result.get(key)
            for key in (
                "assessment_id",
                "target_id",
                "target",
                "target_label",
                "testcase_id",
                "testcase_name",
                "status",
                "applicability",
                "conditions_tested_json",
                "conditions_confirmed_json",
                "conditions_not_found_json",
                "inconclusive_conditions_json",
                "severity",
                "finding_ids_json",
                "evidence_paths_json",
                "poc_paths_json",
                "tools_used_json",
                "validation_state",
                "failure_reason",
                "evidence_id",
                "command",
                "output_preview",
                "created_at",
            )
        }
        with self._lock, self.connect() as connection:
            cursor = connection.execute(
                """INSERT INTO results
                (assessment_id,target_id,target,target_label,testcase_id,testcase_name,status,applicability,
                 conditions_tested_json,conditions_confirmed_json,conditions_not_found_json,
                 inconclusive_conditions_json,severity,finding_ids_json,evidence_paths_json,poc_paths_json,
                 tools_used_json,validation_state,failure_reason,evidence_id,command,output_preview,created_at)
                VALUES (:assessment_id,:target_id,:target,:target_label,:testcase_id,:testcase_name,:status,
                        :applicability,:conditions_tested_json,:conditions_confirmed_json,
                        :conditions_not_found_json,:inconclusive_conditions_json,:severity,:finding_ids_json,
                        :evidence_paths_json,:poc_paths_json,:tools_used_json,:validation_state,
                        :failure_reason,:evidence_id,:command,:output_preview,:created_at)""",
                fields,
            )
            return int(cursor.lastrowid)

    def list_results(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM results WHERE assessment_id=? ORDER BY target_id, testcase_id",
                (assessment_id,),
            ).fetchall()
            fields = (
                "conditions_tested_json",
                "conditions_confirmed_json",
                "conditions_not_found_json",
                "inconclusive_conditions_json",
                "finding_ids_json",
                "evidence_paths_json",
                "poc_paths_json",
                "tools_used_json",
            )
            return [_decode(row, fields) for row in rows]

    def add_evidence(self, evidence: dict[str, Any]) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO evidence
                (id,result_id,assessment_id,target_id,testcase_id,artifact_path,kind,sha256,provenance_json)
                VALUES (:id,:result_id,:assessment_id,:target_id,:testcase_id,:artifact_path,:kind,:sha256,
                        :provenance_json)""",
                {**evidence, "provenance_json": _json(evidence["provenance"])},
            )

    def list_evidence(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE assessment_id=? ORDER BY id", (assessment_id,)
            ).fetchall()
            return [_decode(row, ("provenance_json",)) for row in rows]

    def add_llm_triage(self, entry: dict[str, Any]) -> None:
        with self._lock, self.connect() as connection:
            connection.execute(
                """INSERT INTO llm_triage
                (assessment_id,result_id,model,prompt_version,response_json,validation_state,created_at)
                VALUES (:assessment_id,:result_id,:model,:prompt_version,:response_json,:validation_state,
                        :created_at)""",
                entry,
            )

    def list_llm_triage(self, assessment_id: str) -> list[dict[str, Any]]:
        with self._lock, self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM llm_triage WHERE assessment_id=? ORDER BY id", (assessment_id,)
            ).fetchall()
            return [_decode(row, ("response_json",)) for row in rows]
