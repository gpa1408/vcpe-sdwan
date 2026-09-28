from __future__ import annotations

import json
import threading
from pathlib import Path

from .models import ForwarderState, NatDiscoveryTaskRecord, RenderPlan, RevisionInfo, utc_now


class ForwarderStore:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.data_dir = root / "var/lib/forwarder"
        self.revisions_dir = self.data_dir / "revisions"
        self.rendered_dir = self.data_dir / "rendered"
        self.discovery_dir = self.data_dir / "nat-discovery"
        self.state_file = self.data_dir / "state.json"
        self.current_revision_file = self.data_dir / "current-revision.json"
        self.command_journal_name = "journal.json"
        self._lock = threading.RLock()
        self._ensure_layout()
        self._state = self._load_or_initialize_state()

    def _ensure_layout(self) -> None:
        for path in [
            self.data_dir,
            self.revisions_dir,
            self.rendered_dir,
            self.discovery_dir,
            self.root / "etc/forwarder/dnsmasq",
            self.root / "etc/forwarder/hostapd",
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def _load_or_initialize_state(self) -> ForwarderState:
        if self.state_file.exists():
            return ForwarderState.model_validate_json(self.state_file.read_text(encoding="utf-8"))

        state = ForwarderState()
        self._write_state_files(state)
        self._write_json(self.revisions_dir / f"{state.current_revision}.json", state.model_dump(mode="json"))
        return state

    def state_copy(self) -> ForwarderState:
        with self._lock:
            return self._state.model_copy(deep=True)

    def current_revision(self) -> RevisionInfo:
        with self._lock:
            return RevisionInfo(
                revision=self._state.current_revision,
                status=self._state.current_status,
                applied_at=self._state.applied_at,
            )

    def commit(self, candidate: ForwarderState, status: str = "active") -> RevisionInfo:
        with self._lock:
            candidate.revision_counter = max(candidate.revision_counter, self._state.revision_counter) + 1
            candidate.current_revision = f"rev-{candidate.revision_counter:04d}"
            candidate.current_status = status
            candidate.applied_at = utc_now()
            self._state = candidate
            self._write_state_files(candidate)
            self._write_json(self.revisions_dir / f"{candidate.current_revision}.json", candidate.model_dump(mode="json"))
            return RevisionInfo(
                revision=candidate.current_revision,
                status=candidate.current_status,
                applied_at=candidate.applied_at,
            )

    def rollback(self, revision: str) -> ForwarderState:
        with self._lock:
            snapshot_path = self.revisions_dir / f"{revision}.json"
            if not snapshot_path.exists():
                raise FileNotFoundError(revision)
            snapshot = ForwarderState.model_validate_json(snapshot_path.read_text(encoding="utf-8"))
            snapshot.revision_counter = self._state.revision_counter
            snapshot.allocation_counter = max(snapshot.allocation_counter, self._state.allocation_counter)
            snapshot.current_revision = revision
            snapshot.current_status = "rolled_back"
            snapshot.applied_at = utc_now()
            self._state = snapshot
            self._write_state_files(snapshot)
            return snapshot.model_copy(deep=True)

    def mutate_state(self, mutator) -> ForwarderState:
        with self._lock:
            candidate = self._state.model_copy(deep=True)
            mutator(candidate)
            self._state = candidate
            self._write_state_files(candidate)
            return candidate.model_copy(deep=True)

    def save_render_plan(self, plan: RenderPlan, journal: dict | None = None) -> Path:
        with self._lock:
            for relative_path, content in plan.files.items():
                path = self.root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            plan_root = self.root / "var/lib/forwarder/rendered" / plan.revision
            plan_root.mkdir(parents=True, exist_ok=True)
            self._write_json(plan_root / "plan.json", plan.model_dump(mode="json"))
            script_lines = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
            for phase, commands in plan.phases.items():
                script_lines.append(f"# phase: {phase}")
                if commands:
                    script_lines.extend(commands)
                else:
                    script_lines.append(":")
                script_lines.append("")
            (plan_root / "plan.sh").write_text("\n".join(script_lines), encoding="utf-8")
            if journal is not None:
                self._write_json(plan_root / self.command_journal_name, journal)
            return plan_root

    def write_task_record(self, task: NatDiscoveryTaskRecord) -> None:
        self._write_json(self.discovery_dir / f"{task.task_id}.json", task.model_dump(mode="json"))

    def _write_state_files(self, state: ForwarderState) -> None:
        self._write_json(self.state_file, state.model_dump(mode="json"))
        self._write_json(
            self.current_revision_file,
            RevisionInfo(
                revision=state.current_revision,
                status=state.current_status,
                applied_at=state.applied_at,
            ).model_dump(mode="json"),
        )

    def _write_json(self, path: Path, payload: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
