"""Tests for the pre-delivery JT-value gate (cron/notification_gate.py).

Defence-in-depth: cron watchdog scripts occasionally emit successful
human-facing messages that explicitly self-identify as needing no action
from JT ("Needs JT: none", "Bob will reconcile silently", ...).  The gate
suppresses those pre-delivery while failing OPEN for anything that signals
a material condition (outage, data loss, credentials, security, spend,
approval, capacity, critical risk).

Covers:

* ``should_suppress_delivery``: pure matcher — suppress cases, fail-open
  material boundaries, ordinary actionable content, non-string input.
* ``scheduler.tick`` wiring: suppression applies only to successful,
  non-local delivery; failure alerts and ``[SILENT]`` handling unchanged;
  output still saved; execution records ``delivery_outcome='suppressed'``.
* ``jobs.mark_job_run``: persists ``last_delivery_outcome``.
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# should_suppress_delivery: pure matcher
# ---------------------------------------------------------------------------


class TestGateSuppresses:
    @pytest.mark.parametrize(
        "content",
        [
            "Overnight digest: 3 feeds reconciled.\nNeeds JT: none",
            "Overnight digest: 3 feeds reconciled.\nNeeds JT: none now",
            "Rotation check complete. Needs JT: only if you want the details.",
            "Queue drift detected; Bob is on it. No immediate action is needed from JT.",
            "Sweep complete — no action from JT is required.",
            "Minor log noise on host-2. Bob will reconcile silently.",
            "Minor log noise on host-2. Bob will review silently overnight.",
        ],
    )
    def test_explicit_non_actionable_suppresses(self, content):
        from cron.notification_gate import should_suppress_delivery

        reason = should_suppress_delivery(content)
        assert reason, f"expected suppression for: {content!r}"

    def test_case_insensitive(self):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery("Digest done. NEEDS JT: NONE")

    def test_markdown_bold_marker_suppresses(self):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery("Digest done.\n**Needs JT:** none")


class TestGateFailsOpen:
    @pytest.mark.parametrize(
        "material",
        [
            "Primary DB is unreachable since 03:00.",
            "Gateway outage ongoing on host-2.",
            "host-4 is down.",
            "Possible data loss on volume-3.",
            "Nightly backups failed twice.",
            "Telegram credentials expired; token rotation pending.",
            "Auth failure spike on the admin portal.",
            "Possible security breach on the edge node.",
            "Unexpected payment of $42 charged to the card.",
            "Spend exceeded the weekly budget.",
            "Deploy is blocked awaiting your approval.",
            "Disk full on /var — capacity exhausted.",
            "Critical risk: cert chain expires tomorrow.",
        ],
    )
    def test_material_boundary_beats_no_jt_marker(self, material):
        from cron.notification_gate import should_suppress_delivery

        content = f"Watchdog report.\n{material}\nNeeds JT: none now — Bob will reconcile silently."
        assert should_suppress_delivery(content) is None, (
            f"material signal must fail open: {material!r}"
        )

    @pytest.mark.parametrize(
        "content",
        [
            # Backup/data-loss variants — non-adjacent wording (review round 1)
            "Backup failure on volume-3; Bob will reconcile silently. Needs JT: none",
            "Nightly backup job failed on host-2. Needs JT: none",
            "Backups have been failing since Monday. Needs JT: none now.",
            "Backups are stale (last good: 6 days ago). Needs JT: none.",
            # Percentage-style disk pressure
            "Disk at 97% on /var. Needs JT: none — Bob will handle cleanup silently.",
            # Availability / auth variants
            "Service degraded, 5xx errors climbing. Needs JT: none for now.",
            "Login failures spiked overnight. Needs JT: none.",
            "Sign-in failures spiked overnight. Needs JT: none",
            # Data-loss / restore variants (review round 2)
            "Data was lost on the replica. Needs JT: none",
            "Restore test failed. Needs JT: none",
        ],
    )
    def test_material_variants_fail_open(self, content):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery(content) is None, (
            f"material variant must fail open: {content!r}"
        )

    @pytest.mark.parametrize(
        "content",
        [
            # Observations that JT hasn't acted are nudges TO JT, not
            # assertions that no action is needed — they must deliver.
            "Still no action from JT on the PR review request. Re-pinging tomorrow.",
            "Reminder: no response and no action from JT since Friday.",
        ],
    )
    def test_jt_inaction_observations_deliver(self, content):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery(content) is None, (
            f"JT-inaction nudge must deliver: {content!r}"
        )

    def test_ordinary_actionable_content_delivers(self):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery("3 PRs are waiting on your review today.") is None

    def test_plain_status_without_marker_delivers(self):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery("Sync finished: 14 items updated.") is None

    @pytest.mark.parametrize("content", ["", None, 42])
    def test_empty_or_non_string_never_suppresses(self, content):
        from cron.notification_gate import should_suppress_delivery

        assert should_suppress_delivery(content) is None


# ---------------------------------------------------------------------------
# scheduler.tick wiring
# ---------------------------------------------------------------------------

NO_JT_CONTENT = (
    "Overnight reconcile: 2 duplicate feed entries merged by Bob.\n"
    "Needs JT: none now — Bob will reconcile the remainder silently."
)


def _drive_tick(monkeypatch, tmp_path, job, run_result):
    """Run one tick() with every side-effecting dependency stubbed.

    Returns recorders: saved outputs, delivered contents, mark_job_run calls.
    """
    import cron.scheduler as sched

    monkeypatch.setattr(sched, "_hermes_home", tmp_path)
    monkeypatch.setattr(sched, "get_due_jobs", lambda: [job])
    monkeypatch.setattr(sched, "advance_next_run", lambda *_a, **_kw: None)
    monkeypatch.setattr(sched, "run_job", lambda _job: run_result)

    saved: list = []
    monkeypatch.setattr(
        sched, "save_job_output", lambda jid, out: saved.append((jid, out))
    )

    delivered: list = []

    def fake_deliver(_job, content, adapters=None, loop=None):
        delivered.append(content)
        return None

    monkeypatch.setattr(sched, "_deliver_result", fake_deliver)

    marked: list = []

    def fake_mark(job_id, success, error=None, delivery_error=None, **kwargs):
        marked.append(
            {
                "job_id": job_id,
                "success": success,
                "error": error,
                "delivery_error": delivery_error,
                **kwargs,
            }
        )

    monkeypatch.setattr(sched, "mark_job_run", fake_mark)

    n = sched.tick(verbose=False)
    assert n == 1
    return {"saved": saved, "delivered": delivered, "marked": marked}


class TestTickJtValueGate:
    def test_successful_telegram_no_jt_message_is_suppressed(
        self, tmp_path, monkeypatch
    ):
        """`Needs JT: none now` + Bob-owned action → saved, not delivered,
        recorded as success with delivery_outcome='suppressed'."""
        job = {"id": "j1", "name": "overnight-reconcile", "deliver": "telegram"}
        rec = _drive_tick(
            monkeypatch,
            tmp_path,
            job,
            (True, "full output doc", NO_JT_CONTENT, None),
        )

        assert rec["delivered"] == []
        # Full output still saved locally.
        assert rec["saved"] == [("j1", "full output doc")]
        assert rec["marked"][0]["success"] is True
        assert rec["marked"][0].get("delivery_outcome") == "suppressed"

    def test_material_signal_fails_open_and_delivers(self, tmp_path, monkeypatch):
        content = (
            "Primary DB unreachable since 03:00; Bob restarted the tunnel.\n"
            "Needs JT: none now."
        )
        job = {"id": "j2", "name": "db-watch", "deliver": "telegram"}
        rec = _drive_tick(
            monkeypatch, tmp_path, job, (True, "doc", content, None)
        )

        assert rec["delivered"] == [content]
        assert rec["marked"][0].get("delivery_outcome") in (None,)

    def test_ordinary_actionable_content_still_delivers(self, tmp_path, monkeypatch):
        content = "3 PRs need your review: #12, #14, #19."
        job = {"id": "j3", "name": "pr-nudge", "deliver": "telegram"}
        rec = _drive_tick(
            monkeypatch, tmp_path, job, (True, "doc", content, None)
        )

        assert rec["delivered"] == [content]
        assert rec["marked"][0].get("delivery_outcome") in (None,)

    def test_failure_alert_is_never_gated(self, tmp_path, monkeypatch):
        """Error delivery bypasses the gate even if the text contains a
        no-JT marker."""
        job = {"id": "j4", "name": "broken-watch", "deliver": "telegram"}
        rec = _drive_tick(
            monkeypatch,
            tmp_path,
            job,
            (False, "doc", "alert body", "script exited 3 (Needs JT: none)"),
        )

        assert len(rec["delivered"]) == 1
        assert "failed" in rec["delivered"][0]
        assert rec["marked"][0]["success"] is False
        assert rec["marked"][0].get("delivery_outcome") in (None,)

    def test_local_delivery_is_not_gated(self, tmp_path, monkeypatch):
        """deliver=local jobs never touch a human channel — the gate must
        not mark them suppressed."""
        job = {"id": "j5", "name": "local-log", "deliver": "local"}
        rec = _drive_tick(
            monkeypatch, tmp_path, job, (True, "doc", NO_JT_CONTENT, None)
        )

        # Unchanged behaviour: _deliver_result is still invoked (it no-ops
        # for local targets) and the run is not recorded as suppressed.
        assert rec["delivered"] == [NO_JT_CONTENT]
        assert rec["marked"][0].get("delivery_outcome") in (None,)

    def test_silent_marker_behaviour_unchanged(self, tmp_path, monkeypatch):
        job = {"id": "j6", "name": "quiet", "deliver": "telegram"}
        rec = _drive_tick(
            monkeypatch, tmp_path, job, (True, "doc", "[SILENT]", None)
        )

        assert rec["delivered"] == []
        # [SILENT] is not the JT gate — no suppressed outcome recorded.
        assert rec["marked"][0].get("delivery_outcome") in (None,)


# ---------------------------------------------------------------------------
# jobs.mark_job_run: delivery_outcome persistence
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_cron_dir(tmp_path, monkeypatch):
    """Isolate cron job storage into a temp dir so tests don't stomp on real jobs."""
    monkeypatch.setattr("cron.jobs.CRON_DIR", tmp_path / "cron")
    monkeypatch.setattr("cron.jobs.JOBS_FILE", tmp_path / "cron" / "jobs.json")
    monkeypatch.setattr("cron.jobs.OUTPUT_DIR", tmp_path / "cron" / "output")
    return tmp_path


class TestMarkJobRunDeliveryOutcome:
    def test_suppressed_outcome_persists(self, tmp_cron_dir):
        from cron.jobs import create_job, get_job, mark_job_run

        job = create_job(prompt="digest", schedule="every 1h", deliver="telegram")
        mark_job_run(job["id"], True, None, delivery_outcome="suppressed")

        assert get_job(job["id"])["last_delivery_outcome"] == "suppressed"

    def test_outcome_cleared_on_next_run(self, tmp_cron_dir):
        from cron.jobs import create_job, get_job, mark_job_run

        job = create_job(prompt="digest", schedule="every 1h", deliver="telegram")
        mark_job_run(job["id"], True, None, delivery_outcome="suppressed")
        mark_job_run(job["id"], True, None)

        assert get_job(job["id"])["last_delivery_outcome"] is None
