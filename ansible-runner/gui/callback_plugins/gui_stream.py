"""Stdout callback used only by the GUI (see gui/app.py) so a run's progress
can be tailed live in the browser instead of waiting for the whole playbook
to finish.

Writes two things, paths given via env vars set by app.py:
- GUI_LOG_PATH:    a human-readable line per task/result, appended as it happens.
- GUI_RESULT_PATH: a single JSON file (stats + per-host events) written once
                    at the end, for the structured per-package history table.
"""
import json
import os

from ansible.plugins.callback import CallbackBase

DOCUMENTATION = """
    name: gui_stream
    type: stdout
    short_description: Streams progress to a log file for the web GUI
"""


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "gui_stream"

    def __init__(self):
        super().__init__()
        self.log_path = os.environ.get("GUI_LOG_PATH")
        self.result_path = os.environ.get("GUI_RESULT_PATH")
        self.host_events: dict[str, list] = {}

    def _log(self, line: str):
        if not self.log_path:
            return
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError:
            pass

    @staticmethod
    def _item_label(result):
        r = result._result
        label = r.get("_ansible_item_label")
        if isinstance(label, str) and label:
            return label
        item = r.get("item")
        if item is None:
            return None
        if isinstance(item, dict):
            return item.get("label") or item.get("name") or str(item)
        return str(item)

    def _record(self, result, *, failed=False, skipped=False, unreachable=False):
        # Looped tasks fire this once per item via the v2_runner_item_on_*
        # hooks, then ansible-core fires v2_runner_on_ok/failed once more for
        # the task as a whole with an aggregated "results" list and no item -
        # skip that aggregate call so per-package rows aren't drowned out by
        # one generic entry.
        if "results" in result._result:
            return

        host = result._host.get_name()
        task_name = result._task.get_name()
        changed = bool(result._result.get("changed"))
        item = self._item_label(result)
        label = task_name + (f" ({item})" if item else "")

        if unreachable:
            status = "unreachable"
        elif failed:
            status = "failed"
        elif changed:
            status = "changed"
        elif skipped:
            status = "skipped"
        else:
            status = "ok"

        self._log(f"[{host}] {status}: {label}")
        self.host_events.setdefault(host, []).append({
            "task": task_name, "item": item,
            "changed": changed, "failed": bool(failed),
            "unreachable": bool(unreachable), "skipped": bool(skipped),
        })

    def v2_playbook_on_task_start(self, task, is_conditional):
        self._log(f">>> {task.get_name()}")

    def v2_runner_on_ok(self, result):
        self._record(result)

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self._record(result, failed=True)

    def v2_runner_on_skipped(self, result):
        self._record(result, skipped=True)

    def v2_runner_on_unreachable(self, result):
        self._record(result, unreachable=True)

    def v2_runner_item_on_ok(self, result):
        self._record(result)

    def v2_runner_item_on_failed(self, result):
        self._record(result, failed=True)

    def v2_runner_item_on_skipped(self, result):
        self._record(result, skipped=True)

    def v2_playbook_on_stats(self, stats):
        summary = {}
        for h in sorted(stats.processed.keys()):
            s = stats.summarize(h)
            summary[h] = s
            self._log(
                f"RECAP [{h}]: ok={s['ok']} changed={s['changed']} "
                f"unreachable={s['unreachable']} failed={s['failures']} skipped={s['skipped']}"
            )
        if self.result_path:
            try:
                with open(self.result_path, "w", encoding="utf-8") as f:
                    json.dump({"stats": summary, "host_events": self.host_events}, f)
            except OSError:
                pass
        self._log("=== DONE ===")
