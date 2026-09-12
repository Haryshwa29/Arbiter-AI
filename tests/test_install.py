"""Tests for the installer (ADR-002).

The point of these is that the *plan* is inspectable data, not side effects:
we can assert what an install would do without installing anything. The
dry-run guarantee ("what it prints is what it does") only holds if both walk
the same Plan, so that is what these tests pin down.
"""

from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch
from argparse import Namespace
from pathlib import Path

from arbiter.install import preflight, service
from arbiter.install.cli import build_install_plan, build_parser, write_config
from arbiter.install.plan import Action, Plan, layout_for


def _args(**over):
    base = dict(host="127.0.0.1", port=8787, backend="mock", model="m",
                events="", service=True, force=False, yes=True, dry_run=False,
                scope="user", prefix=None, purge=False,
                bundled_ollama_dir=None, bundled_models_dir=None)
    base.update(over)
    return Namespace(**base)


class LayoutTests(unittest.TestCase):
    def test_prefix_confines_everything_to_one_root(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            root = Path(td).resolve()
            for path in [lay.app_dir, lay.data_dir, lay.config_path,
                         lay.log_dir, lay.memory_db, lay.audit_db, lay.iam_db]:
                self.assertTrue(str(path).startswith(str(root)),
                                f"{path} escaped the prefix")

    def test_databases_live_in_the_data_dir_not_the_app_dir(self):
        # The app dir is replaced wholesale on upgrade/uninstall; anything
        # worth keeping must not live there.
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            for db in (lay.memory_db, lay.audit_db, lay.iam_db):
                self.assertEqual(db.parent, lay.data_dir)


class PlanTests(unittest.TestCase):
    def test_dry_run_executes_nothing(self):
        fired = []
        plan = Plan("t")
        plan.add("would do a thing", run=lambda: fired.append(1))
        import io

        plan.render(stream=io.StringIO())
        self.assertEqual(fired, [])

    def test_execute_runs_actions_in_order(self):
        order = []
        plan = Plan("t")
        plan.add("first", run=lambda: order.append("first"))
        plan.add("second", run=lambda: order.append("second"))
        import io

        plan.execute(stream=io.StringIO())
        self.assertEqual(order, ["first", "second"])

    def test_skip_if_prevents_execution(self):
        fired = []
        a = Action("x", run=lambda: fired.append(1), skip_if=lambda: True)
        plan = Plan("t", [a])
        import io

        plan.execute(stream=io.StringIO())
        self.assertEqual(fired, [])

    def test_render_and_execute_cover_the_same_steps(self):
        """The dry-run promise: same plan, same steps, only side effects differ."""
        import io

        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            plan, _ = build_install_plan(lay, _args(service=False), None)
            rendered = io.StringIO()
            plan.render(stream=rendered)
            described = [a.describe for a in plan.actions]
            for d in described:
                self.assertIn(d.split("(")[0].strip()[:20], rendered.getvalue())


class InstallPlanTests(unittest.TestCase):
    def test_bundled_runtime_and_models_are_copied_inside_install_root(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source_ollama = root / "source-ollama"
            source_models = root / "source-models"
            source_ollama.mkdir()
            source_models.mkdir()
            (source_ollama / "ollama.exe").write_bytes(b"runtime")
            (source_models / "manifest").write_bytes(b"model")
            lay = layout_for("user", root / "installed")
            args = _args(service=False,
                         bundled_ollama_dir=str(source_ollama),
                         bundled_models_dir=str(source_models))
            plan, _ = build_install_plan(lay, args, None)
            plan.execute()
            self.assertEqual((lay.runtime_dir / "ollama" / "ollama.exe").read_bytes(),
                             b"runtime")
            self.assertEqual((lay.models_dir / "manifest").read_bytes(), b"model")
            config = lay.config_path.read_text(encoding="utf-8")
            self.assertIn(str(lay.runtime_dir / "ollama" / "ollama.exe"), config)
            self.assertIn(str(lay.models_dir), config)

    def test_install_is_idempotent_on_existing_config(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            lay.config_path.parent.mkdir(parents=True)
            lay.config_path.write_text("existing", encoding="utf-8")
            plan, _ = build_install_plan(lay, _args(force=False), None)
            config_step = next(a for a in plan.actions if "configuration" in a.describe)
            self.assertTrue(config_step.should_skip())

    def test_force_overwrites_config(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            lay.config_path.parent.mkdir(parents=True)
            lay.config_path.write_text("existing", encoding="utf-8")
            plan, _ = build_install_plan(lay, _args(force=True), None)
            config_step = next(a for a in plan.actions if "configuration" in a.describe)
            self.assertFalse(config_step.should_skip())

    def test_existing_memory_db_is_never_reseeded(self):
        # Re-running the installer must not wipe accumulated learning.
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            lay.data_dir.mkdir(parents=True)
            lay.memory_db.write_bytes(b"pretend-db")
            plan, _ = build_install_plan(lay, _args(), None)
            seed = next(a for a in plan.actions if "seed" in a.describe)
            self.assertTrue(seed.should_skip())

    def test_config_paths_are_absolute(self):
        # The service starts with an unpredictable cwd; relative paths break it.
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            lay.config_path.parent.mkdir(parents=True)
            write_config(lay, "127.0.0.1", 8787, "mock", "m",
                         str(lay.data_dir / "events.jsonl"))
            text = lay.config_path.read_text(encoding="utf-8")
            for line in text.splitlines():
                if line.startswith(("memory_db", "audit_db", "iam_db", "events")):
                    value = line.split("=", 1)[1].strip()
                    self.assertTrue(Path(value).is_absolute(),
                                    f"{line} is not absolute")

    def test_new_install_defaults_to_shadow_mode_and_dry_run_response(self):
        # A fresh install must not be able to block anything on day one.
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            lay.config_path.parent.mkdir(parents=True)
            write_config(lay, "127.0.0.1", 8787, "mock", "m", "/tmp/e.jsonl")
            text = lay.config_path.read_text(encoding="utf-8")
            self.assertIn("shadow_mode = true", text)
            self.assertIn("respond = dry-run", text)


class ServiceTests(unittest.TestCase):
    def test_windows_task_is_created_and_started_immediately(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            completed = type("Completed", (), {"returncode": 0})()
            with patch.object(service, "WINDOWS", True), \
                    patch.object(service.subprocess, "run", return_value=completed) as run:
                result = service.install_service(lay, r"C:\Arbiter\python.exe",
                                                 "127.0.0.1", 8787, "events.jsonl")
            self.assertEqual(run.call_count, 2)
            self.assertIn("/Create", run.call_args_list[0].args[0])
            self.assertIn("/Run", run.call_args_list[1].args[0])
            self.assertIn("created and started", result)

    def test_installed_service_starts_from_installed_config(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            argv = service.installed_argv(lay, str(lay.runtime_dir / "python.exe"))
            self.assertIn("--service-run", argv)
            self.assertIn(str(lay.config_path), argv)
            self.assertNotIn("E:\\", " ".join(argv))

    def test_serve_argv_uses_absolute_installed_paths(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("user", td)
            argv = service.serve_argv(lay, "/usr/bin/python3", "127.0.0.1",
                                      8787, str(lay.data_dir / "e.jsonl"))
            self.assertIn(str(lay.pyz_path), argv)
            self.assertIn(str(lay.memory_db), argv)
            for token in argv[1:]:
                if token.endswith((".db", ".pyz", ".jsonl")):
                    self.assertTrue(Path(token).is_absolute())

    def test_systemd_unit_restricts_writes_to_data_and_logs(self):
        with tempfile.TemporaryDirectory() as td:
            lay = layout_for("system", td)
            unit = service.unit_text(lay, "/usr/bin/python3", "127.0.0.1",
                                     8787, "/tmp/e.jsonl")
            self.assertIn("NoNewPrivileges=true", unit)
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn(f"ReadWritePaths={lay.data_dir}", unit)


class ParserTests(unittest.TestCase):
    def test_exactly_one_mode_is_required(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args([])
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--install", "--uninstall"])

    def test_dry_run_available_on_every_mode(self):
        for mode in ("--install", "--upgrade", "--uninstall", "--status"):
            args = build_parser().parse_args([mode, "--dry-run"])
            self.assertTrue(args.dry_run)


class HardwareRecommendationTests(unittest.TestCase):
    def test_local_ai_requires_both_ram_and_disk(self):
        self.assertEqual(preflight.recommended_mode(8, 8), "local")
        self.assertEqual(preflight.recommended_mode(7.9, 100), "rules")
        self.assertEqual(preflight.recommended_mode(64, 7.9), "rules")
        self.assertEqual(preflight.recommended_mode(None, 100), "rules")


if __name__ == "__main__":
    unittest.main()
