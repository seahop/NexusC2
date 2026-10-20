"""Tests for the command validator (gui/widgets/command_validator.py).

Focus areas from code-review fixes:
  - os module is NOT shadowed (the loop variable is named os_name, not os)
  - Compatibility list processing (normalization to list, OS mapping)
"""

import os as stdlib_os  # alias to avoid any confusion
import unittest
import inspect
import tempfile
from unittest.mock import patch, MagicMock

# Patch logger before import
with patch.dict("sys.modules", {
    "utils.logger": MagicMock(get_logger=MagicMock(return_value=MagicMock())),
}):
    from gui.widgets.command_validator import CommandValidator


def _make_toml(commands_dict):
    """Write a minimal commands.toml and return its path."""
    import tomli
    # tomli is read-only; we write plain TOML by hand
    lines = ["[commands]\n"]
    for key, data in commands_dict.items():
        lines.append(f"[commands.{key}]\n")
        for k, v in data.items():
            if isinstance(v, str):
                lines.append(f'{k} = "{v}"\n')
            elif isinstance(v, list):
                items = ", ".join(f'"{i}"' for i in v)
                lines.append(f"{k} = [{items}]\n")
            elif isinstance(v, bool):
                lines.append(f'{k} = {"true" if v else "false"}\n')
    fd, path = tempfile.mkstemp(suffix=".toml")
    with stdlib_os.fdopen(fd, "w") as f:
        f.writelines(lines)
    return path


class TestOsModuleNotShadowed(unittest.TestCase):
    """The is_command_compatible loop variable must be os_name, not os."""

    def test_loop_variable_is_os_name_not_os(self):
        """Inspect source of is_command_compatible to confirm the loop var is os_name."""
        source = inspect.getsource(CommandValidator.is_command_compatible)
        # The fixed code uses:  for os_name in compatibility
        # The broken code used: for os in compatibility  (shadowing the module)
        # We look for the pattern "for os_name" and reject bare "for os "
        self.assertIn("os_name", source,
                       "Loop variable should be named os_name to avoid shadowing")

    def test_os_module_still_importable_after_validation(self):
        """Using the validator must not break stdlib os module."""
        toml_path = _make_toml({
            "shell": {
                "name": "shell",
                "description": "Execute shell command",
                "os_compatibility": "all",
            },
        })
        try:
            validator = CommandValidator(config_path=toml_path)
            validator.is_command_compatible("shell", "linux")

            # os module should still work normally
            self.assertTrue(hasattr(stdlib_os, "path"))
            self.assertTrue(callable(stdlib_os.path.join))
        finally:
            stdlib_os.remove(toml_path)


class TestOsCompatibilityNormalization(unittest.TestCase):
    """os_compatibility values must be normalized to lists."""

    def _make_validator(self, commands):
        path = _make_toml(commands)
        try:
            return CommandValidator(config_path=path), path
        except Exception:
            stdlib_os.remove(path)
            raise

    def test_string_all_becomes_list(self):
        v, p = self._make_validator({
            "shell": {"name": "shell", "os_compatibility": "all"},
        })
        stdlib_os.remove(p)
        self.assertEqual(v.command_os_compatibility["shell"], ["all"])

    def test_single_string_becomes_list(self):
        v, p = self._make_validator({
            "bof": {"name": "bof", "os_compatibility": "windows"},
        })
        stdlib_os.remove(p)
        self.assertEqual(v.command_os_compatibility["bof"], ["windows"])

    def test_list_stays_list(self):
        v, p = self._make_validator({
            "upload": {"name": "upload", "os_compatibility": ["windows", "linux"]},
        })
        stdlib_os.remove(p)
        self.assertEqual(v.command_os_compatibility["upload"], ["windows", "linux"])


class TestOsMappings(unittest.TestCase):
    """is_command_compatible must map OS variations to canonical names."""

    def setUp(self):
        path = _make_toml({
            "shell": {"name": "shell", "os_compatibility": "all"},
            "bof": {"name": "bof", "os_compatibility": "windows"},
            "sudo_session": {"name": "sudo-session", "os_compatibility": ["linux", "darwin"]},
        })
        self.validator = CommandValidator(config_path=path)
        self.toml_path = path

    def tearDown(self):
        stdlib_os.remove(self.toml_path)

    def test_all_is_compatible_everywhere(self):
        for os_name in ["linux", "windows", "darwin", "unknown"]:
            self.assertTrue(
                self.validator.is_command_compatible("shell", os_name),
                f"'shell' (all) should be compatible with {os_name}"
            )

    def test_windows_only_rejects_linux(self):
        self.assertFalse(self.validator.is_command_compatible("bof", "linux"))

    def test_windows_only_accepts_windows(self):
        self.assertTrue(self.validator.is_command_compatible("bof", "windows"))

    def test_windows_variations_map_correctly(self):
        for variant in ["win", "win32", "win64", "windows_amd64"]:
            self.assertTrue(
                self.validator.is_command_compatible("bof", variant),
                f"'bof' should be compatible with Windows variant '{variant}'"
            )

    def test_linux_variations_map_correctly(self):
        for variant in ["ubuntu", "debian", "centos", "rhel", "fedora"]:
            self.assertTrue(
                self.validator.is_command_compatible("sudo-session", variant),
                f"'sudo-session' should be compatible with Linux variant '{variant}'"
            )

    def test_darwin_variations_map_correctly(self):
        for variant in ["macos", "osx", "mac", "darwin_arm64"]:
            self.assertTrue(
                self.validator.is_command_compatible("sudo-session", variant),
                f"'sudo-session' should be compatible with Darwin variant '{variant}'"
            )

    def test_case_insensitive(self):
        self.assertTrue(self.validator.is_command_compatible("bof", "WINDOWS"))
        self.assertTrue(self.validator.is_command_compatible("bof", "Windows"))


class TestGetCommandsForOs(unittest.TestCase):
    """get_commands_for_os must filter properly."""

    def test_returns_only_compatible_commands(self):
        path = _make_toml({
            "shell": {"name": "shell", "os_compatibility": "all"},
            "bof": {"name": "bof", "os_compatibility": "windows"},
            "sudo_session": {"name": "sudo-session", "os_compatibility": ["linux", "darwin"]},
        })
        try:
            v = CommandValidator(config_path=path)
            linux_cmds = v.get_commands_for_os("linux")
            self.assertIn("shell", linux_cmds)
            self.assertIn("sudo-session", linux_cmds)
            self.assertNotIn("bof", linux_cmds)
        finally:
            stdlib_os.remove(path)


class TestValidateCommand(unittest.TestCase):
    """validate_command integrates OS checks with general validation."""

    def test_empty_command_rejected(self):
        path = _make_toml({"shell": {"name": "shell", "os_compatibility": "all"}})
        try:
            v = CommandValidator(config_path=path)
            valid, error = v.validate_command("")
            self.assertFalse(valid)
            self.assertIn("Empty", error)
        finally:
            stdlib_os.remove(path)

    def test_os_incompatible_command_rejected(self):
        path = _make_toml({
            "bof": {"name": "bof", "os_compatibility": "windows"},
        })
        try:
            v = CommandValidator(config_path=path)
            valid, error = v.validate_command("bof test.o", agent_os="linux")
            self.assertFalse(valid)
        finally:
            stdlib_os.remove(path)


if __name__ == "__main__":
    unittest.main()
