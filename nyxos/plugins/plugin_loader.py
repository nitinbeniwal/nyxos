"""
NyxOS Plugin Loader
====================
Dynamically imports plugin modules, validates their PLUGIN_MANIFEST,
and performs basic safety checks before allowing registration.
"""

from __future__ import annotations

import ast
import importlib
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Optional, Set, Tuple

from loguru import logger


class PluginLoader:
    """Dynamically imports and validates NyxOS plugin modules."""

    REQUIRED_MANIFEST_KEYS: Set[str] = {"name", "version", "author", "hooks"}

    ALLOWED_EVENTS: Set[str] = {
        "on_finding",
        "on_command",
        "on_session_start",
        "on_session_end",
        "on_scan_complete",
    }

    # Patterns that trigger a safety warning (not an outright block, but logged)
    _DANGEROUS_PATTERNS: Tuple[str, ...] = (
        "os.system",
        "subprocess.call",
        "subprocess.Popen",
        "eval(",
        "exec(",
        "__import__(",
        "compile(",
        "ctypes",
    )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load(self, plugin_path: Path) -> Tuple[Optional[dict], Optional[ModuleType]]:
        """
        Import ``plugin.py`` from *plugin_path*, validate the manifest, and
        return the manifest dict and the imported module.

        Args:
            plugin_path: Directory containing ``plugin.py``.

        Returns:
            ``(manifest, module)`` on success, ``(None, None)`` on failure.
        """
        plugin_file = plugin_path / "plugin.py"
        if not plugin_file.exists():
            logger.error("No plugin.py in {}", plugin_path)
            return None, None

        # --- Safety pre-check on source --------------------------------
        safe, warning = self.sandbox_check_file(plugin_file)
        if not safe:
            logger.warning("Plugin at {} flagged by sandbox check: {}", plugin_path, warning)
            # We warn but still allow loading — operators can decide policy.

        # --- Dynamic import --------------------------------------------
        module_name = f"nyxos_plugin_{plugin_path.name.replace('-', '_')}"

        # Remove stale entry if reloading
        if module_name in sys.modules:
            del sys.modules[module_name]

        try:
            spec = importlib.util.spec_from_file_location(module_name, str(plugin_file))
            if spec is None or spec.loader is None:
                logger.error("Cannot create import spec for {}", plugin_file)
                return None, None

            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            logger.error("Import error for {}: {}", plugin_file, exc)
            sys.modules.pop(module_name, None)
            return None, None

        # --- Manifest validation ----------------------------------------
        manifest = getattr(module, "PLUGIN_MANIFEST", None)
        if manifest is None:
            logger.error("Plugin '{}' has no PLUGIN_MANIFEST.", plugin_path.name)
            return None, None

        valid, reason = self.validate_manifest(manifest)
        if not valid:
            logger.error("Invalid manifest in '{}': {}", plugin_path.name, reason)
            return None, None

        # --- Hook existence check ---------------------------------------
        for hook_name in manifest.get("hooks", []):
            fn = getattr(module, hook_name, None)
            if fn is None or not callable(fn):
                logger.warning(
                    "Plugin '{}' declares hook '{}' but no matching callable exists.",
                    manifest["name"],
                    hook_name,
                )

        return manifest, module

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_manifest(self, manifest: Any) -> Tuple[bool, str]:
        """
        Check that *manifest* is a dict with all required keys and
        that declared hooks are within the allowed set.

        Returns:
            ``(True, "")`` on success or ``(False, reason)`` on failure.
        """
        if not isinstance(manifest, dict):
            return False, "PLUGIN_MANIFEST must be a dict."

        missing = self.REQUIRED_MANIFEST_KEYS - manifest.keys()
        if missing:
            return False, f"Missing required keys: {', '.join(sorted(missing))}"

        # Name must be a non-empty string
        if not isinstance(manifest["name"], str) or not manifest["name"].strip():
            return False, "'name' must be a non-empty string."

        # Version must be a non-empty string
        if not isinstance(manifest["version"], str) or not manifest["version"].strip():
            return False, "'version' must be a non-empty string."

        # Author must be a non-empty string
        if not isinstance(manifest["author"], str) or not manifest["author"].strip():
            return False, "'author' must be a non-empty string."

        # Hooks must be a list of strings
        hooks = manifest.get("hooks", [])
        if not isinstance(hooks, list):
            return False, "'hooks' must be a list."

        unknown = set(hooks) - self.ALLOWED_EVENTS
        if unknown:
            return False, f"Unknown hook(s): {', '.join(sorted(unknown))}"

        return True, ""

    # ------------------------------------------------------------------
    # Safety Checks
    # ------------------------------------------------------------------

    def sandbox_check(self, module: Any) -> Tuple[bool, str]:
        """
        Basic runtime safety check on an already-imported module.

        Inspects the module source for dangerous patterns.  This is **not**
        a real sandbox — it is a best-effort heuristic.

        Returns:
            ``(True, "")`` if no dangerous patterns detected,
            ``(False, warning_message)`` otherwise.
        """
        source_file = getattr(module, "__file__", None)
        if source_file is None:
            return True, ""
        return self.sandbox_check_file(Path(source_file))

    def sandbox_check_file(self, filepath: Path) -> Tuple[bool, str]:
        """
        Scan *filepath* source text for dangerous patterns.

        Returns:
            ``(True, "")`` if clean, ``(False, warning)`` if flagged.
        """
        try:
            source = filepath.read_text(encoding="utf-8")
        except OSError:
            return False, f"Cannot read {filepath}"

        flagged: list[str] = []
        for pattern in self._DANGEROUS_PATTERNS:
            if pattern in source:
                flagged.append(pattern)

        if flagged:
            return False, f"Dangerous patterns detected: {', '.join(flagged)}"

        # Optional: AST-level check for import of known dangerous modules
        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            return False, "plugin.py has syntax errors."

        dangerous_imports = {"ctypes", "multiprocessing", "signal"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in dangerous_imports:
                        flagged.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module.split(".")[0] in dangerous_imports:
                    flagged.append(f"from {node.module} import ...")

        if flagged:
            return False, f"Suspicious imports: {', '.join(flagged)}"

        return True, ""
