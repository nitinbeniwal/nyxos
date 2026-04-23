"""
NyxOS Plugin Manager
=====================
Manages the full lifecycle of NyxOS plugins: discovery, installation,
loading, enabling/disabling, uninstallation, and event dispatch.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from loguru import logger

from nyxos.core.config.settings import NyxConfig, get_config
from nyxos.core.security.audit_logger import AuditLogger
from nyxos.plugins.plugin_loader import PluginLoader


@dataclass
class PluginInfo:
    """Metadata about an installed plugin."""
    name: str
    version: str
    author: str
    description: str = ""
    hooks: List[str] = field(default_factory=list)
    enabled: bool = True
    path: Path = field(default_factory=lambda: Path("."))

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        data = asdict(self)
        data["path"] = str(data["path"])
        return data

    @classmethod
    def from_manifest(cls, manifest: dict, plugin_path: Path, enabled: bool = True) -> "PluginInfo":
        """Create a PluginInfo from a validated PLUGIN_MANIFEST dict."""
        return cls(
            name=manifest["name"],
            version=manifest["version"],
            author=manifest["author"],
            description=manifest.get("description", ""),
            hooks=list(manifest.get("hooks", [])),
            enabled=enabled,
            path=plugin_path,
        )


_REGISTRY_FILENAME = "registry.json"


def _load_registry(plugin_dir: Path) -> Dict[str, dict]:
    """Load the plugin registry (enabled/disabled state)."""
    registry_path = plugin_dir / _REGISTRY_FILENAME
    if registry_path.exists():
        try:
            return json.loads(registry_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Corrupt plugin registry, starting fresh: {}", exc)
    return {}


def _save_registry(plugin_dir: Path, registry: Dict[str, dict]) -> None:
    """Persist the plugin registry to disk."""
    registry_path = plugin_dir / _REGISTRY_FILENAME
    registry_path.write_text(json.dumps(registry, indent=2), encoding="utf-8")


def _get_username(config: Optional[NyxConfig]) -> str:
    """Safely extract username from NyxConfig regardless of field name."""
    if config is None:
        return "system"
    user_obj = getattr(config, "user", None)
    if user_obj is None:
        return "system"
    for attr in ("username", "name", "user"):
        val = getattr(user_obj, attr, None)
        if val and isinstance(val, str):
            return val
    if isinstance(user_obj, dict):
        return user_obj.get("username", user_obj.get("name", "system"))
    if isinstance(user_obj, str):
        return user_obj
    return "system"


class PluginManager:
    """Discovers, loads, installs, and manages NyxOS plugins."""

    PLUGIN_DIR: Path = Path.home() / ".nyxos" / "plugins"

    def __init__(self, config: Optional[NyxConfig] = None) -> None:
        self.config: NyxConfig = config or get_config()
        self.loader = PluginLoader()
        self.audit = AuditLogger()
        self.PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
        self._plugins: Dict[str, PluginInfo] = {}
        self._modules: Dict[str, Any] = {}
        self._hooks: Dict[str, List[Callable]] = {
            event: [] for event in PluginLoader.ALLOWED_EVENTS
        }
        self._registry: Dict[str, dict] = _load_registry(self.PLUGIN_DIR)

    def load_all(self) -> List[PluginInfo]:
        """Discover and load every plugin found under PLUGIN_DIR."""
        loaded: List[PluginInfo] = []
        if not self.PLUGIN_DIR.exists():
            logger.debug("Plugin directory does not exist yet.")
            return loaded
        for candidate in sorted(self.PLUGIN_DIR.iterdir()):
            if not candidate.is_dir():
                continue
            if candidate.name.startswith((".", "_")) or candidate.name == _REGISTRY_FILENAME:
                continue
            plugin_py = candidate / "plugin.py"
            if not plugin_py.exists():
                logger.warning("Skipping {}: no plugin.py found", candidate.name)
                continue
            try:
                manifest, module = self.loader.load(candidate)
            except Exception as exc:
                logger.error("Failed to load plugin '{}': {}", candidate.name, exc)
                continue
            if manifest is None or module is None:
                logger.warning("Plugin '{}' failed validation, skipping.", candidate.name)
                continue
            reg_entry = self._registry.get(manifest["name"], {})
            enabled = reg_entry.get("enabled", True)
            info = PluginInfo.from_manifest(manifest, candidate, enabled=enabled)
            self._plugins[info.name] = info
            self._modules[info.name] = module
            if enabled:
                self._register_hooks(info.name, module, manifest.get("hooks", []))
            loaded.append(info)
            logger.info("Loaded plugin: {} v{} (enabled={})", info.name, info.version, enabled)
        username = _get_username(self.config)
        self.audit.log("PLUGIN", "load_all", username, {
            "loaded": [p.name for p in loaded]
        })
        return loaded

    def _register_hooks(self, plugin_name: str, module: Any, hook_names: List[str]) -> None:
        """Register a plugin's hook functions into the event dispatch table."""
        for hook_name in hook_names:
            if hook_name not in PluginLoader.ALLOWED_EVENTS:
                logger.warning("Plugin '{}' declares unknown hook '{}'", plugin_name, hook_name)
                continue
            fn = getattr(module, hook_name, None)
            if fn is None or not callable(fn):
                logger.warning("Plugin '{}' declares hook '{}' but no callable found", plugin_name, hook_name)
                continue
            self._hooks[hook_name].append(fn)
            logger.debug("Registered hook {}.{}", plugin_name, hook_name)

    def _unregister_hooks(self, plugin_name: str) -> None:
        """Remove all hooks belonging to plugin_name."""
        module = self._modules.get(plugin_name)
        if module is None:
            return
        for event in self._hooks:
            self._hooks[event] = [
                cb for cb in self._hooks[event]
                if not self._callback_belongs_to(cb, module)
            ]

    @staticmethod
    def _callback_belongs_to(callback: Callable, module: Any) -> bool:
        """Check if a callback was defined in module."""
        return getattr(callback, "__module__", None) == getattr(module, "__name__", None)

    def install(self, source: str) -> bool:
        """Install a plugin from a git URL or a local directory path."""
        source_path = Path(source).expanduser().resolve()
        if source_path.is_dir():
            return self._install_local(source_path)
        if source.startswith(("http://", "https://", "git@")):
            return self._install_git(source)
        logger.error("Unrecognized plugin source: {}", source)
        return False

    def _install_local(self, source_path: Path) -> bool:
        """Copy a local plugin directory into PLUGIN_DIR."""
        plugin_py = source_path / "plugin.py"
        if not plugin_py.exists():
            logger.error("No plugin.py found in {}", source_path)
            return False
        manifest, module = self.loader.load(source_path)
        if manifest is None:
            logger.error("Plugin validation failed for {}", source_path)
            return False
        dest = self.PLUGIN_DIR / manifest["name"]
        if dest.exists():
            logger.warning("Plugin '{}' already installed, overwriting.", manifest["name"])
            shutil.rmtree(dest)
        shutil.copytree(source_path, dest)
        self._persist_registry_entry(manifest["name"], enabled=True)
        username = _get_username(self.config)
        self.audit.log("PLUGIN", "install", username, {
            "plugin": manifest["name"],
            "source": str(source_path),
        })
        logger.info("Installed plugin '{}' from local path.", manifest["name"])
        return True

    def _install_git(self, url: str) -> bool:
        """Clone a git repository into PLUGIN_DIR."""
        repo_name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
        dest = self.PLUGIN_DIR / repo_name
        if dest.exists():
            logger.warning("Directory '{}' exists, removing for fresh clone.", dest)
            shutil.rmtree(dest)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", url, str(dest)],
                check=True, capture_output=True, text=True, timeout=120,
            )
        except FileNotFoundError:
            logger.error("git is not installed.")
            return False
        except subprocess.CalledProcessError as exc:
            logger.error("git clone failed: {}", exc.stderr.strip())
            return False
        except subprocess.TimeoutExpired:
            logger.error("git clone timed out after 120s.")
            return False
        plugin_py = dest / "plugin.py"
        if not plugin_py.exists():
            logger.error("Cloned repo has no plugin.py — removing.")
            shutil.rmtree(dest, ignore_errors=True)
            return False
        manifest, _ = self.loader.load(dest)
        if manifest is None:
            logger.error("Plugin validation failed — removing.")
            shutil.rmtree(dest, ignore_errors=True)
            return False
        canonical_dest = self.PLUGIN_DIR / manifest["name"]
        if dest != canonical_dest:
            if canonical_dest.exists():
                shutil.rmtree(canonical_dest)
            dest.rename(canonical_dest)
        self._persist_registry_entry(manifest["name"], enabled=True)
        username = _get_username(self.config)
        self.audit.log("PLUGIN", "install", username, {
            "plugin": manifest["name"],
            "source": url,
        })
        logger.info("Installed plugin '{}' from git.", manifest["name"])
        return True

    def uninstall(self, name: str) -> bool:
        """Remove a plugin by name."""
        info = self._plugins.get(name)
        plugin_path = info.path if info else self.PLUGIN_DIR / name
        if not plugin_path.exists():
            logger.error("Plugin '{}' not found at {}", name, plugin_path)
            return False
        self._unregister_hooks(name)
        shutil.rmtree(plugin_path, ignore_errors=True)
        self._plugins.pop(name, None)
        self._modules.pop(name, None)
        self._registry.pop(name, None)
        _save_registry(self.PLUGIN_DIR, self._registry)
        username = _get_username(self.config)
        self.audit.log("PLUGIN", "uninstall", username, {"plugin": name})
        logger.info("Uninstalled plugin '{}'.", name)
        return True

    def enable(self, name: str) -> None:
        """Enable a previously disabled plugin."""
        info = self._plugins.get(name)
        if info is None:
            logger.error("Plugin '{}' is not loaded.", name)
            return
        if info.enabled:
            logger.info("Plugin '{}' is already enabled.", name)
            return
        info.enabled = True
        module = self._modules.get(name)
        if module:
            self._register_hooks(name, module, info.hooks)
        self._persist_registry_entry(name, enabled=True)
        logger.info("Enabled plugin '{}'.", name)

    def disable(self, name: str) -> None:
        """Disable a plugin without uninstalling it."""
        info = self._plugins.get(name)
        if info is None:
            logger.error("Plugin '{}' is not loaded.", name)
            return
        if not info.enabled:
            logger.info("Plugin '{}' is already disabled.", name)
            return
        info.enabled = False
        self._unregister_hooks(name)
        self._persist_registry_entry(name, enabled=False)
        logger.info("Disabled plugin '{}'.", name)

    def list_installed(self) -> List[PluginInfo]:
        """Return metadata for all loaded plugins."""
        return list(self._plugins.values())

    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        """Get info for a specific plugin by name."""
        return self._plugins.get(name)

    def get_hooks(self, event: str) -> List[Callable]:
        """Return all registered callbacks for an event type."""
        return list(self._hooks.get(event, []))

    def fire_event(self, event: str, **kwargs: Any) -> None:
        """Call every hook registered for event. Never crashes the shell."""
        hooks = self._hooks.get(event, [])
        if not hooks:
            return
        try:
            config_dict = {}
            if hasattr(self.config, '__dict__'):
                for key, val in self.config.__dict__.items():
                    try:
                        if hasattr(val, '__dict__'):
                            config_dict[key] = val.__dict__
                        else:
                            config_dict[key] = val
                    except Exception:
                        config_dict[key] = str(val)
        except Exception:
            config_dict = {}
        kwargs.setdefault("config", config_dict)
        for hook in hooks:
            try:
                hook(**kwargs)
            except Exception as exc:
                hook_name = getattr(hook, "__qualname__", repr(hook))
                logger.error("Plugin hook {} raised {}: {}", hook_name, type(exc).__name__, exc)

    def _persist_registry_entry(self, name: str, enabled: bool) -> None:
        """Write the enabled state to the on-disk registry."""
        self._registry[name] = {"enabled": enabled}
        _save_registry(self.PLUGIN_DIR, self._registry)
