"""
NyxOS Plugin System
====================
Community-extensible plugin architecture for NyxOS.
Plugins can add skills, shell builtins, AI providers, and hook into system events.
"""

from nyxos.plugins.plugin_manager import PluginManager, PluginInfo
from nyxos.plugins.plugin_loader import PluginLoader

__all__ = ["PluginManager", "PluginInfo", "PluginLoader"]
