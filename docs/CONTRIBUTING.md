# Contributing to NyxOS

## How to Create a New Skill

1. Create a directory: `nyxos/skills/your_skill/`
2. Add `__init__.py` and `your_skill.py`
3. Extend `BaseSkill` from `nyxos.skills.base_skill`
4. Implement `execute(params)` → `SkillResult`
5. Implement `get_commands(intent)` → `List[str]`
6. Register via `@skill_registry` decorator
7. Add tests in `tests/test_skills.py`

## How to Create a Plugin

1. Create a directory: `~/.nyxos/plugins/your-plugin/`
2. Add `plugin.py` with `PLUGIN_MANIFEST` dict
3. Implement hook functions (`on_finding`, `on_command`, etc.)
4. Optional: add `config.json` for plugin-specific settings
5. See `nyxos/plugins/example_plugin/plugin.py` for a complete example

## Code Style Guide

- **Python 3.12+** required
- **Type hints** on all function signatures
- **Docstrings** on all classes and public methods
- Use `loguru.logger` — never `print()` for internal logs
- Use `rich` for terminal output — never raw ANSI escape codes
- Use `pathlib.Path` — never hardcode paths
- Never bare `except:` — always catch specific exceptions
- All commands must pass through `SafetyGuard.check()`
- All actions must be logged via `AuditLogger.log()`

## Pull Request Process

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write tests for your changes
4. Ensure `python3 verify_nyxos.py` passes
5. Submit a PR with a clear description

## Community

- **GitHub**: github.com/nyxos-project/nyxos
- **Discord**: discord.gg/nyxos
- **LinkedIn**: linkedin.com/company/nyxos
