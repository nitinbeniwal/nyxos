#!/usr/bin/env python3
# Created by Nitin Beniwal (@nitinbeniwal) — Architect
"""
NyxOS — AI-Native Cybersecurity Operating System
=================================================

Entry point for the NyxOS interactive shell.

Usage::

    python main.py                        # Normal launch
    python main.py --no-onboarding        # Skip first-run wizard
    python main.py --config-path /path    # Custom config location
    python main.py --debug                # Enable debug logging
    python main.py --version              # Show version and exit
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from loguru import logger


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="nyxos",
        description="NyxOS — AI-Native Cybersecurity Operating System",
    )
    parser.add_argument(
        "--no-onboarding",
        action="store_true",
        help="Skip the first-run onboarding wizard",
    )
    parser.add_argument(
        "--config-path",
        type=str,
        default=None,
        help="Path to a custom config.json file",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging to stderr",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show NyxOS version and exit",
    )
    return parser.parse_args()


def configure_logging(debug: bool = False) -> None:
    """
    Set up loguru logging.

    - Always writes to ``~/.nyxos/logs/nyxos.log`` at DEBUG level.
    - Writes to stderr at WARNING (or DEBUG if ``--debug`` flag).
    """
    logger.remove()

    # stderr handler
    level = "DEBUG" if debug else "WARNING"
    logger.add(
        sys.stderr,
        level=level,
        format="<dim>{time:HH:mm:ss}</dim> | <level>{level:<7}</level> | {message}",
    )

    # File handler — always captures everything
    log_path = Path.home() / ".nyxos" / "logs" / "nyxos.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            str(log_path),
            level="DEBUG",
            rotation="10 MB",
            retention="7 days",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level:<7} | {name}:{line} | {message}",
        )
    except OSError as e:
        logger.warning(f"Cannot write to log file {log_path}: {e}")


def main() -> None:
    """Launch the NyxOS shell."""
    args = parse_args()

    # Handle --version
    if args.version:
        try:
            from nyxos import __version__
            print(f"NyxOS v{__version__}")
        except ImportError:
            print("NyxOS v0.1.0")
        sys.exit(0)

    # Configure logging before importing anything heavy
    configure_logging(debug=args.debug)

    # Import and launch shell
    try:
        from nyxos.core.shell.nyxsh import NyxShell
    except ImportError as e:
        print(
            f"Error: Cannot import NyxOS shell: {e}\n"
            "Make sure NyxOS is installed: pip install -e .\n"
            "Or run from the project root directory.",
            file=sys.stderr,
        )
        sys.exit(1)

    shell = NyxShell(
        config_path=args.config_path,
        debug=args.debug,
    )
    shell.run(skip_onboarding=args.no_onboarding)


if __name__ == "__main__":
    main()
