"""
NyxOS — AI-Native Cybersecurity Operating System
Package setup configuration.
"""

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = ""
readme_path = this_directory / "docs" / "README.md"
if readme_path.exists():
    long_description = readme_path.read_text(encoding="utf-8")

# Parse requirements.txt
requirements = []
req_path = this_directory / "requirements.txt"
if req_path.exists():
    for line in req_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and not line.startswith("─"):
            requirements.append(line)

setup(
    name="nyxos",
    version="0.1.0",
    author="Nitin Beniwal",
    author_email="",
    url="https://github.com/nitinbeniwal/nyxos",
    # original_author="NyxOS Team",
    author_email="nyxos@protonmail.com",
    description="AI-Native Cybersecurity Operating System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/nyxos-project/nyxos",
    project_urls={
        "Bug Tracker": "https://github.com/nyxos-project/nyxos/issues",
        "Documentation": "https://github.com/nyxos-project/nyxos/tree/main/docs",
        "Source Code": "https://github.com/nyxos-project/nyxos",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.12",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.23.0",
            "pytest-mock>=3.12.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.7.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nyxos=main:main",
            "nyxsh=nyxos.core.shell.nyxsh:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Operating System",
    ],
    license="GPL-3.0",
    keywords="cybersecurity ai pentesting kali-linux osint forensics",
    include_package_data=True,
    package_data={
        "nyxos": [
            "reporting/templates/*.html",
            "dashboard/frontend/**/*",
        ],
    },
)
