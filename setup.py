#!/usr/bin/env python3
"""
Setup script for subsweep-lead-scanner.
Backward compatibility with standard pip install workflows.
"""

from setuptools import setup, find_packages

setup(
    name="subsweep-lead-scanner",
    version="1.0.0",
    description="High-velocity OSINT subdomain reconnaissance, tech stack fingerprinting, business lead harvester, and MCP server",
    author="SubSweep Recon Team",
    author_email="recon@subsweep.dev",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov>=4.0"],
    },
    entry_points={
        "console_scripts": [
            "subsweep=subsweep_lead_scanner.cli:main",
            "lead-scanner=subsweep_lead_scanner.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
)
