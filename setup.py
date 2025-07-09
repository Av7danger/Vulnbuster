#!/usr/bin/env python3
"""
VulnBuster - AI-Powered Offensive Security Framework
Setup script for package installation
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements(filename):
    with open(filename, "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="vulnbuster",
    version="1.0.0",
    author="Av7danger",
    author_email="av7danger@protonmail.com",
    description="AI-Powered Offensive Security Framework for CTFs, Bug Bounties, and Red Teams",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/Av7danger/Vulnbuster",
    project_urls={
        "Bug Tracker": "https://github.com/Av7danger/Vulnbuster/issues",
        "Documentation": "https://github.com/Av7danger/Vulnbuster/docs",
        "Source Code": "https://github.com/Av7danger/Vulnbuster",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Testing",
    ],
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=read_requirements("requirements.txt"),
    extras_require={
        "dev": read_requirements("requirements-dev.txt"),
        "full": read_requirements("requirements-full.txt"),
    },
    entry_points={
        "console_scripts": [
            "vulnbuster=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "vulnbuster": [
            "config/*.json",
            "payloads/*.json",
            "templates/*.html",
            "templates/*.j2",
            "wordlists/*.txt",
            "prompts/*.j2",
        ],
    },
    keywords="security, penetration-testing, vulnerability-scanner, ai, offensive-security, ctf, bug-bounty",
    license="MIT",
    platforms=["any"],
) 