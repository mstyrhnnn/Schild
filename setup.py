
from setuptools import setup, find_packages

setup(
    name="schild",
    version="1.1.0",  # DONE: TASK-06
    description="Autonomous Defense & AI-Driven Threat Hunting",
    author="SCHILD Team",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "openai>=1.30.0,<2.0.0",
        "anthropic>=0.28.0,<1.0.0",
        "google-genai>=1.0.0",
        "python-dotenv>=1.0.0,<2.0.0",
        "scikit-learn>=1.4.0,<2.0.0",
        "numpy>=1.26.0,<3.0.0",
        "requests>=2.31.0,<3.0.0",
        "beautifulsoup4>=4.12.0,<5.0.0",
        "duckduckgo-search>=4.0.0,<7.0.0",
        "json_repair>=0.25.0,<1.0.0",
        "rich>=13.7.0,<15.0.0",
        "watchdog>=4.0.0,<5.0.0",
        "apscheduler>=3.10.0,<4.0.0",
        "fastapi>=0.111.0,<1.0.0",
        "uvicorn>=0.30.0,<1.0.0",
        "pydantic>=2.7.0,<3.0.0",
    ],  # DONE: TASK-06
    entry_points={
        "console_scripts": [
            "schild=schild.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
    ],
)
