# Makefile for VulnBuster

# Variables
PYTHON = python3
PIP = pip3
PYTEST = python -m pytest
COVERAGE = python -m coverage
BLACK = black .
ISORT = isort .
FLAKE8 = flake8
MYPY = mypy .
BANDIT = bandit -r .
SAFETY = safety check --full-report

# Default target
.DEFAULT_GOAL := help

# Help target to show all make commands
help:
	@echo "VulnBuster Development Commands:"
	@echo "  setup           - Set up development environment"
	@echo "  install         - Install package in development mode"
	@echo "  test            - Run tests with coverage"
	@echo "  lint            - Run all linters (black, isort, flake8, mypy)"
	@echo "  format          - Format code with black and isort"
	@echo "  security        - Run security checks (bandit, safety)"
	@echo "  clean           - Clean build artifacts"
	@echo "  docker-build    - Build Docker image"
	@echo "  docker-run      - Run Docker container"
	@echo "  docker-clean    - Remove Docker containers and images"

# Setup development environment
setup:
	$(PYTHON) -m pip install --upgrade pip
	$(PIP) install -e ".[dev]"
	pre-commit install

# Install package in development mode
install:
	$(PIP) install -e .

# Run tests with coverage
test:
	$(PYTEST) --cov=vulnbuster --cov-report=term-missing --cov-report=xml

# Run all linters
lint: black isort flake8 mypy

# Format code
format:
	$(BLACK)
	$(ISORT)

# Run security checks
security:
	$(BANDIT)
	$(SAFETY)

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name '__pycache__' -exec rm -rf {} +
	find . -type f -name '*.py[co]' -delete
	find . -type d -name '.pytest_cache' -exec rm -rf {} +
	find . -type d -name '.mypy_cache' -exec rm -rf {} +
	find . -type d -name '.coverage' -delete

# Docker commands
docker-build:
	docker-compose build

docker-run:
	docker-compose up -d

docker-clean:
	docker-compose down -v --remove-orphans
	docker system prune -f

# Individual linter targets
black:
	$(BLACK) --check .

isort:
	$(ISORT) --check-only .

flake8:
	$(FLAKE8)

mypy:
	$(MYPY)

bandit:
	$(BANDIT)

safety:
	$(SAFETY)

.PHONY: help setup install test lint format security clean docker-build docker-run docker-clean black isort flake8 mypy bandit safety
