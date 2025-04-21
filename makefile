# Makefile

# Variables
PROJECT_NAME := zexfrost
VENV_DIR := .venv
UV := uv
PRE_COMMIT := $(UV) run pre-commit

# Default target
all: init

# Initialize the project
init: uv-sync pre-commit-install

# Install dependencies with uv and create virtual environment in the project folder
uv-sync:
	@echo "Setting up uv and installing dependencies..."
	$(UV) sync

# Install pre-commit hooks
pre-commit-install:
	@echo "Installing pre-commit hooks..."
	$(PRE_COMMIT) install && $(PRE_COMMIT) install --hook-type pre-push

# Run pre-commit hooks on all files
pre-commit-run:
	@echo "Running pre-commit hooks on all files..."
	$(PRE_COMMIT) run --all-files

# Run type check for all files
type-check:
	@echo "Running type check for all files"
	$(UV) run pyright .

# Clean up the project (remove virtual environment and pre-commit hooks)
clean:
	@echo "Cleaning up..."
	rm -rf $(VENV_DIR)
	$(PRE_COMMIT) uninstall

# Help target to display available commands
help:
	@echo "Available commands:"
	@echo "  make init         - Initialize the project (install dependencies and pre-commit hooks)"
	@echo "  make uv-sync - Install dependencies with uv"
	@echo "  make pre-commit-install - Install pre-commit hooks"
	@echo "  make pre-commit-run - Run pre-commit hooks on all files"
	@echo "  make clean        - Clean up the project (remove virtual environment and pre-commit hooks)"
	@echo "  make help         - Display this help message"
	@echo "  make type-check   - Run type check for all files"
	@echo "  make unit-test   - Run all unit tests"

.PHONY: all init uv-sync pre-commit-install pre-commit-run clean type-check unit-test help