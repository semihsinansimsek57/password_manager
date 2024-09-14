#!/bin/bash

# Run bandit for security issues in Python code
echo "Running bandit for security issues in Python code..."
bandit -r .

# Run safety to check for known vulnerabilities in dependencies
echo "Running safety to check for known vulnerabilities in dependencies..."
safety check

# Ensure secure library is up-to-date
echo "Updating secure library..."
pip install --upgrade secure