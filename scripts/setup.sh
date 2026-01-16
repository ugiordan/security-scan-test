#!/bin/bash
# Intentional ShellCheck issues for testing

# SC2086: Quote variables to prevent word splitting
echo $HOME

# SC2046: Quote command substitution
rm $(find . -name "*.tmp")

# SC2006: Use $(...) instead of backticks
result=`ls -la`

# SC2164: Use cd ... || exit in case cd fails
cd /some/directory

# SC2155: Declare and assign separately
export var="$(command_that_might_fail)"

# SC2034: Unused variable
unused_var="test"

# Hardcoded credentials (security issue)
DB_PASSWORD="admin123"
API_TOKEN="ghp_1234567890abcdefghijklmnopqrstuv"

echo "Setup complete"
