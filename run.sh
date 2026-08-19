#!/usr/bin/env bash

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "True usage: ./run.sh <login|register>"
    exit 1
fi

ROOT_PATH=$(pwd)
LOG_FILE="$ROOT_PATH/server.log"

source "$ROOT_PATH/env/bin/activate"

# 1. Cleanup function to stop background server on script exit or interrupt
cleanup() {
    if [ -n "${SERVER_PID:-}" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# 2. Start server in background, redirecting logs to server.log
echo -e "\e[34mStarting server in background...\e[0m"
(cd Server && uvicorn app.main:app --port 8000 --reload > "$LOG_FILE" 2>&1) &
SERVER_PID=$!

# 3. Wait until port 8000 is open and actively accepting connections
echo -ne "\e[33mWaiting for server initialization...\e[0m"
while ! (echo > /dev/tcp/127.0.0.1/8000) 2>/dev/null && ! nc -z 127.0.0.1 8000 2>/dev/null; do
    sleep 0.2
done
echo -e " \e[32m[Ready]\e[0m\n"

# 4. Run CLI with clean terminal input
if [ "$1" == "login" ]; then
    python -m Client.main login
elif [ "$1" == "register" ]; then
    python -m Client.main register
else
    echo "Unknown argument: $1"
    echo "True usage: ./run.sh <login|register>"
    exit 1
fi