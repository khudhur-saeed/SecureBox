#!/usr/bin/env bash

set -euo pipefail


if [ $# -ne 1 ]; then
    echo "True usage: ./run.sh <login|register>"
    exit 1
fi

ROOT_PATH=$(pwd)


source "$ROOT_PATH/env/bin/activate"


echo "Starting server in background..."
(cd Server && uvicorn app.main:app --port 8000 --reload) &
SERVER_PID=$! 

trap "kill $SERVER_PID 2>/dev/null || true" EXIT


sleep 2


if [ "$1" == "login" ]; then
    python -m Client.main login
elif [ "$1" == "register" ]; then
    python -m Client.main register
else
    echo "Unknown argument: $1"
    echo "True usage: ./run.sh <login|register>"
    exit 1
fi