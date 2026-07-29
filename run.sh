#!/usr/bin/env bash
# Start the mail reader. By default it serves every mailbox listed in
# mailboxes.json, selectable from the dropdown in the UI.
#
# Setting MAIL_BUCKET overrides that with a single ad-hoc mailbox:
#   MAIL_BUCKET=some-bucket MAIL_PREFIX=inbox/ ./run.sh
set -euo pipefail
cd "$(dirname "$0")"

export MAIL_REGION="${MAIL_REGION:-us-east-1}"
export MAIL_PORT="${MAIL_PORT:-5000}"

exec .venv/bin/python app.py
