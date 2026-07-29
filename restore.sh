#!/usr/bin/env bash
# Restore deleted messages by removing their S3 delete markers.
#   ./restore.sh <bucket>            list what is currently deleted
#   ./restore.sh <bucket> <key>      restore one message
#   ./restore.sh <bucket> --all      restore everything deleted
#
# Only works within the lifecycle window (30 days); after that the noncurrent
# versions are purged and the mail is genuinely gone.
set -uo pipefail

BUCKET="${1:?usage: restore.sh <bucket> [key|--all]}"
TARGET="${2:-}"

markers() {
  aws s3api list-object-versions --bucket "$BUCKET" \
    --query 'DeleteMarkers[?IsLatest].[Key,VersionId,LastModified]' --output text
}

restore_one() {
  local key="$1" vid="$2"
  aws s3api delete-object --bucket "$BUCKET" --key "$key" --version-id "$vid" >/dev/null \
    && echo "restored $key"
}

if [ -z "$TARGET" ]; then
  echo "Deleted messages in $BUCKET:"
  markers | while read -r key vid ts; do
    subject=$(aws s3api get-object --bucket "$BUCKET" --key "$key" \
                --version-id "$(aws s3api list-object-versions --bucket "$BUCKET" \
                   --prefix "$key" --query 'Versions[?IsLatest==`false`]|[0].VersionId' \
                   --output text)" /dev/stdout 2>/dev/null \
              | grep -im1 '^subject:' | cut -c1-70)
    printf '  %s  %s\n      %s\n' "$ts" "$key" "${subject:-(no subject)}"
  done
  echo
  echo "Restore one:  ./restore.sh $BUCKET <key>"
  echo "Restore all:  ./restore.sh $BUCKET --all"
  exit 0
fi

if [ "$TARGET" = "--all" ]; then
  markers | while read -r key vid ts; do restore_one "$key" "$vid"; done
else
  VID=$(aws s3api list-object-versions --bucket "$BUCKET" --prefix "$TARGET" \
          --query 'DeleteMarkers[?IsLatest && Key==`'"$TARGET"'`]|[0].VersionId' \
          --output text)
  if [ -z "$VID" ] || [ "$VID" = "None" ]; then
    echo "no delete marker for $TARGET in $BUCKET" >&2
    exit 1
  fi
  restore_one "$TARGET" "$VID"
fi

echo "Hit Refresh in the reader to pick the change up."
