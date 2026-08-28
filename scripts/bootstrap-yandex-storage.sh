#!/usr/bin/env bash

# Do not inherit caller-supplied xtrace while handling credential values.
set +x
set -Eeuo pipefail
umask 077

readonly BUCKET="routing.akent.site"
readonly DOMAIN="https://routing.akent.site"
readonly MANIFEST_URL="$DOMAIN/manifest.json"
readonly S3_ENDPOINT="https://storage.yandexcloud.net"
readonly GITHUB_ENVIRONMENT="production"

usage() {
    cat <<'EOF'
Usage: scripts/bootstrap-yandex-storage.sh [--check | --permissions | --help]

  --check        Verify Yandex bucket access, custom-domain HTTPS readiness,
                 and production GitHub environment secrets. This is the
                 default and is read-only.
  --permissions  Print the least-privilege setup requirements.
  --help         Show this help.

This script never creates or changes the bucket, DNS, website hosting,
public access, or TLS certificate. Those are user-owned prerequisites.
EOF
}

permissions() {
    cat <<'EOF'
Yandex runtime service account:
  - storage.editor on the routing.akent.site bucket only.
  - Create static access keys and store their values as the production GitHub
    environment secrets YANDEX_S3_ACCESS_KEY_ID and
    YANDEX_S3_SECRET_ACCESS_KEY.

The user owns bucket creation, DNS, website hosting/public access, and the
custom-domain TLS certificate. This readiness check does not provision or
modify any of them.
EOF
}

die() {
    printf 'bootstrap-yandex-storage: error: %s\n' "$*" >&2
    exit 1
}

mode="check"
while (($#)); do
    case "$1" in
        --check)
            mode="check"
            ;;
        --permissions)
            permissions
            exit 0
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
    shift
done

[[ "$mode" == "check" ]] || die "unsupported mode"

required_variables=(
    GITHUB_REPOSITORY
    YANDEX_S3_ACCESS_KEY_ID
    YANDEX_S3_SECRET_ACCESS_KEY
)
for variable in "${required_variables[@]}"; do
    [[ -n "${!variable:-}" ]] || die "missing required environment variable: $variable"
done

[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || \
    die "GITHUB_REPOSITORY must be OWNER/NAME"

for command in curl aws gh python3; do
    command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

temporary_directory="$(mktemp -d)" || die "could not create a temporary directory"
manifest_file="$temporary_directory/manifest.json"
secret_list_file="$temporary_directory/environment-secrets.txt"

cleanup() {
    rm -f -- "$manifest_file" "$secret_list_file"
    rmdir -- "$temporary_directory" 2>/dev/null || true
}
trap cleanup EXIT

set +e
http_status="$(
    curl --silent --show-error --location \
        --connect-timeout 15 --max-time 60 \
        --output "$manifest_file" --write-out '%{http_code}' \
        "$MANIFEST_URL"
)"
curl_status=$?
set -e
if ((curl_status != 0)); then
    die "custom-domain manifest probe failed at the network boundary (curl status $curl_status)"
fi

case "$http_status" in
    200)
        if ! python3 - "$manifest_file" <<'PY'
import json
import sys

try:
    document = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if isinstance(document, dict) else 1)
PY
        then
            die "custom-domain manifest probe returned invalid JSON"
        fi
        ;;
    404)
        ;;
    *)
        die "custom-domain manifest probe failed with HTTP $http_status"
        ;;
esac

if ! AWS_ACCESS_KEY_ID="$YANDEX_S3_ACCESS_KEY_ID" \
    AWS_SECRET_ACCESS_KEY="$YANDEX_S3_SECRET_ACCESS_KEY" \
    aws s3api head-bucket --bucket "$BUCKET" --endpoint-url "$S3_ENDPOINT"; then
    die "could not access Yandex Object Storage bucket $BUCKET"
fi

if ! gh api --silent "repos/$GITHUB_REPOSITORY/environments/$GITHUB_ENVIRONMENT" \
    >/dev/null; then
    die "could not inspect GitHub environment $GITHUB_ENVIRONMENT"
fi
if ! gh secret list --repo "$GITHUB_REPOSITORY" --env "$GITHUB_ENVIRONMENT" \
    --json name --jq '.[].name' >"$secret_list_file"; then
    die "could not inspect GitHub environment secrets"
fi
for secret in YANDEX_S3_ACCESS_KEY_ID YANDEX_S3_SECRET_ACCESS_KEY; do
    grep -Fx -- "$secret" "$secret_list_file" >/dev/null || \
        die "GitHub environment $GITHUB_ENVIRONMENT is missing $secret"
done

printf 'Yandex Object Storage readiness verified for %s\n' "$DOMAIN"
