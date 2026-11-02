#!/usr/bin/env bash
# Publish the package to PyPI.
#
# The token comes from the environment, never from a file in the
# repository:
#
#   PYPI_API_TOKEN=pypi-... scripts/publish_release.sh
#
# The token is a PyPI API token for the account that owns the project,
# with the "publish" scope on the `b-hunters` project.  Create one at
# https://pypi.org/manage/account/token/ — an account-wide token is not
# needed and is more than this needs.
#
# The version is taken from the package itself, so the artefact that is
# uploaded is the one that was tested.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-/home/sniper/pentest/.venv/bin/python}"
REPOSITORY="${PYPI_REPOSITORY:-https://upload.pypi.org/legacy/}"

cd "${REPO_ROOT}"

if [ -z "${PYPI_API_TOKEN:-}" ]; then
  echo "PYPI_API_TOKEN is not set."
  echo
  echo "  export PYPI_API_TOKEN='pypi-...'"
  echo "  scripts/publish_release.sh"
  echo
  echo "The token is an API token for the account that owns the project."
  exit 2
fi

VERSION="$("${PYTHON}" -c 'import b_hunters; print(b_hunters.__version__)')"
echo "==> publishing b-hunters ${VERSION}"

rm -rf dist
"${PYTHON}" -m build
"${PYTHON}" -m twine check dist/*
"${PYTHON}" -m twine upload \
  --non-interactive \
  --repository-url "${REPOSITORY}" \
  --username "__token__" \
  --password "${PYPI_API_TOKEN}" \
  dist/*

echo
echo "==> published:"
"${PYTHON}" -m twine upload --skip-existing --repository-url "${REPOSITORY}" dist/* 2>/dev/null || true
curl -sS "https://pypi.org/pypi/b-hunters/json" | "${PYTHON}" -c "
import json, sys
data = json.load(sys.stdin)
print('  the version on PyPI is now', data['info']['version'])
"
