#!/usr/bin/env bash
# Build the scanner worker images.
#
# The workers share one class with the platform: the `BHunters` base
# class, which carries the message contract and the helpers that put
# the target's session into a scanner's invocation.  That class is
# published on PyPI, but the published release does not always have
# the helpers the current workers use: a worker that calls
# `auth_headers(task)` against a release without it fails at runtime,
# and it fails *inside the scan*, where it is hardest to see.
#
# So the images are built against the shared class in this repository,
# not against whatever happens to be on PyPI.  The wheel is built here,
# copied into the worker's build context, and installed from there.
# Nothing is published and nothing is pinned to a version that may not
# exist.
#
# Usage:
#   scripts/build_workers.sh              # every worker
#   scripts/build_workers.sh nuclei ffuf  # only these

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPOS_ROOT="$(cd "${REPO_ROOT}/.." && pwd)"
VERSION="${BHUNTERS_WORKER_VERSION:-1.2.0}"
PYTHON="${PYTHON:-/home/sniper/pentest/.venv/bin/python}"
BUILD_DIR="$(mktemp -d)"

cleanup() {
  # The wheel is a build artefact: it must never be left behind in a
  # worker repository.
  for repo in "${REPOS_ROOT}"/B-Hunters-*; do
    rm -f "${repo}"/b_hunters-*.whl
  done
  rm -rf "${BUILD_DIR}"
}
trap cleanup EXIT

# The image name of every worker and the repository it is built from.
# The names do not follow one rule — the repository of the web
# technology worker is "Web-Technology" and the image is
# "webtechnology" — so the pairs are written down.
WORKER_REPOS=(
  "dalfox:B-Hunters-DalFox"
  "dirsearch:B-Hunters-Dirsearch"
  "ffuf:B-Hunters-Ffuf"
  "getjs:B-Hunters-GetJS"
  "gowitness:B-Hunters-gowitness"
  "jsscanner:B-Hunters-jsscanner"
  "katana:B-Hunters-Katana"
  "nmap:B-Hunters-NMap"
  "nuclei:B-Hunters-Nuclei"
  "paramspider:B-Hunters-ParamSpider"
  "sqlmap:B-Hunters-Sqlmap"
  "ssti:b-hunters-SSTI-Checker"
  "subrecon:B-Hunters-Subrecon"
  "wapiti:B-Hunters-Wapiti"
  "wayback:B-Hunters-Wayback"
  "webtechnology:B-Hunters-Web-Technology"
  "xray:B-Hunters-xray"
)

if [ "$#" -gt 0 ]; then
  SELECTED=("$@")
else
  SELECTED=()
  for pair in "${WORKER_REPOS[@]}"; do
    SELECTED+=("${pair%%:*}")
  done
fi

echo "==> building the shared class"
rm -rf "${BUILD_DIR}/b_hunters"
mkdir -p "${BUILD_DIR}/b_hunters"
cp -r "${REPO_ROOT}/b_hunters/." "${BUILD_DIR}/b_hunters/"
# The build artefacts of the source tree must not end up in the wheel.
find "${BUILD_DIR}/b_hunters" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true

cd "${BUILD_DIR}"
"${PYTHON}" -m pip wheel --no-deps -w "${BUILD_DIR}" "${REPO_ROOT}" >/dev/null
WHEEL="$(ls "${BUILD_DIR}"/b_hunters-*.whl | head -1)"
echo "    ${WHEEL}"

FAILED=()

for worker in "${SELECTED[@]}"; do
  repo=""
  for pair in "${WORKER_REPOS[@]}"; do
    if [ "${pair%%:*}" = "${worker}" ]; then
      repo="${REPOS_ROOT}/${pair#*:}"
      break
    fi
  done
  if [ -z "${repo}" ] || [ ! -d "${repo}" ]; then
    echo "==> ${worker}: no repository for it, skipping"
    continue
  fi
  if [ ! -f "${repo}/Dockerfile" ]; then
    echo "==> ${worker}: no Dockerfile, skipping"
    continue
  fi

  echo "==> ${worker}"
  name="$(basename "${WHEEL}")"
  cp "${WHEEL}" "${repo}/"

  # The build file.  The committed Dockerfile installs the published
  # release; this one installs the wheel built from this repository.
  # The wheel is copied into the image and removed again, so the image
  # carries no build artefact.
  python3 - "${repo}/Dockerfile" "${repo}/Dockerfile.local" "${name}" <<'PYTHON'
import pathlib
import sys

source, target, wheel = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), sys.argv[3]
text = source.read_text()
lines = []
for line in text.splitlines(keepends=True):
    lines.append(line)
    if "pip install" in line and "${B_HUNTERS_WHEEL}" in line:
        # The published release is installed first: it carries the
        # dependencies.  The wheel built from this repository is then
        # laid over it, so the shared class is the one this repository
        # has and the dependencies are the ones the release declares.
        #
        # The flags of the original line are carried over: an image
        # that installs into the system packages needs to be told so
        # again.
        flags = ""
        if "--break-system-packages" in line:
            flags = " --break-system-packages"
        lines.append(f"COPY {wheel} /tmp/{wheel}\n")
        lines.append(
            "RUN pip install --no-cache-dir --no-deps --force-reinstall"
            f"{flags} /tmp/{wheel} && rm -f /tmp/{wheel}\n"
        )
target.write_text("".join(lines))
PYTHON

  # One worker that fails to build must not stop the others.
  if ! (
    cd "${repo}"
    docker build -q -f Dockerfile.local -t "b-hunters-local/${worker}:${VERSION}" .
  ); then
    FAILED+=("${worker}")
  fi
  rm -f "${repo}/Dockerfile.local" "${repo}/${name}"
done

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "==> these workers did not build: ${FAILED[*]}"
  exit 1
fi

echo "==> the worker images are built"
echo
echo "    the images:"
for pair in "${WORKER_REPOS[@]}"; do
  name="${pair%%:*}"
  if docker image inspect "b-hunters-local/${name}:${VERSION}" >/dev/null 2>&1; then
    echo "      b-hunters-local/${name}:${VERSION}"
  fi
done
