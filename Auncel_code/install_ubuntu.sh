#!/usr/bin/env bash
set -euo pipefail

# Install the native packages and Python environment used by the release.
# Run this script from any directory; paths are resolved relative to the script.
RELEASE_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_PYPBC="${INSTALL_PYPBC:-0}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This installer is intended for Ubuntu or WSL Ubuntu." >&2
  exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get was not found. Use an Ubuntu installation (native or WSL)." >&2
  exit 1
fi

if [[ "${SKIP_APT:-0}" == "1" ]]; then
  echo "SKIP_APT=1: using the Ubuntu packages already installed."
else
  if ! sudo apt-get update; then
    echo "apt-get update reported a repository warning; using the available package indexes." >&2
  fi
  sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    ca-certificates \
    curl \
    git \
    python3-dev \
    python3-pip \
    python3-venv
  if [[ "${INSTALL_PYPBC}" == "1" ]]; then
    sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y \
      autoconf \
      automake \
      libgmp-dev \
      libtool \
      pkg-config
    # Ubuntu names the requested PBC development package libpbc-dev.
    if apt-cache show libpbc-dev >/dev/null 2>&1; then
      sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y libpbc-dev
    else
      echo "libpbc-dev is unavailable in the configured Ubuntu repositories; building PBC from source."
      PBC_VERSION="${PBC_VERSION:-0.5.14}"
      PBC_URL="${PBC_URL:-https://crypto.stanford.edu/pbc/files/pbc-${PBC_VERSION}.tar.gz}"
      PBC_WORK="${TMPDIR:-/tmp}/pbc-${PBC_VERSION}-release"
      rm -rf "${PBC_WORK}"
      mkdir -p "${PBC_WORK}"
      curl -fsSL "${PBC_URL}" -o "${PBC_WORK}/pbc.tar.gz"
      tar -xzf "${PBC_WORK}/pbc.tar.gz" -C "${PBC_WORK}"
      PBC_SOURCE_DIR="${PBC_WORK}/pbc-${PBC_VERSION}"
      (cd "${PBC_SOURCE_DIR}" && ./configure --prefix=/usr/local && make -j"$(nproc)")
      sudo make -C "${PBC_SOURCE_DIR}" install
      sudo ldconfig
    fi
  fi
fi

if [[ -d "${RELEASE_ROOT}/.venv" && ! -f "${RELEASE_ROOT}/.venv/.release_venv" ]]; then
  # Older versions of this installer created a shared-site environment. It
  # exposed unrelated Ubuntu packages and made pip report their conflicts.
  rm -rf "${RELEASE_ROOT}/.venv"
fi
if [[ ! -d "${RELEASE_ROOT}/.venv" ]]; then
  "${PYTHON_BIN}" -m venv "${RELEASE_ROOT}/.venv"
  touch "${RELEASE_ROOT}/.venv/.release_venv"
fi
source "${RELEASE_ROOT}/.venv/bin/activate"
python -m pip install --upgrade pip setuptools wheel
python -m pip install --no-cache-dir -r "${RELEASE_ROOT}/requirements.txt"

if [[ "${INSTALL_PYPBC}" == "1" ]]; then
  PYPBC_REPO="${PYPBC_REPO:-https://github.com/debatem1/pypbc.git}"
  PYPBC_WORK="${TMPDIR:-/tmp}/pypbc-release"
  rm -rf "${PYPBC_WORK}"
  git clone --depth 1 "${PYPBC_REPO}" "${PYPBC_WORK}"
  python -m pip install --no-cache-dir --no-build-isolation "${PYPBC_WORK}"
else
   PYPBC_SOURCE="$("${PYTHON_BIN}" -c 'import pypbc; print(pypbc.__file__)' 2>/dev/null || true)"
  if [[ -z "${PYPBC_SOURCE}" ]]; then
    echo "PYPBC was not found in the existing Ubuntu Python environment." >&2
    echo "Install it separately or rerun with INSTALL_PYPBC=1." >&2
    exit 1
  fi
  VENV_SITE="$(python -c 'import site; print(site.getsitepackages()[0])')"
  export PYPBC_SOURCE VENV_SITE
  python - <<'PY'
import os
from pathlib import Path

source = Path(os.environ['PYPBC_SOURCE']).resolve()
site = Path(os.environ['VENV_SITE'])
if source.name == '__init__.py':
    source = source.parent
target = site / source.name
if target.is_symlink() or target.is_file():
    target.unlink()
elif target.exists():
    raise RuntimeError('PYPBC target already exists: %s' % target)
target.symlink_to(source, target_is_directory=source.is_dir())
print('using preinstalled PYPBC:', source)
PY
fi
python -c "import pypbc; print('PYPBC import: OK')"

python - <<'PY'
import solcx
if not any(str(v) == "0.8.24" for v in solcx.get_installed_solc_versions()):
    solcx.install_solc("0.8.24")
print("Python dependencies and solc 0.8.24 are ready")
PY

cd "${RELEASE_ROOT}"
python -c "import pypbc, web3, eth_tester, solcx; print('runtime imports: OK')"
python -m compileall -q src experiments baselines crypto
echo "Ubuntu environment is ready in ${RELEASE_ROOT}/.venv"
