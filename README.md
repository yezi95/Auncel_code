# Reproducible experiments

This directory is the package for the Auncel. The executable protocol runtime is in
`src/`; `crypto/pvss.py` contains the PYPBC pairing operations.
The package contains source code, configuration, contract code, and input data
only. It does not contain historical results, logs, virtual environments,
editor state, compiler caches, or plotting code.

## Environment

The commands below target Ubuntu 20.04. The data file
is `data/data.csv`; paths are resolved from the package root.

```bash
python data/xblock.py /path/to/BlockTransaction.csv --output data/data.csv \
  --count 100000 --seed 42
```

```bash
cd /path/to/Auncel_code
bash install_ubuntu.sh
source .venv/bin/activate
```

`install_ubuntu.sh` creates the Python virtual environment, installs the pinned
Python requirements, and prepares solc 0.8.24. 

If PYPBC and the PBC development library must be built on a new Ubuntu host,
use the optional branch:

```bash
INSTALL_PYPBC=1 bash install_ubuntu.sh
```
For a manual installation, the equivalent commands are:

```bash
sudo apt-get update
sudo apt-get install -y build-essential ca-certificates curl git python3-dev \
  python3-pip python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install --no-cache-dir -r requirements.txt
cd /path/to/Auncel_code
python -c "import pypbc; print('PYPBC ready')"
python -c "import solcx; solcx.install_solc('0.8.24')"
```

The pairing parameter file is `crypto/pbc.params`. The Solidity contract is
compiled locally by the experiment runner with solc 0.8.24. The `data.csv`
checksum and column mapping are checked before an experiment starts.

## Experiments

`configs/experiments.yaml` is JSON syntax accepted as YAML. The fixed settings
are 500 transactions per run, `k = 2, 4, 6, 8`, seeds 1 through 10, and ten
independent runs for every configuration. Results are written only under the
directory passed with `--results-dir`; each run stores raw observations and a
mean ± sample-SD CSV.

GSSC transactions use the configured gas price of 2 Gwei. The value is recorded
in `configs/system.yaml` and applied to every measured contract call.

Run the complete TPS/latency campaign (both schemes, both studies):

```bash
python experiments/reproduce_all.py --study all --scheme both \
  --results-dir results/campaign
```

The first study fixes the cross-shard ratio at 0.4 and compares `k = 2, 4, 6,
8`. The second fixes `k = 4` and sweeps the cross-shard ratio from 0.1 through
0.8. 

To run one scheme or one study, use `--scheme Auncel` or `--scheme DCchain`,
and `--study shards` or `--study ratios`. ：

```bash
python experiments/reproduce_all.py --check
python experiments/reproduce_all.py --plan
```

## incentive experiment

`experiments/revised_incentive.py` is the Fig. 5 revised-incentive Monte Carlo
experiment. It writes numeric CSV and JSON observations under
`results/incentive/processed`:

```bash
python experiments/revised_incentive.py
```


## Output layout

Each campaign directory contains `raw/` per-seed protocol traces and
`processed/` mean-SD tables. 
