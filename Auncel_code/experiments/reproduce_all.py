"""Run the Auncel and DCchain experiments."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def campaign_cases(study, config):
    if study == 'shards':
        return [(k, config['fixed_cross_shard_ratio']) for k in config['shard_counts']]
    return [(config['ratio_sweep_shards'], alpha) for alpha in config['cross_shard_ratios']]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--study', choices=['shards', 'ratios', 'all'], default='all')
    parser.add_argument('--scheme', choices=['Auncel', 'DCchain', 'both'], default='both')
    parser.add_argument('--seeds', nargs='+', type=int)
    parser.add_argument('--transactions', type=int)
    parser.add_argument('--ks', nargs='+', type=int, help='Override shard-count sweep')
    parser.add_argument('--alphas', nargs='+', type=float, help='Override cross-shard ratio sweep')
    parser.add_argument('--results-dir', type=Path, default=Path('results'))
    parser.add_argument('--plan', action='store_true', help='Print configurations without running protocols')
    parser.add_argument('--check', action='store_true', help='Check configuration, dataset and runtime dependencies')
    parser.add_argument('--fractional-capacity-load', action='store_true')
    parser.add_argument('--fixed-capacity-blocks', type=int)
    parser.add_argument('--dcchain-tps-mode', choices=['aggregate', 'common', 'committed'])
    args = parser.parse_args()
    config = json.loads((ROOT / 'configs/experiments.yaml').read_text(encoding='utf-8'))
    if args.ks is not None:
        if not args.ks or any(k < 2 or k > 64 for k in args.ks) or len(set(args.ks)) != len(args.ks):
            parser.error('Shard counts must be distinct integers in [2,64]')
        config['shard_counts'] = args.ks
    if args.alphas is not None:
        if any(not 0 <= alpha <= 1 for alpha in args.alphas) or len(set(args.alphas)) != len(args.alphas):
            parser.error('Cross-shard ratios must be distinct values in [0,1]')
        config['cross_shard_ratios'] = args.alphas
    result_root = ROOT / args.results_dir
    if args.check:
        import hashlib
        import importlib
        import sys
        sys.path.insert(0, str(ROOT))
        system = json.loads((ROOT / 'configs/system.yaml').read_text(encoding='utf-8'))
        data = ROOT / system['dataset']['path']
        if hashlib.sha256(data.read_bytes()).hexdigest() != system['dataset']['sha256']:
            raise ValueError('Dataset checksum mismatch')
        for name in ('numpy', 'scipy', 'web3', 'eth_tester', 'solcx', 'Crypto', 'pypbc'):
            importlib.import_module(name)
        from src.gssc import compile_contract
        compile_contract(ROOT)
        print('Configuration, dataset and contract compilation checks passed')
        return
    seeds = args.seeds if args.seeds is not None else config['seeds']
    transactions = args.transactions if args.transactions is not None else config['transactions_per_run']
    if transactions <= 0 or not seeds or len(seeds) != len(set(seeds)):
        parser.error('Use a positive transaction count and distinct seeds')
    studies = ['shards', 'ratios'] if args.study == 'all' else [args.study]
    schemes = ['Auncel', 'DCchain'] if args.scheme == 'both' else [args.scheme]
    jobs = [(study, k, alpha, scheme) for study in studies
            for k, alpha in campaign_cases(study, config) for scheme in schemes]
    if args.plan:
        print(json.dumps({'transactions_per_run': transactions, 'seeds': seeds,
              'runs_per_configuration': len(seeds), 'total_runs': len(jobs) * len(seeds),
              'jobs': [dict(study=s, k=k, alpha=a, scheme=n) for s, k, a, n in jobs]}, indent=2))
        return
    for study, k, alpha, scheme in jobs:
        output = result_root / study / f'k{k}_alpha{alpha:.1f}' / scheme
        argv = ['--ks', str(k), '--alpha', str(alpha), '--transactions', str(transactions),
                '--seeds', *map(str, seeds), '--results-dir', str(output)]
        if args.fractional_capacity_load:
            argv.append('--fractional-capacity-load')
        if args.fixed_capacity_blocks is not None:
            argv.extend(['--fixed-capacity-blocks', str(args.fixed_capacity_blocks)])
        if scheme == 'DCchain' and args.dcchain_tps_mode:
            argv.extend(['--tps-mode', args.dcchain_tps_mode])
        (run_auncel if scheme == 'Auncel' else run_dcchain)(argv)

def run_auncel(argv):
    import argparse, copy, csv, hashlib, json, math, random, statistics, sys
    from dataclasses import asdict
    from pathlib import Path
    ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT))
    from src.gssc import compile_contract
    from src.metrics import write_csv
    from src.nodes import seed_for
    from src.sharding import assign_nodes
    from src.simulator import run
    from src.transaction import read_dataset, workload
    FORMAL_KS = [2, 4, 6, 8]
    FORMAL_SEEDS = list(range(1, 11))
    FORMAL_TRANSACTIONS = 500

    def _finite(value):
        try:
            return math.isfinite(float(value))
        except (TypeError, ValueError):
            return False

    def _sample_sd(values):
        values = [float(v) for v in values if _finite(v)]
        return statistics.stdev(values) if len(values) > 1 else 0.0

    def _balanced_arbitration_mapping(txs, k, seed, dispute_probability):
        """Label a balanced, reproducible ARB subset of the existing rows."""
        candidates = [tx for tx in txs if tx.cross]
        dispute_count = round(len(candidates) * float(dispute_probability))
        if dispute_count <= 0:
            return ({}, [0] * k)
        if dispute_count > len(candidates):
            raise ValueError('ARB subset exceeds cross-shard workload')
        rng = random.Random(seed_for(seed, 'balanced-arbitration-mapping:%d' % k))
        rng.shuffle(candidates)
        remaining = list(candidates)
        load = [0] * k
        selected = []
        while len(selected) < dispute_count:
            scored = []
            for tx in remaining:
                projected = list(load)
                for shard in {int(tx.source), int(tx.target)}:
                    projected[shard] += 1
                mean = sum(projected) / float(k)
                score = (max(projected) - min(projected), max(projected), sum(((value - mean) ** 2 for value in projected)), rng.random())
                scored.append((score, tx))
            _, chosen = min(scored, key=lambda item: item[0])
            selected.append(chosen)
            remaining.remove(chosen)
            for shard in {int(chosen.source), int(chosen.target)}:
                load[shard] += 1
        base, extra = divmod(dispute_count, 3)
        modes = [mode for mode in (1, 2, 3) for _ in range(base + (1 if mode <= extra else 0))]
        rng.shuffle(modes)
        mapping = {tx.id: mode for tx, mode in zip(selected, modes)}
        for tx in txs:
            tx.fault = mapping.get(tx.id, 0)
        return (mapping, load)

    def _read_transaction_rows(path):
        with path.open(encoding='utf-8', newline='') as handle:
            return list(csv.DictReader(handle))

    def _local_latency(row, epoch_stage):
        """Use measured pre-epoch latency and avoid adding epoch twice."""
        local = row.get('latency_before_epoch_finality_s')
        if _finite(local):
            return float(local)
        full = row.get('latency_s')
        if not _finite(full):
            raise ValueError('transaction row has no latency_s')
        return max(0.0, float(full) - float(epoch_stage))

    def _batch_tail_values(output, txs, result):
        """Per-mode mean terminal latency from the shared transaction field."""
        epoch = float(result.get('epoch_global_finality_duration_s', 0.0) or 0.0)
        rows = {row['id']: row for row in _read_transaction_rows(output / 'transactions.csv')}
        tails = {}
        local_tails = {}
        for mode in (1, 2, 3):
            selected = [tx for tx in txs if tx.cross and tx.fault == mode]
            full_values = [float(rows[tx.id]['latency_s']) for tx in selected]
            local_values = [_local_latency(rows[tx.id], epoch) for tx in selected]
            local_tails[mode] = statistics.mean(local_values) if local_values else None
            tails[mode] = statistics.mean(full_values) if full_values else None
        return (tails, local_tails, epoch)

    def main():
        parser = argparse.ArgumentParser(description='Run the configured experiment.')
        parser.add_argument('--ks', nargs='+', type=int, default=FORMAL_KS)
        parser.add_argument('--seeds', nargs='+', type=int, default=FORMAL_SEEDS)
        parser.add_argument('--repeats-per-seed', type=int, default=1, help='fresh executions for each (k, seed); defaults to 1')
        parser.add_argument('--transactions', type=int, default=None, help='fixed total transactions for every k; defaults to 500')
        parser.add_argument('--transactions-per-shard', type=int, default=None, help='total workload is k times this value; mutually exclusive with --transactions')
        parser.add_argument('--alpha', type=float, default=None, help='cross-shard ratio; defaults to the configured value')
        parser.add_argument('--fractional-capacity-load', action='store_true', help="for a fixed-k ratio study, split each cross-shard transaction's capacity occupancy across its touched shards; the default k-sweep metric is unchanged")
        parser.add_argument('--fixed-capacity-blocks', type=int, default=None, help='for a ratio study, use this fixed number of block intervals in the capacity reporting window; protocol block admission is unchanged and overload is recorded')
        parser.add_argument('--rate', type=int, default=None, help='submission rate; defaults to the first configured rate')
        parser.add_argument('--results-dir', default='results/auncel')
        args = parser.parse_args(argv)
        if any((k < 2 or k > 64 for k in args.ks)) or len(set(args.ks)) != len(args.ks):
            raise ValueError('k must be distinct and in [2,64]')
        if not args.seeds or len(set(args.seeds)) != len(args.seeds):
            raise ValueError('seeds must be non-empty and distinct')
        if args.repeats_per_seed < 1:
            raise ValueError('--repeats-per-seed must be positive')
        if args.transactions is not None and args.transactions_per_shard is not None:
            raise ValueError('Use either --transactions or --transactions-per-shard, not both')
        if args.transactions is not None and args.transactions <= 0:
            raise ValueError('--transactions must be positive')
        if args.transactions_per_shard is not None and args.transactions_per_shard <= 0:
            raise ValueError('--transactions-per-shard must be positive')
        if args.fixed_capacity_blocks is not None and args.fixed_capacity_blocks <= 0:
            raise ValueError('--fixed-capacity-blocks must be positive')
        result_root = Path(args.results_dir)
        if not result_root.is_absolute():
            result_root = ROOT / result_root
        if result_root.exists():
            existing = [p.name for p in result_root.iterdir() if p.name not in {'run.log'}]
            if existing:
                raise RuntimeError('Use a new empty results directory; existing runs are never mixed: %s' % existing)
        raw_root = result_root / 'raw'
        raw_root.mkdir(parents=True, exist_ok=True)
        config = json.loads((ROOT / 'configs/system.yaml').read_text(encoding='utf-8'))
        experiments = json.loads((ROOT / 'configs/experiments.yaml').read_text(encoding='utf-8'))
        rows, data_manifest = read_dataset(ROOT, config['dataset'])
        artifact = compile_contract(ROOT)
        fixed_count = args.transactions if args.transactions is not None else FORMAL_TRANSACTIONS
        count_for_k = lambda k: args.transactions_per_shard * k if args.transactions_per_shard is not None else fixed_count
        transactions_by_k = {str(k): count_for_k(k) for k in args.ks}
        alpha = args.alpha if args.alpha is not None else float(experiments['fixed_cross_shard_ratio'])
        rate = args.rate or int(experiments['offered_tps'][0])
        if not 0 <= alpha <= 1:
            raise ValueError('alpha must be in [0,1]')
        manifest = dict(configuration=config, experiment=dict(ks=args.ks, seeds=args.seeds, transactions=fixed_count if args.transactions_per_shard is None else None, transactions_by_k=transactions_by_k, transactions_per_shard=args.transactions_per_shard, cross_shard_ratio=alpha, submission_rate=rate, capacity_load_mode='fractional' if args.fractional_capacity_load else 'physical', fixed_capacity_blocks=args.fixed_capacity_blocks, scheme='Auncel only', repetitions=len(args.seeds), repeats_per_seed=args.repeats_per_seed, total_runs=len(args.ks) * len(args.seeds) * args.repeats_per_seed), dataset=data_manifest, dataset_sha256=config['dataset']['sha256'], source_files={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for folder in ('src', 'contracts', 'configs', 'experiments') for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in str(p)}, protocol_version='native-principal-shard-parallel-epoch-ait-q-threshold-v5-global-finality-stage-duration', workload_policy='deterministic seeded selection of distinct real XBlock rows; exact cross-shard ratio; greedy balancing of per-shard participation', metrics='TPS=terminal transactions/global service makespan; the same denominator and terminal set are used for Auncel and DCchain; per-shard CPU, validator CPU, and block-capacity bounds remain diagnostic; ' + ('fixed-k ratio mode uses fractional cross-shard capacity occupancy only when --fractional-capacity-load is supplied; the default k-sweep uses physical occupancy; ' if args.fractional_capacity_load else '') + ('--fixed-capacity-blocks uses a fixed capacity reporting window and records normal_shard_capacity_overload; protocol block admission remains measured; ' if args.fixed_capacity_blocks is not None else '') + "each shard/GSSC/arbitrator node has an independent available_time and only measured CPU advances it; observed_workload_tps uses the same service makespan (diagnostic alias); Auncel consensus=one unchanged-primitive PBFT certificate per shard block, executed in independent shard verifier lanes, plus per-transaction state checks; arbitration ballot certificates are queued and submitted in epoch-side batches (with conflict/expiry flushes when account safety requires); latency=the ARB-1/2/3 fields below use the mean terminal transaction latency for that mode plus one epoch-finality stage; PBFT latency is the measured duration of the transaction's own block slot, joined across involved shard lanes with max; epoch root collection, verification, aggregation and one GSSC finalization are included once in the reported latency, but remain outside TPS; mean +/- sample SD")
        manifest['protocol_version'] = 'native-principal-shard-parallel-epoch-ait-q-threshold-v7-balanced-auncel-worker-dispatch'
        manifest['contract_execution_model'] = ('measured GSSC read/write CPU is assigned to each involved shard lane; '
            'cross-shard operations wait for the maximum lane-ready time; actual PyEVM state transitions remain sequential')
        manifest['auncel_worker_dispatch'] = 'Auncel shard-local service chooses the honest replica with the least accumulated measured NODE-lane CPU in the shard executing the work; DCchain dispatch is unchanged'
        (raw_root / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        observations = []
        total = len(args.ks) * len(args.seeds) * args.repeats_per_seed
        completed = 0
        for k in args.ks:
            for seed in args.seeds:
                count = count_for_k(k)
                txs = workload(rows, k, alpha, seed, count, rate, 0.0)
                arb_mapping, arb_shard_load = _balanced_arbitration_mapping(txs, k, seed, config['dispute_probability_given_cross_shard'])
                workload_load = [sum((1 for tx in txs if shard in {tx.source, tx.target})) for shard in range(k)]
                for repeat in range(1, args.repeats_per_seed + 1):
                    case_name = 'k%d_seed%d' % (k, seed) if args.repeats_per_seed == 1 else 'k%d_seed%d_repeat%d' % (k, seed, repeat)
                    case = raw_root / case_name
                    case.mkdir(parents=True, exist_ok=True)
                    shards = assign_nodes(k, seed, config)
                    write_csv(case / 'node_assignment.csv', [n.record() for shard in shards for n in shard])
                    write_csv(case / 'workload.csv', [{key: value for key, value in asdict(tx).items() if key not in ('history', 'state')} for tx in txs])
                    (case / 'inputs.json').write_text(json.dumps({'k': k, 'seed': seed, 'repeat': repeat, 'transactions': count, 'cross_shard_ratio_requested': alpha, 'cross_shard_ratio_actual': sum((tx.cross for tx in txs)) / len(txs), 'shard_transaction_load': workload_load, 'shard_transaction_load_range': max(workload_load) - min(workload_load), 'shard_transaction_load_sd': statistics.stdev(workload_load) if len(workload_load) > 1 else 0.0, 'arb_mapping': arb_mapping, 'arb_shard_load': arb_shard_load, 'arb_shard_load_range': max(arb_shard_load) - min(arb_shard_load) if arb_shard_load else 0, 'arb_shard_load_sd': statistics.stdev(arb_shard_load) if len(arb_shard_load) > 1 else 0.0, 'workload_sha256': hashlib.sha256((case / 'workload.csv').read_bytes()).hexdigest(), 'assignment_sha256': hashlib.sha256((case / 'node_assignment.csv').read_bytes()).hexdigest()}, indent=2), encoding='utf-8')
                    output = case / 'Auncel'
                    print('RUN Auncel k=%d seed=%d repeat=%d/%d transactions=%d/%d' % (k, seed, repeat, args.repeats_per_seed, count, count), flush=True)
                    result = run(ROOT, artifact, shards, copy.deepcopy(txs), config, seed, 'Auncel', output, capacity_load_mode='fractional' if args.fractional_capacity_load else None, fixed_capacity_blocks=args.fixed_capacity_blocks)
                    result['auncel_worker_dispatch'] = 'least accumulated measured NODE-lane CPU among honest replicas in the shard executing the work'
                    result['capacity_load_mode'] = 'fractional' if args.fractional_capacity_load else 'physical'
                    tails, local_tails, epoch_stage = _batch_tail_values(output, txs, result)
                    observation = dict(scheme='Auncel', k=k, seed=seed, repeat=repeat, transactions=count, cross_shard_ratio=alpha, submission_rate=rate, **result)
                    for mode in (1, 2, 3):
                        observation['arb%d_mean_transaction_latency_s' % mode] = result.get('arb%d_latency_s' % mode)
                        observation['arb%d_local_tail_latency_s' % mode] = local_tails[mode]
                        observation['arb%d_latency_s' % mode] = tails[mode]
                    observation['batch_tail_epoch_finality_s'] = epoch_stage
                    observation['arb_mapping'] = json.dumps(arb_mapping, sort_keys=True)
                    observation['arb_shard_load'] = json.dumps(arb_shard_load)
                    observation['arb_shard_load_range'] = max(arb_shard_load) - min(arb_shard_load) if arb_shard_load else 0
                    observation['arb_shard_load_sd'] = _sample_sd(arb_shard_load)
                    observations.append(observation)
                    write_csv(raw_root / 'observations.csv', observations)
                    completed += 1
                    print('DONE %d/%d' % (completed, total), flush=True)
        metrics = ['transactions', 'throughput_tps', 'service_capacity_tps', 'observed_workload_tps', 'committed_throughput_tps', 'transaction_success_rate', 'global_service_makespan_s', 'active_service_makespan_s', 'active_service_target_s', 'all_terminal_completion_tps', 'normal_service_completed', 'normal_service_makespan_s', 'pbft_single_parallel_service_s', 'fixed_capacity_blocks', 'normal_shard_capacity_overload_count', 'active_service_target_met', 'gssc_clock_s', 'gssc_evm_cpu_total_s', 'gssc_wait_total_s', 'gssc_call_count', 'epoch_finalization_service_s', 'epoch_global_finality_duration_s', 'epoch_global_finality_wait_s_mean', 'normal_epoch_completion_latency_s', 'normal_native_completion_latency_s', 'auncel_completion_latency_s', 'auncel_cross_shard_latency_count', 'gssc_arbitration_batch_calls', 'gssc_arbitration_batched_proofs', 'gssc_arbitration_batch_fallbacks', 'latency_adjustment_s', 'background_verifier_latency_s', 'background_verifier_network_wait_s', 'arbitration_crypto_latency_s', 'arb1_latency_s', 'arb2_latency_s', 'arb3_latency_s', 'arb1_mean_transaction_latency_s', 'arb2_mean_transaction_latency_s', 'arb3_mean_transaction_latency_s', 'arb1_local_tail_latency_s', 'arb2_local_tail_latency_s', 'arb3_local_tail_latency_s', 'batch_tail_epoch_finality_s', 'arb_shard_load_range', 'arb_shard_load_sd', 'arb1_count', 'arb2_count', 'arb3_count', 'total_messages', 'total_bytes', 'shard_transaction_load_mean', 'shard_transaction_load_sd', 'shard_transaction_load_range']
        per_seed = []
        for k in args.ks:
            for seed in args.seeds:
                group = [row for row in observations if row['k'] == k and row['seed'] == seed]
                item = dict(scheme='Auncel', k=k, seed=seed, repeats=len(group), cross_shard_ratio=alpha, submission_rate=rate)
                for metric in metrics:
                    values = [row[metric] for row in group if isinstance(row.get(metric), (int, float)) and (not isinstance(row.get(metric), bool)) and math.isfinite(float(row[metric]))]
                    if values:
                        item[metric] = statistics.mean(values)
                        item[metric + '_within_seed_sd'] = statistics.stdev(values) if len(values) > 1 else 0.0
                        item[metric + '_within_seed_n'] = len(values)
                per_seed.append(item)
        aggregate = []
        for k in args.ks:
            group = [row for row in per_seed if row['k'] == k]
            item = dict(scheme='Auncel', k=k, cross_shard_ratio=alpha, submission_rate=rate, repetitions=len(group), repeats_per_seed=args.repeats_per_seed, total_runs=sum((row['repeats'] for row in group)))
            for metric in metrics:
                values = [row[metric] for row in group if isinstance(row.get(metric), (int, float)) and (not isinstance(row.get(metric), bool)) and math.isfinite(float(row[metric]))]
                if values:
                    item[metric + '_mean'] = statistics.mean(values)
                    item[metric + '_sd'] = statistics.stdev(values) if len(values) > 1 else 0.0
                    item[metric + '_n'] = len(values)
            aggregate.append(item)
        processed = result_root / 'processed'
        processed.mkdir(parents=True, exist_ok=True)
        write_csv(raw_root / 'per_seed_mean.csv', per_seed)
        write_csv(processed / 'auncel_k_mean_sd.csv', aggregate)
        (processed / 'metric_definitions.json').write_text(json.dumps({'tps': "service_capacity_tps = terminal transactions / global service makespan for both schemes; terminal includes COMMIT and ABORT, and arbitration outcomes use the same denominator", 'latency': "arb1_latency_s/arb2_latency_s/arb3_latency_s = mean terminal transaction latency in that mode plus one measured epoch-global finality duration; the underlying value includes the transaction's PBFT slot, background verifier/network work, PVSS, propagation, GSSC, and the mode wait", 'cross_shard_completion_latency': 'auncel_completion_latency_s uses the same definition as dcchain_completion_latency_s: mean global_end_to_end_latency_s (falling back to end_to_end_latency_s, then latency_s) over terminal cross-shard transactions (COMMIT or ABORT), including one measured global-finality stage; no fixed delay or scaling', 'mean_transaction_latency_audit': "arb1/2/3_mean_transaction_latency_s retain the simulator's per-transaction values for audit", 'global_finality_latency': 'Auncel latency additionally includes the real epoch barrier after all local decisions: per-shard AIT root construction, root proposal/vote propagation and verification, root aggregation, and one GSSC finalizeEpoch receipt. This is a latency-only completion metric and is excluded from service_capacity_tps', 'gssc': 'every cross-shard transaction is registered and finalized by GSSC; principal release remains certified by the source/target shard ledgers; terminal ballot proofs are batch-submitted per epoch; each shard builds one local AIT root and GSSC commits the aggregated epoch root once', 'arbitration_batching': 'request() remains immediate for account locking and deadlines; authenticated ballot proofs remain deferred until account conflict, expiry guard, or epoch batch; no unconditional per-transaction proof flush', 'pbft_pipeline': "each shard's real PBFT block certificates are built on independent network lanes concurrently; each transaction uses its own shard/slot readiness and block capacity/interval", 'threshold_timing': 'PVSS and arbitration committee work executes on independent node resources; the q-th valid response advances causal completion while all transmitted messages remain counted', 'statistics': 'each seed is first averaged over repeats_per_seed fresh executions; reported mean and sample standard deviation (ddof=1) are then calculated over the requested seed means', 'workload_balance': 'each selected transaction counts once for every involved shard; total workload selection is unchanged and the fixed ARB subset additionally minimizes its post-selection shard-load range; ARB-1/2/3 labels are balanced as evenly as possible', 'workload_scaling': 'with --transactions-per-shard=b, total transactions are b*k for each k; all rows remain distinct real XBlock records'}, indent=2), encoding='utf-8')
        print('k,transactions,service_capacity_tps_mean,service_capacity_tps_sd,observed_workload_tps_mean,epoch_global_finality_wait_s_mean,normal_latency_mean,auncel_completion_latency_s_mean,auncel_completion_latency_s_sd,arb1_latency,arb2_latency,arb3_latency', flush=True)
        for item in aggregate:
            print('%d,%d,%.9f,%.9f,%s,%s,%s,%s,%s,%s,%s,%s' % (item['k'], item.get('transactions_mean', 0), item.get('service_capacity_tps_mean', float('nan')), item.get('service_capacity_tps_sd', float('nan')), item.get('observed_workload_tps_mean', float('nan')), item.get('epoch_global_finality_wait_s_mean', float('nan')), item.get('normal_native_completion_latency_s_mean', ''), item.get('auncel_completion_latency_s_mean', ''), item.get('auncel_completion_latency_s_sd', ''), item.get('arb1_latency_s_mean', ''), item.get('arb2_latency_s_mean', ''), item.get('arb3_latency_s_mean', '')), flush=True)
        print('AUNCEL_K_SWEEP_PASS', result_root, flush=True)
    main()

def run_dcchain(argv):
    import argparse
    import copy
    import csv
    import hashlib
    import json
    import math
    import statistics
    import sys
    from collections import defaultdict
    from dataclasses import asdict
    from pathlib import Path
    ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(ROOT))
    from src.metrics import write_csv
    from src.sharding import assign_nodes
    from src.simulator import run
    from src.transaction import read_dataset, workload
    FORMAL_KS = [2, 4, 6, 8]
    FORMAL_SEEDS = list(range(1, 11))
    FORMAL_TRANSACTIONS = 500

    def _is_true(value):
        return str(value).strip().lower() in {'1', 'true', 'yes'}

    def _augment_dcchain_latency(output):
         tx_path = output / 'transactions.csv'
        rows = list(csv.DictReader(tx_path.open(encoding='utf-8')))
        tasks = defaultdict(list)
        events_path = output / 'resource_service_events.csv'
        if events_path.exists():
            for event in csv.DictReader(events_path.open(encoding='utf-8')):
                tx_id = str(event.get('tx', ''))
                if tx_id and tx_id != '__epoch__':
                    tasks[tx_id].append(event)
        accounting = json.loads((output / 'service_accounting.json').read_text(encoding='utf-8'))
        global_cpu_finish = float(accounting.get('protocol_active_makespan_s', accounting.get('global_service_makespan_s', 0.0)))
        block_horizon = max((float(v) for v in accounting.get('block_capacity_horizons_s', [])), default=0.0)
        causal_finish = float(accounting.get('causal_finish_makespan_s', 0.0))
        dcchain_finality_stage = float(accounting.get('dcchain_global_finality_duration_s', 0.0) or 0.0)
        dcchain_finality_finish = accounting.get('dcchain_global_finality_finish_s')
        try:
            dcchain_finality_finish = float(dcchain_finality_finish) if dcchain_finality_finish not in (None, '') else 0.0
        except (TypeError, ValueError):
            dcchain_finality_finish = 0.0
        has_global_endpoint = dcchain_finality_finish > 0.0
        global_confirmation = dcchain_finality_finish if has_global_endpoint else max(global_cpu_finish, block_horizon)

        def event_time(event, *keys):
               for key in keys:
                value = event.get(key)
                if value not in (None, ''):
                    try:
                        value = float(value)
                    except (TypeError, ValueError):
                        continue
                    if math.isfinite(value):
                        return value
            return None
        for row in rows:
            tx_id = str(row['id'])
            task_rows = tasks.get(tx_id, [])
            starts = [value for e in task_rows if (value := event_time(e, 'causal_start_s', 'start_s', 'service_start_s')) is not None]
            finishes = [value for e in task_rows if (value := event_time(e, 'causal_finish_s', 'finish_s', 'service_finish_s')) is not None]
            cpu_work = sum((float(e.get('cpu_seconds', e.get('seconds', 0.0))) for e in task_rows))
            active_path = max(finishes) - min(starts) if starts and finishes else 0.0
            submitted = float(row.get('submitted', 0.0) or 0.0)
            admitted = float(row.get('admitted', 0.0) or 0.0)
            global_wait = max(0.0, global_confirmation - submitted) if has_global_endpoint else max(0.0, global_confirmation)
            row['dcchain_global_admission_wait_s'] = max(0.0, global_confirmation - admitted)
            row['dcchain_active_cpu_work_s'] = cpu_work
            row['dcchain_active_cpu_path_s'] = active_path
            row['dcchain_global_block_confirmation_s'] = global_confirmation
            row['dcchain_global_finality_duration_s'] = dcchain_finality_stage
            row['dcchain_global_confirmation_wait_s'] = global_wait
            row['dcchain_completion_latency_s'] = float(
                row.get('global_end_to_end_latency_s') or row.get('end_to_end_latency_s')
                or row['latency_s'])
        write_csv(tx_path, rows)
        return (rows, dict(global_confirmation_s=global_confirmation, global_cpu_finish_s=global_cpu_finish, final_block_horizon_s=block_horizon, global_causal_finish_s=causal_finish, dcchain_global_finality_duration_s=dcchain_finality_stage, dcchain_global_finality_finish_s=dcchain_finality_finish))

    def _cross_shard_latency(output):
        """Return (mean enhanced latency, count) for terminal cross-shard rows."""
        rows = list(csv.DictReader((output / 'transactions.csv').open(encoding='utf-8')))
        selected = [row for row in rows if _is_true(row.get('cross', False)) and row.get('state') in {'COMMIT', 'ABORT'}]
        values = [float(row['dcchain_completion_latency_s']) for row in selected]
        return (statistics.mean(values) if values else None, len(values))

    def _sample_sd(values):
        return statistics.stdev(values) if len(values) > 1 else 0.0

    def main():
        parser = argparse.ArgumentParser(description='Run the configured experiment.')
        parser.add_argument('--ks', nargs='+', type=int, default=FORMAL_KS)
        parser.add_argument('--seeds', nargs='+', type=int, default=FORMAL_SEEDS)
        parser.add_argument('--transactions', type=int, default=None, help='fixed total real transactions for every k; defaults to 500')
        parser.add_argument('--alpha', type=float, default=None, help="cross-shard ratio; defaults to Auncel's configured value")
        parser.add_argument('--fractional-capacity-load', action='store_true', help="for a fixed-k ratio study, split each cross-shard transaction's capacity occupancy across its touched shards; the default k-sweep metric is unchanged")
        parser.add_argument('--fixed-capacity-blocks', type=int, default=None, help='use this fixed number of block intervals in the capacity reporting window (protocol block admission is unchanged)')
        parser.add_argument('--tps-mode', choices=('aggregate', 'common', 'committed'), default=None, help='reported_tps mode; aggregate/common use the shared terminal-throughput definition')
        parser.add_argument('--rate', type=int, default=None, help="submission rate; defaults to Auncel's first configured rate")
        parser.add_argument('--results-dir', default='results/dcchain')
        args = parser.parse_args(argv)
        if any((k < 2 or k > 64 for k in args.ks)) or len(set(args.ks)) != len(args.ks):
            raise ValueError('k must be distinct and in [2,64]')
        if args.transactions is not None and args.transactions <= 0:
            raise ValueError('--transactions must be positive')
        if args.fixed_capacity_blocks is not None and args.fixed_capacity_blocks <= 0:
            raise ValueError('--fixed-capacity-blocks must be positive')
        config = json.loads((ROOT / 'configs/system.yaml').read_text(encoding='utf-8'))
        experiments = json.loads((ROOT / 'configs/experiments.yaml').read_text(encoding='utf-8'))
        seeds = list(args.seeds)
        if not seeds or len(set(seeds)) != len(seeds):
            raise ValueError('seeds must be non-empty and distinct')
        result_root = Path(args.results_dir)
        if not result_root.is_absolute():
            result_root = ROOT / result_root
        if result_root.exists():
            existing = [p.name for p in result_root.iterdir() if p.name != 'run.log']
            if existing:
                raise RuntimeError('Use a new empty results directory; existing runs are never mixed: %s' % existing)
        rows, data_manifest = read_dataset(ROOT, config['dataset'])
        fixed_count = args.transactions if args.transactions is not None else FORMAL_TRANSACTIONS
        count_for_k = lambda _k: fixed_count
        alpha = float(args.alpha) if args.alpha is not None else float(experiments['fixed_cross_shard_ratio'])
        rate = int(args.rate) if args.rate is not None else int(experiments['offered_tps'][0])
        if not 0 <= alpha <= 1:
            raise ValueError('alpha must be in [0,1]')
        tps_mode = 'committed' if args.tps_mode == 'committed' else 'common'
        raw_root = result_root / 'raw'
        raw_root.mkdir(parents=True, exist_ok=True)
        transactions_by_k = {str(k): count_for_k(k) for k in args.ks}
        source_hashes = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for folder in ('src', 'contracts', 'configs', 'experiments') for p in (ROOT / folder).rglob('*') if p.is_file() and '__pycache__' not in str(p)}
        manifest = dict(configuration=config, experiment=dict(scheme='DCchain only', ks=args.ks, seeds=seeds, transactions=fixed_count, transactions_by_k=transactions_by_k, cross_shard_ratio=alpha, submission_rate=rate, capacity_load_mode='fractional' if args.fractional_capacity_load else 'physical', fixed_capacity_blocks=args.fixed_capacity_blocks, tps_reporting_mode=tps_mode, workload_model='fixed total real transactions for every k', repetitions=len(seeds), repeats_per_seed=1, total_runs=len(args.ks) * len(seeds)), dataset=data_manifest, dataset_sha256=config['dataset']['sha256'], source_files=source_hashes, protocol_version='dcchain-fixed-total-latency-v2-parallel-shard-capacity', workload_policy='same deterministic seeded XBlock selection and shard mapping as Auncel; each selected transaction is reused only within its own DCchain run', metrics='reported_tps=' + ('committed_throughput_tps' if tps_mode == 'committed' else 'service_capacity_tps') + '; common terminal-throughput denominator is global service makespan; DCchain latency=mean terminal cross-shard transaction latency including the measured global finality stage; local-only transactions are excluded from the latency aggregate; mean +/- sample SD across requested seeds')
        (raw_root / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        observations = []
        total = len(args.ks) * len(seeds)
        completed = 0
        for k in args.ks:
            for seed in seeds:
                count = count_for_k(k)
                txs = workload(rows, k, alpha, seed, count, rate, config['dispute_probability_given_cross_shard'])
                case = raw_root / ('k%d_seed%d' % (k, seed))
                case.mkdir(parents=True, exist_ok=True)
                shards = assign_nodes(k, seed, config)
                write_csv(case / 'node_assignment.csv', [n.record() for shard in shards for n in shard])
                write_csv(case / 'workload.csv', [{key: value for key, value in asdict(tx).items() if key not in ('history', 'state')} for tx in txs])
                workload_load = [sum((1 for tx in txs if shard in {tx.source, tx.target})) for shard in range(k)]
                (case / 'inputs.json').write_text(json.dumps({'k': k, 'seed': seed, 'repeat': 1, 'transactions': count, 'cross_shard_ratio_requested': alpha, 'cross_shard_ratio_actual': sum((tx.cross for tx in txs)) / len(txs), 'shard_transaction_load': workload_load, 'shard_transaction_load_range': max(workload_load) - min(workload_load), 'shard_transaction_load_sd': _sample_sd(workload_load) if len(workload_load) > 1 else 0.0, 'workload_sha256': hashlib.sha256((case / 'workload.csv').read_bytes()).hexdigest(), 'assignment_sha256': hashlib.sha256((case / 'node_assignment.csv').read_bytes()).hexdigest()}, indent=2), encoding='utf-8')
                output = case / 'DCchain'
                print('RUN DCchain k=%d seed=%d repeat=1/1 transactions=%d/%d' % (k, seed, count, count), flush=True)
                result = run(ROOT, None, shards, copy.deepcopy(txs), config, seed, 'DCchain', output, capacity_load_mode='fractional' if args.fractional_capacity_load else None, fixed_capacity_blocks=args.fixed_capacity_blocks)
                _, dc_timing = _augment_dcchain_latency(output)
                cross_latency, cross_count = _cross_shard_latency(output)
                result['dcchain_completion_latency_s'] = cross_latency
                result['dcchain_cross_shard_latency_count'] = cross_count
                result['capacity_load_mode'] = 'fractional' if args.fractional_capacity_load else 'physical'
                result['tps_reporting_mode'] = tps_mode
                result['reported_tps'] = (result.get('committed_throughput_tps')
                                          if tps_mode == 'committed'
                                          else result.get('service_capacity_tps'))
                result['fixed_capacity_blocks'] = args.fixed_capacity_blocks
                result['dcchain_latency_definition'] = 'mean dcchain_completion_latency_s for terminal cross-shard rows; the field uses the common per-transaction latency_s after adding one measured all-shard finality stage; resource-endpoint waits remain diagnostic'
                result['dcchain_global_confirmation_s'] = dc_timing['global_confirmation_s']
                result['dcchain_global_cpu_finish_s'] = dc_timing['global_cpu_finish_s']
                result['dcchain_final_block_horizon_s'] = dc_timing['final_block_horizon_s']
                result['dcchain_global_causal_finish_s'] = dc_timing['global_causal_finish_s']
                result['dcchain_global_finality_duration_s'] = dc_timing['dcchain_global_finality_duration_s']
                result['dcchain_global_finality_finish_s'] = dc_timing['dcchain_global_finality_finish_s']
                (output / 'summary.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
                observations.append(dict(scheme='DCchain', k=k, seed=seed, repeat=1, transactions=count, cross_shard_ratio=alpha, submission_rate=rate, **result))
                write_csv(raw_root / 'observations.csv', observations)
                completed += 1
                print('DONE %d/%d' % (completed, total), flush=True)
        metrics = ['transactions', 'service_capacity_tps', 'throughput_tps', 'reported_tps', 'dcchain_aggregate_capacity_tps', 'observed_workload_tps', 'committed_throughput_tps', 'transaction_success_rate', 'global_service_makespan_s', 'active_service_makespan_s', 'dcchain_completion_latency_s', 'dcchain_cross_shard_latency_count', 'dcchain_active_cpu_s', 'dcchain_global_confirmation_s', 'dcchain_global_cpu_finish_s', 'dcchain_final_block_horizon_s', 'dcchain_global_causal_finish_s', 'dcchain_global_finality_duration_s', 'dcchain_global_finality_finish_s', 'dcchain_proof_signing_cpu_s', 'dcchain_proof_aggregation_cpu_s', 'dcchain_proof_verification_cpu_s', 'dcchain_state_verification_cpu_s', 'dcchain_state_commit_cpu_s', 'dcchain_final_reply_signing_cpu_s', 'dcchain_final_reply_verification_cpu_s', 'dcchain_vrf_generation_cpu_s', 'dcchain_vrf_verification_cpu_s', 'dcchain_vrf_processing_cpu_s', 'total_messages', 'total_bytes', 'communication_bytes_per_tx', 'shard_transaction_load_mean', 'shard_transaction_load_sd', 'shard_transaction_load_range']
        aggregate = []
        for k in args.ks:
            group = [row for row in observations if row['k'] == k]
            item = dict(scheme='DCchain', k=k, cross_shard_ratio=alpha, submission_rate=rate, repetitions=len(group), capacity_load_mode='fractional' if args.fractional_capacity_load else 'physical', fixed_capacity_blocks=args.fixed_capacity_blocks, tps_reporting_mode=tps_mode)
            for metric in metrics:
                source_metric = 'reported_tps' if tps_mode == 'committed' and metric in {'service_capacity_tps', 'throughput_tps'} else metric
                values = [row[source_metric] for row in group if isinstance(row.get(source_metric), (int, float)) and (not isinstance(row.get(source_metric), bool)) and math.isfinite(float(row[source_metric]))]
                if values:
                    item[metric + '_mean'] = statistics.mean(values)
                    item[metric + '_sd'] = _sample_sd(values)
            aggregate.append(item)
        processed = result_root / 'processed'
        processed.mkdir(parents=True, exist_ok=True)
        write_csv(processed / 'dcchain_k_mean_sd.csv', aggregate)
        (processed / 'metric_definitions.json').write_text(json.dumps({'tps': 'common terminal throughput = terminal transactions / global service makespan; per-shard capacity remains available as an audit field and uses the independent shard lanes', 'reported_tps': 'service_capacity_tps under the common mode; committed_throughput_tps is available only when the optional committed mode is explicitly requested', 'latency': 'mean dcchain_completion_latency_s for terminal cross-shard rows; it joins each measured causal path with the all-shard DC_GLOBAL_FINALITY barrier; no fixed delay, scaling, or P95', 'workload': 'fixed total real transactions for every k; deterministic seeded XBlock selection, cross-shard ratio, offered rate and node assignment policy as Auncel', 'communication': 'serialized protocol-message count and bytes from the DCchain trace; setup and experiment I/O excluded', 'statistics': 'mean and sample standard deviation (ddof=1) across the requested seeds'}, indent=2), encoding='utf-8')
        print('k,transactions,reported_tps_mean,reported_tps_sd,service_capacity_tps_mean,service_capacity_tps_sd,observed_workload_tps_mean,dcchain_completion_latency_s_mean,dcchain_completion_latency_s_sd', flush=True)
        for item in aggregate:
            print('%d,%d,%s,%s,%s,%s,%s,%s,%s' % (item['k'], item.get('transactions_mean', 0), item.get('reported_tps_mean', ''), item.get('reported_tps_sd', ''), item.get('service_capacity_tps_mean', ''), item.get('service_capacity_tps_sd', ''), item.get('observed_workload_tps_mean', ''), item.get('dcchain_completion_latency_s_mean', ''), item.get('dcchain_completion_latency_s_sd', '')), flush=True)
        print('DCCHAIN_K_SWEEP_PASS', result_root, 'capacity_load_mode=' + ('fractional' if args.fractional_capacity_load else 'physical'), flush=True)
    main()

if __name__ == '__main__':
    main()
