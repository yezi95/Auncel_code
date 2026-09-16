import csv
import json
import math
import random
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'results' / 'incentive' / 'processed'

SEED = 1
TRIALS_A = 10000
TRIALS_B = 10000
TRIALS_C = 10000
K_VALUES = list(range(2, 9))
DEFAULT_P = 3 / 10
SYSTEM_CONFIG = json.loads((ROOT / 'configs' / 'system.yaml').read_text(encoding='utf-8'))
ARBITRATION_THRESHOLD_F = SYSTEM_CONFIG.get('arbitration_threshold_f', {})

def write_csv(path, rows):
    if not rows:
        return
    with path.open('w', newline='', encoding='utf-8') as fp:
        writer = csv.DictWriter(fp, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

def arbitration_f(k):
    """
    Auncel arbitration parameter:
        floor(2(k-1)/3) < f < k

    The configured values are used for k=2,4,6,8.  Other committee sizes
    fall back to the smallest integer satisfying the same strict bound.

    Successful honest committee condition:
        H > f
    """
    k = int(k)
    lower = 2 * (k - 1) // 3
    raw = ARBITRATION_THRESHOLD_F.get(str(k), ARBITRATION_THRESHOLD_F.get(k))
    f = lower + 1 if raw is None else int(raw)
    if not lower < f < k:
        raise ValueError('invalid arbitration threshold f=%d for committee size k=%d' % (f, k))
    return f

def analytical_success_probability(k, p):
    """
    Conservative analytical lower bound:

        P(H > f) >=
        1 - sum_{j=C-f}^{C}
            binom(C,j) p^j (1-p)^(C-j)

    where:
        C = k,
        p = Byzantine/failure probability of one independently selected
            arbitration node.
    """
    C = k
    f = arbitration_f(k)
    failure_probability = sum((math.comb(C, j) * p ** j * (1.0 - p) ** (C - j) for j in range(C - f, C + 1)))
    return max(0.0, min(1.0, 1.0 - failure_probability))

def monte_carlo_success(k, p, trials, rng):
    """
    Independently sample one arbitration-node state for each shard.

    True  -> Byzantine/unavailable
    False -> honest/available

    Success iff H > f.
    """
    successes = 0
    f = arbitration_f(k)
    for _ in range(trials):
        bad = sum((rng.random() < p for _ in range(k)))
        honest = k - bad
        if honest > f:
            successes += 1
    return successes / trials

def generate_fig5a():
    """
    Validate the revised rational-arbitrator payoff model.

    Revised model:

        pi_hon = R_fix + Phi_pool / |H| - C_gas

        E[pi_mal] =
            (1-p_d) * B_ext
            - p_d * Phi_i
            - C_gas

        pi_neg = 0

    The experiment simulates malicious behaviour as well as the closed-form
    payoff equations:
      - detected with probability p_d;
      - if detected, penalty Phi_i is lost;
      - otherwise external bribe B_ext is received.

    Honest payoff is deterministic.
    """
    fixed_reward = 1.5
    phi_pool = 4.0
    honest_participants = 4
    gas_cost = 1.0
    penalty = 4.0
    external_bribe = 4.0
    incentive_threshold = max(0.0, (external_bribe - fixed_reward) / (penalty + external_bribe))
    honest_payoff = fixed_reward + phi_pool / honest_participants - gas_cost
    rows = []
    detection_values = [i / 50 for i in range(51)]
    for idx, pd in enumerate(detection_values):
        rng = random.Random(SEED + 100000 + idx)
        honest_samples = []
        malicious_samples = []
        negative_samples = []
        for _ in range(TRIALS_A):
            honest_samples.append(honest_payoff)
            detected = rng.random() < pd
            if detected:
                malicious_payoff = -penalty - gas_cost
            else:
                malicious_payoff = external_bribe - gas_cost
            malicious_samples.append(malicious_payoff)
            negative_samples.append(0.0)
        empirical_honest = sum(honest_samples) / TRIALS_A
        empirical_malicious = sum(malicious_samples) / TRIALS_A
        empirical_negative = 0.0
        theoretical_honest = honest_payoff
        theoretical_malicious = (1.0 - pd) * external_bribe - pd * penalty - gas_cost
        rows.append({'detection_probability': pd, 'trials': TRIALS_A, 'empirical_honest_payoff': empirical_honest, 'empirical_malicious_payoff': empirical_malicious, 'empirical_nonparticipation_payoff': empirical_negative, 'theoretical_honest_payoff': theoretical_honest, 'theoretical_malicious_payoff': theoretical_malicious, 'theoretical_nonparticipation_payoff': 0.0, 'fixed_reward': fixed_reward, 'phi_pool': phi_pool, 'honest_participants': honest_participants, 'gas_cost': gas_cost, 'penalty': penalty, 'external_bribe': external_bribe, 'incentive_threshold': incentive_threshold, 'theorem_condition_1_holds': int(fixed_reward > gas_cost), 'theorem_condition_2_holds': int(fixed_reward + pd * penalty > (1.0 - pd) * external_bribe)})
    path = OUT / 'fig5a_incentive.csv'
    write_csv(path, rows)
    return rows

def generate_fig5b():
    """
    For every k=2,...,8 and arbitration-node failure probability
    p=0,...,0.30:

        1. perform 10,000 independent Monte Carlo trials;
        2. calculate empirical P(H > f);
        3. calculate analytical lower bound.

    The point p=0.30 corresponds to the current configuration:
        malicious_per_shard / nodes_per_shard = 3/10.
    """
    rows = []
    probability_values = [i / 100 for i in range(31)]
    for k in K_VALUES:
        for p_index, p in enumerate(probability_values):
            rng = random.Random(SEED + 1000000 + k * 10000 + p_index)
            empirical = monte_carlo_success(k=k, p=p, trials=TRIALS_B, rng=rng)
            theoretical = analytical_success_probability(k=k, p=p)
            rows.append({'k': k, 'committee_size': k, 'f': arbitration_f(k), 'error_probability': p, 'trials': TRIALS_B, 'empirical_success_probability': empirical, 'theoretical_lower_bound': theoretical, 'is_system_default_p': int(abs(p - DEFAULT_P) < 1e-12)})
    path = OUT / 'fig5b_arbitration_probability.csv'
    write_csv(path, rows)
    return rows

def generate_fig5c(k=8):
    rows = []
    probability_values = [i / 100 for i in range(31)]
    frequency_values = [i / 50 for i in range(51)]
    window_transactions = 10
    f = arbitration_f(k)
    for freq_index, freq in enumerate(frequency_values):
        for p_index, p in enumerate(probability_values):
            rng = random.Random(SEED + 2000000 + freq_index * 10000 + p_index)
            successful_windows = 0
            for _ in range(TRIALS_C):
                window_success = True
                for _tx in range(window_transactions):
                    if rng.random() >= freq:
                        continue
                    bad = sum((rng.random() < p for _ in range(k)))
                    honest = k - bad
                    if honest <= f:
                        window_success = False
                        break
                if window_success:
                    successful_windows += 1
            empirical = successful_windows / TRIALS_C
            single_arb_success = analytical_success_probability(k, p)
            theoretical = (1.0 - freq * (1.0 - single_arb_success)) ** window_transactions
            rows.append({'k': k, 'committee_size': k, 'f': f, 'error_probability': p, 'arbitration_frequency': freq, 'window_transactions': window_transactions, 'trials': TRIALS_C, 'empirical_success_probability': empirical, 'theoretical_success_probability': theoretical, 'absolute_difference': abs(empirical - theoretical)})
    path = OUT / 'fig5c_sensitivity.csv'
    write_csv(path, rows)
    return rows

def generate_all():
    a = generate_fig5a()
    b = generate_fig5b()
    c = generate_fig5c(k=8)
    manifest = {'experiment': 'Fig.5 revised incentive', 'replacement': True, 'old_fig5_data_used': False, 'seed': SEED, 'fig5a': {'type': 'Monte Carlo incentive simulation', 'trials_per_point': TRIALS_A, 'detection_probability_range': [0.0, 1.0], 'note': 'Simulation validates the revised expected payoff equations and illustrates the Theorem 4 detection-probability threshold; not measured blockchain execution latency/revenue.'}, 'fig5b': {'type': 'Monte Carlo arbitration reliability + analytical bound', 'k_values': K_VALUES, 'trials_per_point': TRIALS_B, 'error_probability_range': [0.0, 0.3], 'system_default_p': DEFAULT_P}, 'fig5c': {'type': 'Monte Carlo joint sensitivity analysis', 'k': 8, 'committee_size': 8, 'trials_per_point': TRIALS_C, 'error_probability_range': [0.0, 0.3], 'arbitration_frequency_range': [0.0, 1.0], 'window_transactions': 10, 'reliability_definition': 'probability that all triggered arbitrations in the observation window satisfy H > f'}}
    (OUT / 'fig5_manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    print('NEW_FIG5_DATA_COMPLETE', 'Fig5a:', len(a), 'Fig5b:', len(b), 'Fig5c:', len(c))

def main():
    import argparse
    parser = argparse.ArgumentParser(description='Run the revised incentive experiment.')
    parser.add_argument('--output-dir', type=Path, default=Path('results/incentive/processed'))
    args = parser.parse_args()
    global OUT
    OUT = args.output_dir if args.output_dir.is_absolute() else ROOT / args.output_dir
    OUT.mkdir(parents=True, exist_ok=True)
    generate_all()

if __name__ == '__main__':
    main()
