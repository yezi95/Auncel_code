"""Configurable arbitration committee thresholds.

For a committee of size ``s``, the configured fault threshold ``f`` must obey
``floor(2*(s-1)/3) < f < s``.  Both the arbitration response quorum and the
PVSS reconstruction threshold are then ``f + 1``.
"""


def arbitration_parameters(config, committee_size):

    s = int(committee_size)
    if s < 2:
        raise ValueError("arbitration committee size must be at least 2")
    lower = 2 * (s - 1) // 3
    configured = config.get("arbitration_threshold_f", {})
    raw = configured.get(str(s), configured.get(s))
    f = lower + 1 if raw is None else int(raw)
    if not lower < f < s:
        raise ValueError(
            "invalid arbitration threshold f=%d for committee size s=%d; "
            "require floor(2*(s-1)/3) < f < s" % (f, s)
        )
    q = f + 1
    t = f + 1
    return f, q, t

