# Reproducible Deception Success Index

Current sessions include two separate versioned records:

- `evaluation`: `dsof-eidp-v1`, implementing 0.35E + 0.30I + 0.20D + 0.15P.
- `dsi`: `dsof-observed-engagement-v1`, retained for compatibility and audit.

## Four-component score

Each input is measured, persisted and bounded. A ratio normalizer caps at 1.

| Component | Explicit definition |
|---|---|
| E | 100 × (0.5 × min(duration / 120 s, 1) + 0.5 × min(interactions / 20, 1)) |
| I | 100 × (0.6 × min(distinct meaningful actions / 5, 1) + 0.4 × min(depth / 4, 1)) |
| D | 100 / (1 + observed protected-service connections during this honeypot session) |
| P | 100 × min(prior same-source, same-origin sessions within 24 hours / 3, 1) |

D compares this one honeypot connection to protected-service connections
observed during the same session. It is an operational connection-share proxy,
not a causal estimate of prevented attacks. It needs configured protected
ports, continuous capture readiness since session start, no known queue loss
and no pending processing backlog. Overflow of the bounded connection history
also invalidates coverage. Missing D leaves the total score `null`; it is not
replaced with zero or an invented value. All scores are heuristics, not validated
scientific effectiveness measures. Kernel drops are unknown and are explicitly
included in coverage notes. Other interfaces and unconfigured services are
outside the measurement scope.

Persistence reads at most 10,000 recent same-source/origin sessions and records
that sample limit. A source address can represent multiple people. Active
scores are provisional; normal completion marks the record final. Interrupted
sessions are excluded from strategy learning even if evidence is retained.

Reproduce with `dsof.evaluation.calculate_eidp` using the persisted `inputs`,
`prior_sessions_24h` and `protected_connections_during_session`. The live
acceptance tool checks this calculation.

## Legacy engagement score

Weights and normalizers are stored on each `dsi` record, initially 30% duration,
30% interactions, 20% distinct actions and 20% maximum depth. This score does
not measure diversion or longitudinal persistence. The original configuration
in `config.dsi.json` affects only this legacy score. Old records are never
silently rewritten as the new metric.

## Learning

Only completed attributed live sessions on newly profiled alerts contribute.
Records are grouped by attack category, behavior tier, service and scoring
policy. EIDP comparisons also separate protected ports and capture interfaces.
Complete EIDP is preferred when its configured baseline has enough evidence;
otherwise comparable legacy scores can be used. Both baseline and challenger
need three sessions; a five-point advantage is required for switching.
Unknown scores, active/interrupted sessions and manual tests do not train the
live selector. Retention removes expired feedback naturally.
