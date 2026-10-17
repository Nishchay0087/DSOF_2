# Measured localhost policy-replay benchmark

This is a controlled protocol pilot, not completion of the professor’s gateway experiment or human validation. 
Actual HTTP, SSH and TCP exchanges were recorded. Six policies were replayed against the same per-seed outcome panels; each learner received only its chosen arm’s reward. All arms were measured to allow matched comparison and a hindsight fixed-arm gap. It is an offline replay, not deployment of learned routing policies.

Training: 200 episodes per policy/class/seed; held out: 50; seeds: [11, 23, 37, 53, 71]. Pilot caps were fixed before collecting the main panels.

DSI uses equal weights pending actual AHP judgments. Diversion is action share relative to a local reference surrogate, not protection of real assets. Persistence is measured wall time and is affected by the fixed worker load and protocol latency. Attack classes are assigned by the runner; detector and gateway performance are not tested. SSH arms are fixed Paramiko emulators, not Cowrie. No false-redirection or fingerprint-resistance claim is made.

| Class | Policy | Held-out DSI mean (95% t CI across seeds) | Surrogate diversion | Failures |
|---|---|---|---|---|
| web | static | 77.11 (72.07, 82.15) | 93.27 | 0/250 |
| web | random | 67.89 (65.46, 70.32) | 90.77 | 0/250 |
| web | rule | 65.86 (62.13, 69.59) | 89.49 | 0/250 |
| web | q_learning | 69.15 (61.87, 76.43) | 91.32 | 0/250 |
| web | epsilon_greedy | 77.05 (72.03, 82.07) | 93.27 | 0/250 |
| web | ucb1 | 77.15 (72.15, 82.15) | 93.27 | 0/250 |
| ssh | static | 76.28 (73.89, 78.67) | 95.44 | 0/250 |
| ssh | random | 68.08 (66.46, 69.71) | 93.85 | 0/250 |
| ssh | rule | 68.37 (65.76, 70.98) | 93.43 | 0/250 |
| ssh | q_learning | 64.99 (58.45, 71.53) | 92.83 | 0/250 |
| ssh | epsilon_greedy | 76.36 (73.90, 78.81) | 95.44 | 0/250 |
| ssh | ucb1 | 76.30 (73.84, 78.77) | 95.44 | 0/250 |
| scan | static | 56.41 (54.87, 57.95) | 93.80 | 0/250 |
| scan | random | 55.53 (54.17, 56.88) | 92.85 | 0/250 |
| scan | rule | 57.22 (55.76, 58.68) | 92.08 | 0/250 |
| scan | q_learning | 55.72 (53.68, 57.77) | 92.74 | 0/250 |
| scan | epsilon_greedy | 56.38 (54.83, 57.92) | 93.80 | 0/250 |
| scan | ucb1 | 56.37 (54.84, 57.89) | 93.80 | 0/250 |

CIs are not clipped to the score range. Five seeds give limited precision. Exact paired two-sided sign-flip tests with five seeds cannot achieve p < 0.05; all 15 held-out contrasts use Holm correction. Report negative results; this run cannot establish that UCB1 is superior.

## Reproduction and evidence

`manifest.json` records settings and source hashes; `outcomes.jsonl` contains protocol events; `decisions.sqlite3` links every choice/reward/state to an outcome; `seed_results.json`, `summary.json`, `weight_sensitivity.json` contain analysis. Admission failures stay in the denominator with zero reward. Frozen learners neither update nor explore; random and rule baselines retain their fixed behavior. The experimental rate-bucket rule is not the current production service selector. 

## Still required for the paper

Consented human sessions and evaluator AHP matrices; the contained routed testbed; Cowrie arm comparison if claiming Cowrie; independent detection evaluation; benign-redirection measurement. Do not describe scripted records as human judgments or claim completed end-to-end E4/E5.
