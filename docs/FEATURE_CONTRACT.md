# Feature contracts

The active model is now the 78-feature training package. See
[active model contract](NEW_MODEL_CONTRACT.md) for preprocessing and additional
measurements. The 52-feature contract below is retained for historical evidence
and compatibility tests. Shared measurements retain the conventions below.

## Original artifact evidence and the legacy live feature contract

## What the supplied files establish

The original `artifacts/xgb_model.joblib` is an XGBClassifier with 52 numeric inputs, objective `multi:softprob`, and encoded classes 0 through 6. The booster stores no feature names. `feature_schema.json` supplies the ordered names below. `label_classes.json` supplies the labels in index order: Bots, Brute Force, DDoS, DoS, Normal Traffic, Port Scanning, Web Attacks. Startup verifies these structures and refuses inference if they are incompatible.

The SHA-256 recorded **before implementation** in `validation/model_baseline.json` is `86e5dd0e6afe353e3ee1b7488271e390a047ec8483cc540b526c1f74ca65e8f6`. The original file is 1,495,546 bytes. Startup compares its current hash against that baseline before deserialization. Hash checking detects change; it does not make untrusted pickle/joblib files safe. Load only the supplied trusted artifact.

For this original 52-feature artifact, no matching training script, requirements lock, fitted scaler/imputer/encoder, feature-extractor version, training split specification, original packet capture, flow timeout setting, or DSI definition was supplied. A separate 78-feature, 10-class training package was added on 14 October 2026 and its offline evaluation was reproduced; see [training package validation](TRAINDATA_VALIDATION.md). It does not establish provenance for this artifact. Accordingly, **original live feature parity cannot be established**. DSOF marks every live/manual prediction `experimental_unverified` and uses raw numeric values without fitting or inventing preprocessing. The model's label mapping follows the supplied array, but the original label encoder is absent. It is impossible to establish from these files alone whether omitted preprocessing was unnecessary or lost.

The supplied `model_metrics.json` reports test accuracy 0.9990796335195885. This is historical artifact metadata, with no documented evaluation split or reproducible procedure. It is **not** DSOF live accuracy, a newly measured result, or proof of generalization. No new accuracy/ROC claim is made.

## Dataset inspection

`datasets/cicids2017_cleaned.csv` has the same 52 feature columns followed by `Attack Type`. A complete streaming scan of the label, initial-window, and minimum-segment columns counted 2,520,751 rows: Normal Traffic 2,095,057; Port Scanning 90,694; Web Attacks 2,143; Brute Force 9,150; DDoS 128,014; Bots 1,948; DoS 193,745. This was a data inspection, not training or evaluation.

The two initial-window columns span -1 through 65,535. `min_seg_size_forward` spans **-536,870,661 through 138**, which includes values inconsistent with an ordinary measured TCP header. There were no nulls in those three inspected numeric columns. Other columns were not exhaustively audited for all data-quality defects. Strict replay/manual validation rejects negative numeric features other than the explicit initial-window sentinel; it does not repair or silently coerce malformed dataset rows.

Preserving a trained model means preserving its serialized learned estimator (verified here by its hash). Preserving the dataset means separately retaining the source observations and labels unchanged. One does not imply the other; model inference requires the estimator and its feature contract, while reproducible re-evaluation/training additionally needs suitable data and provenance. DSOF modifies neither original artifact nor dataset.

## Runtime conventions (explicit implementation choices)

These conventions define DSOF's measured extractor; they **do not claim to reconstruct undocumented training choices**.

- A bidirectional key is protocol plus sorted `(IP, port)` endpoints. The first observed packet defines forward direction, even for a midstream capture. Destination Port is that first packet's destination port. TCP and UDP are supported over IPv4/IPv6. Fragmented IP datagrams are excluded, without reassembly.
- Capture timestamp is seconds since Unix epoch. Duration and inter-arrival time (IAT), Active and Idle features are converted to **microseconds**. Rates use seconds. A flow snapshot ends at its last actual packet, not at evaluation wall-clock time.
- Packet length is the transport **payload** length, in bytes; Ethernet/IP/TCP headers do not count as payload. All captured transport packets count, including zero-payload packets and retransmissions. HTTP reassembly separately deduplicates retransmitted content. Capture loss/duplication changes these statistics and is not concealed.
- `header_length` is TCP data offset times four, including TCP options; UDP header length is eight bytes. TCP windows are first observed raw, unscaled 16-bit fields in each direction. No reverse TCP packet and UDP use the explicit unavailable sentinel **-1**. Window scaling is not applied.
- Means include zero-payload packets. Sample standard deviation and variance use divisor `n-1`; empty or singleton dispersion is zero. Empty directional/IAT statistics are zero by definition of this extractor, not fabricated measurements or supplied missing values. First captured packet appears once in aggregate length statistics.
- Rates at exactly zero observed duration are explicitly zero. This differs from extractors that emit infinity, NaN or a special value. A missing submitted feature is never supplied with zero.
- IAT is between successively observed packets (overall or same direction). Regressing capture timestamps are reported and excluded from IAT observations. Last timestamp remains the latest observed value; negative intervals are never transformed into invented positive timing.
- An observed gap greater than five seconds closes an active interval and creates an idle observation. Active durations include the current observed interval when the snapshot is taken. A gap greater than one second begins a new subflow burst; Subflow Fwd Bytes is total forward payload bytes divided by the number of observed bursts. These explicit burst definitions may differ from the missing original extractor.
- FlowTracker defaults are 2,048 active flows, 10 seconds idle, 120 seconds lifetime and 10,000 packets per flow; the application may override these using validated configuration (the application's idle default is two seconds for prompt local detection). Flows end/split at configured limits; oldest inactive-in-LRU-order entries are evicted when capacity is reached. The engine drains removed flows for a final decision. Undrained removals are bounded and counted as `unprocessed_evictions` if that bound is exceeded.
- Constant-size online moments are stored per flow. The tracker never retains a packet list. Capture queue capacity is bounded and queue drops are counted. Kernel/Npcap drops are **unknown** through the current Scapy abstraction and displayed as unknown, never zero.

The upstream [CICFlowMeter BasicFlow implementation](https://github.com/ahlashkari/CICFlowMeter/blob/master/src/main/java/cic/cs/unb/ca/jnetpcap/BasicFlow.java) is a useful comparison reference, but the workspace does not identify the version or transformation that produced this CSV. No source match is inferred from names alone. Npcap installation and access settings are documented in the [official Npcap user guide](https://npcap.com/guide/npcap-users-guide.html).

## Exact ordered numeric inputs

All JSON inputs must contain exactly these keys and finite numeric values (no strings, booleans, nulls, NaN or infinity). Python constructs a float32 array in this order regardless of mapping insertion order. Float32 overflow, negative values outside documented sentinels, invalid ports, and invalid windows are rejected with the named feature. Counts are measured integers; non-integer submitted counts are rejected. Units cannot be inferred from an arbitrary submitted number, so callers must obey this documented contract. No confidence/probability transformation is applied.

| Order | Exact name | Unit / definition |
|---:|---|---|
| 1 | Destination Port | Integer port 0..65535 |
| 2 | Flow Duration | Microseconds, last minus first packet |
| 3 | Total Fwd Packets | Forward packet count |
| 4 | Total Length of Fwd Packets | Forward payload bytes sum |
| 5 | Fwd Packet Length Max | Forward payload bytes maximum |
| 6 | Fwd Packet Length Min | Forward payload bytes minimum |
| 7 | Fwd Packet Length Mean | Forward payload bytes mean |
| 8 | Fwd Packet Length Std | Forward payload bytes sample standard deviation |
| 9 | Bwd Packet Length Max | Reverse payload bytes maximum |
| 10 | Bwd Packet Length Min | Reverse payload bytes minimum |
| 11 | Bwd Packet Length Mean | Reverse payload bytes mean |
| 12 | Bwd Packet Length Std | Reverse payload bytes sample standard deviation |
| 13 | Flow Bytes/s | Both directions' payload bytes / duration seconds |
| 14 | Flow Packets/s | Both directions' packet count / duration seconds |
| 15 | Flow IAT Mean | Microseconds |
| 16 | Flow IAT Std | Microseconds, sample standard deviation |
| 17 | Flow IAT Max | Microseconds |
| 18 | Flow IAT Min | Microseconds |
| 19 | Fwd IAT Total | Microseconds, sum of valid forward IATs |
| 20 | Fwd IAT Mean | Microseconds |
| 21 | Fwd IAT Std | Microseconds, sample standard deviation |
| 22 | Fwd IAT Max | Microseconds |
| 23 | Fwd IAT Min | Microseconds |
| 24 | Bwd IAT Total | Microseconds, sum of valid reverse IATs |
| 25 | Bwd IAT Mean | Microseconds |
| 26 | Bwd IAT Std | Microseconds, sample standard deviation |
| 27 | Bwd IAT Max | Microseconds |
| 28 | Bwd IAT Min | Microseconds |
| 29 | Fwd Header Length | Forward transport header bytes sum |
| 30 | Bwd Header Length | Reverse transport header bytes sum |
| 31 | Fwd Packets/s | Forward count / flow duration seconds |
| 32 | Bwd Packets/s | Reverse count / flow duration seconds |
| 33 | Min Packet Length | Both directions' payload bytes minimum |
| 34 | Max Packet Length | Both directions' payload bytes maximum |
| 35 | Packet Length Mean | Both directions' payload bytes mean |
| 36 | Packet Length Std | Payload bytes sample standard deviation |
| 37 | Packet Length Variance | Payload bytes squared, sample variance |
| 38 | FIN Flag Count | Captured TCP packets with FIN bit |
| 39 | PSH Flag Count | Captured TCP packets with PSH bit |
| 40 | ACK Flag Count | Captured TCP packets with ACK bit |
| 41 | Average Packet Size | Payload bytes sum / packet count |
| 42 | Subflow Fwd Bytes | Forward payload bytes / observed burst count |
| 43 | Init_Win_bytes_forward | First forward raw TCP window, or -1 unavailable |
| 44 | Init_Win_bytes_backward | First reverse raw TCP window, or -1 unavailable |
| 45 | act_data_pkt_fwd | Forward packets with nonempty payload |
| 46 | min_seg_size_forward | Minimum observed forward transport header bytes |
| 47 | Active Mean | Microseconds, observed active interval mean |
| 48 | Active Max | Microseconds |
| 49 | Active Min | Microseconds |
| 50 | Idle Mean | Microseconds, qualifying gap mean; zero if no gap |
| 51 | Idle Max | Microseconds |
| 52 | Idle Min | Microseconds |

## Consequences and compatibility

Undocumented preprocessing, length-statistic implementation quirks, direction, timeout, burst, flag or active-period semantics can materially change model output. For example, the first inspected CSV row has Packet Length Mean 111.8372093 and Average Packet Size 113.1529412, whereas DSOF deliberately computes those two quantities consistently from the same observed samples. It would be unjustified to invent an original extractor's duplicate-sample behavior from one row. Short request flows may therefore produce high-confidence wrong categories. Preserve and inspect the original output; independent HTTP rules provide cleartext request evidence without modifying model probabilities.

The implementation successfully loads the original file with Python 3.13.1, XGBoost 3.4.1, NumPy 2.4.2, scikit-learn 1.5.2 and joblib 1.3.2; these versions are pinned for the local reproduction. This is observed local compatibility, not knowledge of the missing original training environment. Scapy 2.7.0 supplies capture. Incompatible import/deserialization/schema failures keep model readiness false and produce an actionable error. The original model is loaded once per process and predictions are serialized with a lock.
