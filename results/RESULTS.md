# Results summary

All numbers are measured, not estimated. Reproduce with the commands in the README.

## 1. CICIoV2024: why it cannot evaluate an AI detector

| | |
|---|---|
| Rows | 1,408,219, only **3,588 unique** (ID + 8 bytes + class) |
| Unique attack frames | DoS 21, gas 2, RPM 10, speed 5, steering 3 |
| Attack IDs seen in normal traffic | **none** |
| One-line rule "ID never seen in normal traffic" | **184,482 / 184,482 attacks, 0 false alarms** |

Published ~99.9% scores on this dataset come from duplicate rows and attack IDs
that never occur in normal traffic. It is used here for the **rules layer** only.
Details: `data_report.md`.

## 2. ROAD: the AI detector

Dataset: ORNL ROAD (Verma et al., PLoS ONE 2024), real vehicle, ~3 h of normal
traffic (24.1M frames, 106 IDs). Attacks forge frames on **legitimate IDs**;
masquerade versions remove the real frames so timing stays normal.
Details: `road_report.md`.

Split by whole recording: attack instance 3 → train, 2 → val, 1 → test;
the coolant attack exists once and is in **test only (never seen in training)**.
Threshold (0.98) and smoothing (5 of the last 10 frames of an ID) were chosen on
val and frozen before the single test run.

### Detector
1. **Rules**: ID whitelist, per-ID rate check.
2. **AI**: MLP 27 → 32 → 16 → 1, **1,441 parameters**, full int8,
   **5,232-byte** TFLite model. float and int8 decisions agree on 100% of val frames.
   Features: value never seen / outside normal range (per ID and byte), broken
   signal pairs (automatically found, e.g. gear ↔ reverse light), byte change since
   the previous frame of the ID, time since that frame. No raw byte values.
3. **Severity**: ALERT = unknown ID, wrong timing, or the model backed by strong
   evidence (impossible value or broken signal pair). WARNING = the model fired with
   only a never-seen value as evidence (possibly a new, normal car state).

### Rules only vs rules + AI (val)
| | Masquerade frames caught |
|---|---|
| Rules only | 0% |
| Rules + AI | 99.8–99.9% (every attack type) |

### Test set (int8 model, run once)
| Attack | Fabrication | Masquerade |
|---|---|---|
| Max speedometer | 99.8% | 99.8% |
| Correlated signal (wheel speeds) | 99.8% | 99.8% |
| Reverse light on | 99.8% | 99.8% |
| Reverse light off | 99.4% | 99.4% |
| Fuzzing | 93.9% | — |
| Max coolant temp (**never seen in training**) | 88.4% | **0% (missed)** |

All frames, all attacks: **99.2%** caught at ALERT level. Median delay to the first
alert ≈ 40 ms (5 frames at a 10 ms period); 406 ms for coolant (100 ms period).

| Clean test drives (22.9 min, never used for training or tuning) | Events | Frames/min |
|---|---:|---:|
| ALERT | 1 (2.6 per hour), in the "benign anomaly" drive | 0.26 |
| WARNING | 246, in the "benign anomaly" and "diagnostics" drives | 51.3 |

An event = flagged frames less than 1 s apart.

### Limitations (honest reading)
- **Coolant masquerade is missed.** Its byte varies too much between normal drives
  for the never-seen check, it has no signal partner, and its timing is unchanged.
  Nothing in the features can reveal it. The fabrication version is caught by timing.
- **WARNINGs are frequent on unusual drives** (deliberate benign anomalies,
  diagnostic sessions): the car shows values the training drives never contained.
  They are reported as "unknown state", not as attacks; a longer normal-traffic
  recording of the target car would reduce them.
- One recording per attack type in val and test: per-attack numbers rest on one
  capture each.
- The 0.5 ALERT-frames/min target used to pick the threshold was not reachable on
  val (3.2 at every threshold, one event); the highest threshold (0.98) was used.

Files: `road_mlp_int8_test.json`, `road_mlp_int8_val.json`, `road_mlp_config.json`,
`road_mlp_final_log.txt`, `road_profile.json` (the tables that go into the firmware).
