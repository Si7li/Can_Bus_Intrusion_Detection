# CICIoV2024 data report

Raw rows: **1,408,219**, unique (features + class): **3,588**

| Class | Raw rows | Unique rows | Unique % | Train | Val | Test |
|---|---:|---:|---:|---:|---:|---:|
| benign | 1,223,737 | 3,547 | 0.29% | 2,482 | 355 | 710 |
| dos | 74,663 | 21 | 0.03% | 15 | 2 | 4 |
| spoof_gas | 9,991 | 2 | 0.02% | 2 | 2 | 2 |
| spoof_rpm | 54,900 | 10 | 0.02% | 7 | 1 | 2 |
| spoof_speed | 24,951 | 5 | 0.02% | 5 | 5 | 5 |
| spoof_steering | 19,977 | 3 | 0.02% | 3 | 3 | 3 |

Split built from: **deduplicated** data

Label conflicts (same 9 features, different class): **0** feature vectors

MEMORISED classes (< 10 unique rows, copied into train/val/test): ['spoof_gas', 'spoof_speed', 'spoof_steering']. Their scores do not measure generalisation; rules (e.g. unknown ID) should catch them.

WARNING: few unique rows (< 50) for ['dos', 'spoof_gas', 'spoof_rpm', 'spoof_speed', 'spoof_steering']: per-class scores will be unreliable; consider the binary task.
