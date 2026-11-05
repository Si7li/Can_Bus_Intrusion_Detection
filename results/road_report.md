# ROAD data report

Ambient: **12** captures, **24,149,519** frames, **2.98 h**, **106** distinct IDs

| Ambient capture | Frames | Seconds | Frames/s | IDs | Dyno | DLC≠8 | all-0xFF frames |
|---|---:|---:|---:|---:|---|---:|---:|
| ambient_dyno_drive_basic_long | 2,991,272 | 1250.9 | 2391 | 106 | yes | 0 | 0 |
| ambient_dyno_drive_basic_short | 1,063,624 | 444.8 | 2392 | 106 | yes | 0 | 0 |
| ambient_dyno_drive_benign_anomaly | 771,519 | 456.5 | 1690 | 106 | yes | 0 | 0 |
| ambient_dyno_drive_extended_long | 1,424,208 | 657.9 | 2165 | 106 | yes | 0 | 0 |
| ambient_dyno_drive_extended_short | 790,442 | 359.8 | 2197 | 106 | yes | 0 | 0 |
| ambient_dyno_drive_radio_infotainment | 932,852 | 390.5 | 2389 | 106 | yes | 0 | 0 |
| ambient_dyno_drive_winter | 114,148 | 47.7 | 2392 | 106 | yes | 0 | 0 |
| ambient_dyno_exercise_all_bits | 4,419,422 | 2172.8 | 2034 | 106 | yes | 0 | 0 |
| ambient_dyno_idle_radio_infotainment | 1,572,318 | 660.8 | 2379 | 106 | yes | 0 | 0 |
| ambient_dyno_reverse | 123,047 | 51.4 | 2392 | 106 | yes | 0 | 0 |
| ambient_highway_street_driving_diagnostics | 1,124,751 | 469.9 | 2393 | 106 | road | 0 | 0 |
| ambient_highway_street_driving_long | 8,821,916 | 3764.3 | 2344 | 106 | road | 0 | 0 |

| Attack capture | Target ID | Payload | Frames | Attack frames | Target frames in interval | Payload matches outside interval | IDs not in ambient |
|---|---|---|---:|---:|---:|---:|---:|
| correlated_signal_attack_1 | 0x6e0 | `595945450000FFFF` | 81,262 | 2,087 | 4173 | 0 | 0 |
| correlated_signal_attack_1_masquerade | 0x6e0 | `595945450000FFFF` | 79,176 | 2,087 | 2087 | 0 | 0 |
| correlated_signal_attack_2 | 0x6e0 | `595945450000FFFF` | 69,657 | 2,141 | 4281 | 0 | 0 |
| correlated_signal_attack_2_masquerade | 0x6e0 | `595945450000FFFF` | 67,517 | 2,141 | 2141 | 0 | 0 |
| correlated_signal_attack_3 | 0x6e0 | `595945450000FFFF` | 41,829 | 1,265 | 2529 | 0 | 0 |
| correlated_signal_attack_3_masquerade | 0x6e0 | `595945450000FFFF` | 40,565 | 1,265 | 1265 | 0 | 0 |
| fuzzing_attack_1 | XXX | `FFFFFFFFFFFFFFFF` | 49,342 | 592 | - | 0 | 556 |
| fuzzing_attack_2 | XXX | `FFFFFFFFFFFFFFFF` | 32,351 | 352 | - | 1 | 337 |
| fuzzing_attack_3 | XXX | `FFFFFFFFFFFFFFFF` | 13,238 | 115 | - | 1 | 112 |
| max_engine_coolant_temp_attack | 0x4e7 | `XXXXXXXXXXFFXXXX` | 61,923 | 43 | 85 | 0 | 0 |
| max_engine_coolant_temp_attack_masquerade | 0x4e7 | `XXXXXXXXXXFFXXXX` | 61,881 | 43 | 43 | 0 | 0 |
| max_speedometer_attack_1 | 0xd0 | `XXXXXXXXXXFFXXXX` | 213,397 | 2,445 | 4889 | 0 | 0 |
| max_speedometer_attack_1_masquerade | 0xd0 | `XXXXXXXXXXFFXXXX` | 210,953 | 2,445 | 2445 | 0 | 0 |
| max_speedometer_attack_2 | 0xd0 | `XXXXXXXXXXFFXXXX` | 145,894 | 3,141 | 6281 | 0 | 0 |
| max_speedometer_attack_2_masquerade | 0xd0 | `XXXXXXXXXXFFXXXX` | 142,754 | 3,141 | 3141 | 0 | 0 |
| max_speedometer_attack_3 | 0xd0 | `XXXXXXXXXXFFXXXX` | 213,551 | 6,108 | 12215 | 0 | 0 |
| max_speedometer_attack_3_masquerade | 0xd0 | `XXXXXXXXXXFFXXXX` | 207,444 | 6,108 | 6108 | 0 | 0 |
| reverse_light_off_attack_1 | 0xd0 | `XXXX04XXXXXXXXXX` | 67,902 | 673 | 1345 | 330 | 0 |
| reverse_light_off_attack_1_masquerade | 0xd0 | `XXXX04XXXXXXXXXX` | 67,230 | 673 | 673 | 330 | 0 |
| reverse_light_off_attack_2 | 0xd0 | `XXXX04XXXXXXXXXX` | 99,628 | 2,372 | 4743 | 367 | 0 |
| reverse_light_off_attack_2_masquerade | 0xd0 | `XXXX04XXXXXXXXXX` | 97,257 | 2,372 | 2372 | 367 | 0 |
| reverse_light_off_attack_3 | 0xd0 | `XXXX04XXXXXXXXXX` | 140,855 | 2,435 | 4869 | 788 | 0 |
| reverse_light_off_attack_3_masquerade | 0xd0 | `XXXX04XXXXXXXXXX` | 138,421 | 2,435 | 2435 | 788 | 0 |
| reverse_light_on_attack_1 | 0xd0 | `XXXX0CXXXXXXXXXX` | 133,237 | 1,992 | 3983 | 12 | 0 |
| reverse_light_on_attack_1_masquerade | 0xd0 | `XXXX0CXXXXXXXXXX` | 131,246 | 1,992 | 1992 | 12 | 0 |
| reverse_light_on_attack_2 | 0xd0 | `XXXX0CXXXXXXXXXX` | 175,945 | 3,690 | 7379 | 12 | 0 |
| reverse_light_on_attack_2_masquerade | 0xd0 | `XXXX0CXXXXXXXXXX` | 172,256 | 3,690 | 3690 | 12 | 0 |
| reverse_light_on_attack_3 | 0xd0 | `XXXX0CXXXXXXXXXX` | 156,052 | 2,352 | 4703 | 12 | 0 |
| reverse_light_on_attack_3_masquerade | 0xd0 | `XXXX0CXXXXXXXXXX` | 153,701 | 2,352 | 2352 | 12 | 0 |

**Attack frames per family**

| Family | Fabrication | Masquerade |
|---|---:|---:|
| correlated_signal | 5,493 | 5,493 |
| fuzzing | 1,059 | 0 |
| max_engine_coolant_temp | 43 | 43 |
| max_speedometer | 11,694 | 11,694 |
| reverse_light_off | 5,480 | 5,480 |
| reverse_light_on | 8,034 | 8,034 |

Skipped:
- accelerator_attack_drive_1: no injected frames (accelerator attack)
- accelerator_attack_drive_2: no injected frames (accelerator attack)
- accelerator_attack_reverse_1: no injected frames (accelerator attack)
- accelerator_attack_reverse_2: no injected frames (accelerator attack)

Notes:
- *Payload matches outside interval*: frames with the target ID that already carry the injected value in normal operation. High values (reverse_light_off) mean the forged value is normal in other contexts: it can't be detected from the value alone.
- Each `_masquerade` capture is its fabrication capture with the real target-ID frames removed: keep both in the same split.
