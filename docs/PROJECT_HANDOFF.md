# Project handoff: TinyML Intrusion Detection for an Automotive CAN Bus (STM32F446)

> **For Claude Code:** this file summarizes a long planning conversation held in the Claude app. It contains the full project idea, every decision taken (and why), the current state, the hardware the student already has, and the next steps. The student is continuing the work on their own machine with you. **They use Arch Linux.**

---

## 1. Who and what

- **Student project** for a course in **embedded systems security**. The professor requires:
  - a real embedded project on a board,
  - a dataset used to train or fine-tune an AI model,
  - **protections against attacks at three layers: physical, logical and network** (at least one per layer).
- The student also wants the project to be **impressive on a resume** (target roles: embedded software, automotive software/cybersecurity, IoT security).
- The student is a beginner with STM32 and needs clear, step-by-step guidance. Explain things simply.

## 2. The project in one paragraph

A small embedded device, an **STM32 NUCLEO-F446RE**, is connected to a **CAN bus** (the network used inside cars). It runs a small **AI model (int8, TinyML)** that classifies every CAN frame in real time as normal or as an attack (DoS or one of four spoofing types). The model is trained on the public **CICIoV2024** dataset, recorded on a real 2019 Ford. A **PC with a USB-to-CAN adapter** replays real vehicle traffic from the dataset and injects attacks onto the bus. The device itself is protected at the **network** layer (AI detector + rules), the **physical** layer (readout protection, tamper switch, brown-out reset) and the **logical** layer (signed secure boot, flash write protection, watchdog, input validation). A **PC dashboard** shows the status of the three layers and turns alerts into **incidents** with a plain-language report of what happened (template-based now, local LLM later).

## 3. Why CAN, and the attacks

- CAN (ISO 11898) is a 1980s broadcast bus: two wires (CAN-H, CAN-L), 120 Ω termination at each end, frames with an **11-bit ID** (priority + meaning) and **0–8 data bytes**.
- **No authentication, no encryption**: any node can send any ID; receivers can't tell who sent a frame.
- **DoS**: flood the bus with a very high-priority ID (e.g. 0x000); it wins arbitration every time and starves legitimate ECUs.
- **Spoofing**: send frames with a legitimate ID (speed, RPM, gas pedal, steering) but false data, interleaved with the real ECU's frames; spoofing typically raises the message rate of that ID.
- **Replay**: re-send recorded valid frames (defeated by freshness counters, see SecOC).
- Motivation examples: 2015 Jeep Cherokee remote hack (Miller & Valasek, recall of ~1.4 M vehicles); regulation UNECE R155 and standard ISO/SAE 21434.

## 4. Dataset: CICIoV2024

- Source: Canadian Institute for Cybersecurity, University of New Brunswick (2024). Page: https://www.unb.ca/cic/datasets/iov-dataset-2024.html — download: http://cicresearch.ca/IOTDataset/CICIoV2024/
- Paper: Neto et al., "CICIoV2024: Advancing realistic IDS approaches against DoS and spoofing attack in IoV CAN bus", *Internet of Things*, 101209, 2024.
- Recorded on a **2019 Ford** with all ECUs intact, immobilized for safety. 5 attacks via CAN.
- Formats: decimal, hexadecimal, binary folders; files for benign, DoS, spoofing-GAS, spoofing-RPM, spoofing-SPEED, spoofing-STEERING_WHEEL. **Use the decimal version.**
- Columns: `ID`, `DATA_0`…`DATA_7`, `label` (benign/attack), `category`, `specific_class`.
- Published stats (decimal): ID range 65–1438, mean ≈ 537.

| Class | Messages | Share |
|---|---:|---:|
| Benign | 1,223,737 | 86.9% |
| DoS | 74,663 | 5.3% |
| Spoofing RPM | 54,900 | 3.9% |
| Spoofing Speed | 24,951 | 1.8% |
| Spoofing Steering | 19,977 | 1.4% |
| Spoofing Gas | 9,991 | 0.7% |
| **Total** | **1,408,219** | 184,482 attacks (13.1%) |

(Class counts from Le & Alsmadi, arXiv:2512.14958.)

**Known issues, all must be handled:**
1. **Class imbalance** → class weights; report per-class F1 / macro-F1, not accuracy.
2. **Many duplicate rows** (ECUs repeat messages; the dataset FAQ says unique rows are limited, ~15k is mentioned as a threshold for needing more data) → **deduplicate BEFORE splitting**, report unique rows per class, check for identical feature vectors with different labels.
3. **No timestamps** → per-message model uses content only; the PC replay script sets timing; timing features are future work.
4. **Suspiciously high published scores** (~99.9%); the dataset creators note speed spoofing resembles benign traffic → honest evaluation is a selling point of this project.
5. Label columns may contain extra spaces → strip on load.

Alternatives considered and rejected: CICIoT2023 (IP network, not CAN, overused), ASCAD (side-channel, needs oscilloscope). Kept for future work: HCRL Car-Hacking (timestamps), ROAD by ORNL (stealthier attacks, timestamps).

## 5. Hardware

### Decided
- **Detector board: STM32 NUCLEO-F446RE** (Cortex-M4F 180 MHz, 512 KB flash, 128 KB SRAM, bxCAN, RTC tamper input, on-board ST-LINK, reversible RDP Level 1).
- Why not ESP32: its security features (secure boot, flash encryption, JTAG disable) are one-time eFuses → risky to rehearse demos. Why not STM32H7: overkill for a ~1 KB model and harder (caches, memory domains); kept as future work (AI CAN gateway).
- Attacker / traffic source: **PC + USB-to-CAN adapter** running Python (`python-can`). (Raspberry Pi was the first idea, replaced by the PC.)

### What the student already has (from a photo)
- Nucleo-64 board **MB1136 rev C** → this board design is shared by several Nucleo-64 models; **verify the chip reads STM32F446RE**.
- **Waveshare SN65HVD230 CAN board** (3.3 V transceiver, correct for STM32). Probably has an on-board 120 Ω resistor; verify.
- **USB-to-CAN adapter** (black box, Chinese brand, screw terminals CAN-H / GND / CAN-L, ACT LED, yellow jumper labeled "120欧电阻" = 120 Ω termination, keep it ON). **Exact model and protocol unknown → must be identified on Arch** (see §11).
- USB-A to **Mini-USB** cable (fits the Nucleo).

### Still to buy
- Male-to-female jumper wires (Nucleo Arduino headers are female, Waveshare pins are male).
- Short twisted pair for CAN-H/CAN-L.
- Micro-switch or reed switch + small plastic box (tamper demo).
- Optional: multimeter (expect ~60 Ω between CAN-H and CAN-L with power off), CR2032 holder on VBAT, 0.96" I2C OLED, extra LEDs.

### Wiring

| From | To |
|---|---|
| Nucleo 3V3 | Waveshare 3.3V |
| Nucleo GND | Waveshare GND |
| Nucleo D14 = **PB9 (CAN1_TX)** | Waveshare CTX/TX |
| Nucleo D15 = **PB8 (CAN1_RX)** | Waveshare CRX/RX |
| Waveshare CANH | Adapter CAN-H |
| Waveshare CANL | Adapter CAN-L |
| Nucleo GND | Adapter GND (common ground) |
| Lid switch | **PC13 = RTC_TAMP1** (also the blue user button on the Nucleo) |

Confirm PB8/PB9 and PC13 alternate functions in STM32CubeMX.

**Bit timing for 500 kbit/s:** APB1 = 45 MHz (core at 180 MHz), prescaler 5 → tq ≈ 111 ns; 1 + BS1 15 + BS2 2 = 18 tq = 2 µs → 500 kbit/s, sample point ≈ 89%. Recompute if the clock tree differs (CubeMX shows the result). CAN filter: accept all IDs (the IDS must see unknown IDs).

## 6. Machine-learning pipeline

1. Load the six decimal CSVs, strip label whitespace.
2. **Deduplicate** on the 9 features + class; report unique rows per class; check label conflicts.
3. Stratified split **70 / 10 / 20** (test set used once). If a class has too few unique rows, report it and merge/drop or use the binary task.
4. Features: `ID/2047` and each byte `/255` (the exact values the STM32 has per frame). Optional cheap window features (share of the last N frames with this ID, ID-seen-in-benign flag), computed identically on device.
5. **Baseline: Random Forest** (≈50 trees, depth 12, class_weight balanced); exportable to C via emlearn/micromlgen.
6. **Main model: MLP 9 → 32 → 16 → 6** (ReLU, softmax) = **950 parameters**; Adam 1e-3, batch 256, balanced class weights, early stopping (patience 10), fixed seeds. Optional binary model (benign vs attack).
7. **Post-training full-int8 quantization** (TFLite, representative dataset ~2000 rows, int8 input/output).
8. **Deploy with X-CUBE-AI** in STM32CubeMX: Analyze (flash/RAM), Validate on desktop + on target, generate C.
9. Evaluation: per-class precision/recall/F1, macro-F1, confusion matrix, benign false-positive rate, float vs int8, generalization test (train without one spoofing class, check the binary model still flags it).
10. Training runs on a laptop or Google Colab; no GPU needed.

**Real-time budget:** at 500 kbit/s a full bus is ≈ 3,700–4,500 frames/s → ≈ 220–270 µs per frame for everything.

**Expected values (targets, NOT measured; must be replaced by real measurements):**

| Metric | Expected value |
|---|---|
| Model size (weights) | 1.1 KB (1,112 bytes, computed: 896 int8 weights + 54 int32 biases) |
| Total AI footprint | 20 KB flash, 1 KB RAM |
| Inference time per frame | 25 µs |
| Total processing per frame | 40 µs |
| Macro-F1 float32 (deduplicated) | 0.95 |
| Macro-F1 int8 | 0.94 |
| Macro-F1 without dedup | 0.99 |
| Per-frame benign false-positive rate | 0.1% |
| False alarms per minute (with k-of-n smoothing) | 0.5 |

Note: false alarms/min = FPR × frames/s × 60, so smoothing (e.g. 3 suspicious frames of the same ID out of the last 10) is required.

## 7. Firmware architecture (STM32, C, HAL, STM32CubeIDE)

Two images:

| Flash region | Address | Content |
|---|---|---|
| Sectors 0–2 (3 × 16 KB) | 0x08000000–0x0800BFFF | Bootloader + public key (write-protected) |
| Sector 3 (16 KB) | 0x0800C000–0x0800FFFF | Image header: magic, version, size, 64-byte signature |
| Sectors 4–7 | 0x08010000–0x0807FFFF | Application (448 KB) |

Application data path:
1. CAN RX interrupt (`HAL_CAN_RxFifo0MsgPendingCallback` + `HAL_CAN_GetRxMessage`) pushes the frame + timestamp into a **ring buffer** (nothing else in the ISR; count overflows).
2. Main loop pops frames → **rules** (DLC valid, known ID, per-ID rate) → features → int8 quantize → **model** (X-CUBE-AI) → decision (rule failed or attack class above threshold, with k-of-n smoothing).
3. Alert: LED LD2 (PA5) + JSON line over USART2 (ST-LINK virtual COM) to the PC dashboard.
4. IWDG refreshed each loop. Inference time measured with the DWT cycle counter (`DWT->CYCCNT`, 180 cycles = 1 µs).

## 8. Security architecture (the three required layers)

### Threat model
| Asset | Threat | Attacker capability |
|---|---|---|
| Correct vehicle data | Forged/flooding frames | Bus access (OBD-II, compromised ECU) |
| Firmware + trained model | Extraction via SWD | Physical possession + debugger |
| Secrets (keys) | Tampering after opening the box | Physical access |
| Detector integrity | Malicious firmware disabling detection | Ability to reflash |
| Availability | Crash/hang from malformed input or glitches | Bus access, power glitches |

### Network layer
- **AI detection** on every frame (main contribution).
- **Rules**: known-ID whitelist (e.g. DoS ID 0x000 never seen in benign), DLC check, per-ID rate check.
- **Optional SecOC-style authentication** (AUTOSAR Secure Onboard Communication): truncated AES-128-CMAC + freshness counter in the payload (e.g. 4 data bytes + 1 freshness + 3 MAC). Prevents forgery and replay, not DoS, no encryption. On the F446 (no AES hardware) done in software (mbedTLS). Demo on 1–2 IDs only (dataset frames have no MACs).

### Physical layer
- **RDP Level 1** via STM32CubeProgrammer option bytes: blocks flash readout via debug; regression to Level 0 mass-erases flash. **Never use Level 2 (0xCC): permanent, locks the board forever.**
- **RTC tamper** on PC13: lid switch; tamper event erases RTC backup registers (where secrets/keys live) and raises an interrupt; with a coin cell on VBAT it works unpowered.
- **BOR level 3** (~2.7 V) against simple voltage glitches (qualitative only).

### Logical layer
- **Secure boot**: bootloader computes SHA-256 of the app (mbedTLS, software) and verifies an **ECDSA P-256** signature (micro-ecc `uECC_verify`, curve secp256r1) with the embedded public key; valid → set VTOR + MSP, jump to 0x08010000; invalid → refuse, blink, log. Signing on the PC with Python `cryptography` (raw 64-byte r‖s for micro-ecc). Signed version number → anti-rollback. First step: simple hash check, then signature.
- **WRP** on sectors 0–3.
- **IWDG** (e.g. 100 ms timeout).
- **Input validation** (DLC ≤ 8, bounds checks); optional MPU to make SRAM non-executable.

### Demonstrations (expected result: all pass)
| ID | Demo |
|---|---|
| N1 | PC injects DoS → alert |
| N2 | PC injects speed spoofing → alert |
| N3 (optional) | Forged frame without valid MAC → rejected |
| P1 | ST-LINK flash read works at RDP 0, fails at RDP 1 |
| P1b | RDP 1 → 0 regression mass-erases flash |
| P2 | Opening the lid erases backup registers + alarm |
| L1 | Modified firmware (one byte changed / wrong key) refused at boot |
| L1c | Write to bootloader sectors fails (WRP) |
| L2 | Deliberate main-loop hang → IWDG reset, logged |

## 9. Incident-analysis layer + PC dashboard (added late in the conversation)

Goal: not just "an LED turned on", but **what happened, exactly**.

1. **STM32**: already knows the attack type (6-class model). Sends structured JSON lines; aggregates alerts (rate-limited) with `n` = frames represented.
2. **PC dashboard** (Python + **Streamlit**, already built in the cloud session, see §10): live status of the three layers (OK / WARNING / ALERT), KPIs, traffic and suspicious-frame charts, incident list, export JSON/CSV, session recording + replay, and a **built-in simulator** with buttons for every attack (DoS, spoof speed/RPM/gas/steering, tamper, modified firmware, watchdog hang) so it can be demoed without hardware.
3. **Explanation**: compares flagged frames with a **normal profile** (per benign ID: min/max of each byte) built from CICIoV2024, e.g. "DATA_3 = 200 (normal range 0–120)", "ID 0x000 never appears in normal traffic". CICIoV2024 doesn't document which ID is speed/RPM/etc., but the IDs targeted in each spoofing file reveal it → readable names.
4. **Report**: **template-based now** (deterministic, cannot hallucinate, can't fail during the demo). **Later**: a **local LLM via Ollama** only rewrites the template summary into natural language + recommendation, with instructions not to add facts; template text is the fallback if the LLM is unavailable.

**JSON line protocol (STM32 → PC, 115200 baud, one object per line):**
```
{"t":"stats","fps":1012,"infer_us":24}                                  once per second
{"t":"alert","cls":"spoofing-SPEED","id":"0x0B4","conf":97,"n":10,
 "data":[0,0,0,200,0,0,0,0],"why":"rate"}                               flagged frames, max ~1 line/ID/100 ms
{"t":"event","kind":"tamper"}                                           also boot_refused, watchdog_reset,
                                                                        wrp_violation; boot_ok (+version),
                                                                        rdp_level (+value)
```
`conf` may be 0–1 or 0–100 (integer avoids float printf on the MCU). IDs as hex strings "0x0B4". Non-JSON lines are shown as raw text. At 115200 baud only ~90 such lines/s fit → the firmware must aggregate during floods.

Severity mapping used: DoS high, speed high, RPM medium, gas critical, steering critical, tamper critical, modified firmware high, watchdog medium.

## 10. What exists right now

| Item | Status | Where |
|---|---|---|
| 6-slide deck, English (cover, motivation, dataset, system design, three-layer security, evaluation) | Done | claude.ai artifact (private), titled "TinyML CAN-Bus IDS" |
| Same deck in French | Done | claude.ai artifact, "IDS TinyML pour bus CAN" |
| 31-page PDF report (everything in §3–§8 + test plan, schedule, BOM, risks, future work, references, code skeletons for training, PC replay script, firmware, secure boot/signing) | Done | `CAN_IDS_Project_Report.pdf` (downloaded by the student) |
| PC dashboard (Streamlit: `app.py`, `engine.py`, `sources.py`, `make_profile.py`, README) | Built; engine unit-tested; UI tested with the simulator; **serial mode not yet tested with real hardware** | Zip delivered separately (`can-ids-dashboard`) |
| Slides/report do **not** yet mention the incident-analysis/dashboard layer | To do | — |
| Hardware | Partly in hand (see §5) | — |
| ML notebook, firmware, bootloader | Not started | — |

## 11. Arch Linux environment notes

- **Python**: system Python is externally managed → use a venv: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`.
- **Serial access**: `/dev/ttyACM*` / `/dev/ttyUSB*` belong to the `uucp` group: `sudo usermod -aG uucp $USER`, then log out/in. The Nucleo's ST-LINK VCP is usually `/dev/ttyACM0`.
- **ST tools**: STM32CubeIDE, STM32CubeMX (+ X-CUBE-AI pack), STM32CubeProgrammer have Linux installers on st.com; AUR packages also exist (check current names). ST-LINK udev rules come with CubeProgrammer, or the open-source `stlink` package.
- **can-utils** (`candump`, `cansend`): install via pacman or AUR.
- **Identify the USB-CAN adapter first** (plug in, then `lsusb` and `sudo dmesg | tail`):
  - Appears as a native `can0` (gs_usb / candleLight): `sudo ip link set can0 type can bitrate 500000 && sudo ip link set can0 up`, test with `candump can0`; python-can `interface="socketcan"`.
  - Appears as `/dev/ttyACM0` with slcan firmware: `sudo slcand -o -c -s6 /dev/ttyACM0 can0 && sudo ip link set can0 up` (`-s6` = 500 kbit/s).
  - Appears as `/dev/ttyUSB0` (e.g. CH340) with a proprietary protocol: many cheap boxed "USB-CAN" adapters use a vendor serial protocol; check whether python-can supports it (e.g. its `seeedstudio` interface supports one common protocol) or find the model name. **This is the first risk to clear.**

## 12. Plan (≈ 8 weeks, 10–15 h/week; ML work first because it needs no hardware)

| Week | Work |
|---|---|
| 1 | Hardware check (adapter on Arch). Download CICIoV2024; load, clean, dedupe; RF baseline |
| 2 | MLP + class weights; evaluation; int8; X-CUBE-AI analyze/validate |
| 3 | STM32CubeIDE; model on board fed over USB serial; timing |
| 4 | CAN bus wiring; PC replay/attack script; live detection; rules; JSON protocol → dashboard |
| 5 | Physical layer: RDP 1, tamper + backup registers, BOR |
| 6–7 | Logical layer: hash boot check → ECDSA signature; WRP; IWDG; input validation |
| 8 | Measurements, demo video, report update, slides |

Priority if time runs short: network IDS → RDP + tamper → hash boot check → ECDSA → incident LLM → SecOC.

**Immediate next steps:**
1. Identify the USB-CAN adapter on Arch and get `candump` working.
2. First CAN milestone (before any AI): STM32 sends a frame every 100 ms at 500 kbit/s, seen on the PC; then the PC sends a frame and the Nucleo toggles its LED.
3. Write the training notebook (§6).
4. Make the firmware emit the JSON protocol and test the dashboard in serial mode.
5. Update slides + report with the incident-analysis layer.

**Risks:** adapter not supported by python-can; CAN wiring/bitrate/termination issues; results too good (dedupe!); speed spoofing hard per message (rules/window features); locking the board (never RDP 2; enable protections last); bootloader bricking (develop at RDP 0, WRP off).

## 13. Future work (mention in report/slides, not in scope now)
- **AI-powered CAN gateway on STM32H7** (NUCLEO-H753ZI with HW crypto, or H723ZG): two FDCAN buses (untrusted infotainment/OBD side vs trusted powertrain side), whitelist + rate rules + **sequence model (1D-CNN/GRU) using inter-arrival times**, trained on Car-Hacking/ROAD; forward-then-quarantine design, metric = forged frames passed before blocking; demo with a second board as "engine ECU" + OLED dashboard (spoofed speed shows without gateway, blocked with it). ~2–4 extra weeks.
- Full SecOC, CAN FD, adversarial evaluation (craft evasive spoofed frames, then harden), local LLM incident reports.

## 14. Resume framing
- "Built an AI-based intrusion detection system for automotive CAN bus on STM32F446, detecting DoS and spoofing attacks in real time ([X]% F1, [Y] µs inference, [Z] KB model)."
- "Implemented defense in depth on an embedded device: secure boot with firmware signature verification, readout protection, and RTC tamper detection."
- Make it stand out with: a 1–2 min demo video, real numbers, a clean GitHub repo (README, diagram, results, reproduction steps), and the honest-evaluation story (dedupe before split).

---

## 15. Conversation history (chronological)

Every question the student asked, with the substance of each answer.

1. **"Find a free public dataset for an embedded security + AI project, impressive for my resume."** Explained the idea (train on a PC, run the model on a board = TinyML). Proposed CICIoV2024 (car CAN bus, top pick), CICIoT2023 (IoT network, easiest), ASCAD (side-channel, hardcore). Recommended CICIoV2024 with two boards on a CAN bus.
2. **"Which boards for CICIoV2024?"** First suggested ESP32-S3 as detector + Raspberry Pi as attacker, SN65HVD230 transceivers (3.3 V, avoid TJA1050 5 V modules), 120 Ω terminations, twisted pair; STM32 mentioned as the more "industrial" option.
3. **"Is it feasible? How does training happen?"** Yes, 4–6 weeks; training on laptop/Colab; steps: clean, features (ID + 8 bytes, optional windows), RF baseline, small NN with class weights, honest evaluation, int8 quantization, deploy, test on the real bus.
4. **"Create a 5-slide presentation for the professor."** Built an English deck (cover, motivation, dataset with class table, system design, evaluation + 6-week plan) after verifying dataset facts on the official page.
5. **"Remove the 6-week plan and make a French version."** Done (French number formatting, translated speaker notes).
6. **"I want this on an STM32."** Switched both decks to NUCLEO-F446RE + SN65HVD230 + X-CUBE-AI.
7. **"Can the attack be simulated by PC?"** Yes: PC + USB-CAN adapter (best), PC + second Nucleo as bridge, or PC → STM32 over USB serial (easiest, start there).
8. **"There must be at least one attack per section: physical, logical, networking."** Proposed network = CAN DoS/spoofing; physical = SWD firmware readout; logical = evasion attack on the model (or malicious firmware update).
9. **"Should I change the project?"** No, keep it and add the physical and logical parts on the same board.
10. **Clarification: it's *protection* that must be at the three layers.** Network = AI IDS (+ optional SecOC); physical = RDP Level 1 + RTC tamper switch (+ BOR); logical = secure boot with signature + WRP + watchdog + frame validation.
11. **"Add these to the presentations."** Added slide "Three layers of protection on one device" to both decks (now 6 slides); attacker switched from Raspberry Pi to PC + USB-CAN; evaluation slide updated.
12. **"Is STM32 hard, should I switch to ESP32?"** Stay with STM32: reversible protections (ESP32 eFuses are permanent), tamper pin, internal flash, automotive credibility; hardest part = secure bootloader; overall medium difficulty.
13. **"Is the model training feasible?"** Yes, easiest part: small data, few unique rows after dedupe, ~1 KB model, fits the ~200 µs per-frame budget; the real challenge is honest evaluation.
14. **"Which STM32 to buy?"** NUCLEO-F446RE (optional NUCLEO-F439ZI for HW crypto); avoid Blue Pill and TrustZone chips; shopping list.
15. **"No H7?"** Possible but overkill and harder (cache, memory domains); if H7 then NUCLEO-H753ZI (crypto) or H723ZG.
16. **"Good for my resume?"** Yes, if executed: demo video, real numbers, GitHub repo, honest evaluation; resume lines proposed.
17. **"Impressive AI projects with an H7?"** AI CAN gateway (best), face-recognition access control with anti-spoofing, runtime attack detection on the chip, speaker verification, object detection, predictive maintenance; avoid "LLM on MCU".
18. **"Explain the AI-powered CAN gateway."** Domains + central gateway concept, two buses, rules + sequence model with timing, Car-Hacking/ROAD datasets, quarantine design, three layers, demo, H753ZI hardware, +2–4 weeks.
19. **"How many weeks realistically?"** F446 version ≈ 8 weeks part-time (4–5 full-time); H7 gateway ≈ 11–12 weeks. Week-by-week plan given.
20. **"Do the F446 version."** Confirmed; decks already match; H7 gateway becomes future work.
21. **"What is SecOC?"** AUTOSAR Secure Onboard Communication: MAC (AES-CMAC) + freshness counter, truncated in 8-byte CAN frames; prevents forgery/replay, not DoS, no encryption; complements the AI detector; optional in this project.
22. **"Give me everything in detail like a report, as a PDF."** Produced the 31-page report (sections 1–10, references, appendices with code skeletons). Results marked [to be measured].
23. **"Give expected macro-F1, false-alarm rate, inference time, model size, which demos worked."** Gave estimates; clarified nothing has been run yet.
24. **"Remove reasoning and confidence."** / **"Exact numbers, not ranges."** Final single-value targets are in §6; all security demos expected to pass. They are targets, to be replaced by measurements.
25. **"What equipment to buy?"** Full list (see §5).
26. **"Can we add an AI layer that tells exactly what happened / what kind of attack?"** Yes: incident-analysis layer = STM32 aggregates and explains, PC dashboard, LLM report on the PC (local via Ollama), only from structured facts.
27. **"Which one is better?"** Template first (deterministic, can't hallucinate, never fails in the demo), LLM on top as hybrid with template fallback; run the LLM locally.
28. **"Do the dashboard first."** Built and tested the Streamlit dashboard with simulator, serial and replay modes (see §9–10).
29. **Photo of the hardware.** Identified parts, adapter protocol must be checked, termination ~60 Ω check, wiring table, still-to-buy list, first CAN milestone.
30. **"I'm on Arch Linux and want to continue in Claude Code."** → this file.

## 16. How to help the student from here
- Start with §12 "Immediate next steps", in order.
- Keep explanations simple and step by step; the student is new to STM32 and CubeIDE.
- Never present expected values as measured results.
- Never suggest RDP Level 2.
- When the student gets real numbers, update the report results table and the slides.
