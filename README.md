# TinyML Intrusion Detection for an Automotive CAN Bus (STM32F446)

An STM32 NUCLEO-F446RE on a CAN bus checks every CAN frame in real time: rules
(ID whitelist, timing) plus a small int8 neural network (1,441 parameters) that
spots forged values on legitimate IDs. It raises ALERT / WARNING with the bytes
that triggered it. Trained and tested on the **ROAD** dataset (real vehicle,
masquerade attacks); **CICIoV2024** is used for the rules layer and an
honest-evaluation finding. Results: [`results/RESULTS.md`](results/RESULTS.md).

## Project layout

| Folder | Content |
|---|---|
| `ml/` | Dataset preparation, training, evaluation, quantization (Python) |
| `firmware/` | STM32 application: CAN reception, detector, alerts (C, STM32CubeIDE) |
| `bootloader/` | Secure bootloader with signature check (C) |
| `pc/` | PC tools: CAN replay/attack script, dashboard |
| `data/` | Dataset (not in git: download it yourself, see below) |
| `results/` | Metrics, confusion matrices, data reports produced by the scripts |
| `docs/` | Design documents |

## 1. Setup (Arch Linux)

```bash
uv venv --python 3.12 .venv          # Python 3.12: TensorFlow is needed later and lags new Pythons
source .venv/bin/activate
uv pip install -r ml/requirements.txt
```

## 2. Get the dataset

1. Open https://www.unb.ca/cic/datasets/iov-dataset-2024.html and go to the download
   (http://cicresearch.ca/IOTDataset/CICIoV2024/). CIC asks you to fill in a short form first.
2. Download the **decimal** version.
3. Copy its CSV files (benign, DoS, spoofing-GAS, -RPM, -SPEED, -STEERING_WHEEL) into
   `data/raw/decimal/`.

Any `*.csv` in that folder is loaded. The class comes from the `specific_class` column,
so the file names don't matter.

## 2b. Get the ROAD dataset (used to train the AI model)

ROAD (ORNL, CC-BY-4.0, no registration) has forged frames on **legitimate** IDs, which is where an
AI detector is actually needed. CICIoV2024 attacks only use IDs that never appear in normal traffic,
so an ID whitelist alone catches all of them (see `results/data_report.md`).

```bash
mkdir -p data/raw/road && cd data/raw/road
curl -L -o road.zip https://zenodo.org/api/records/10462796/files/road.zip/content   # 557 MB
unzip road.zip 'road/readme.md' 'road/ambient/*' 'road/attacks/*'                     # 1.3 GB
cd ../../../ml/src && python road_data.py     # -> data/processed/road/, results/road_report.md
```

Paper: Verma et al., "A comprehensive guide to CAN IDS data and introduction of the ROAD dataset",
PLoS ONE 19(1), e0296879, 2024.

## 2c. Get CAN-MIRGU (second car: independent check)

CAN-MIRGU (CC BY 4.0): a 2016 electric car, 17 h of normal driving over 6 days and
36 attack recordings with per-frame labels. The UCI repository's zip (doi
10.24432/C5H911) was broken when we tried it (empty archive header, then zeros),
so download the authors' Google Drive folder
(linked from https://github.com/sampathrajapaksha/CAN-MIRGU) into `data/raw/mirgu/drive/`
(5.5 GB of logs, ~49 files):

```bash
uv pip install --python .venv/bin/python gdown
mkdir -p data/raw/mirgu/drive && cd data/raw/mirgu/drive
gdown --folder --continue --timeout 60 --retries 20 "https://drive.google.com/drive/folders/1uUKLEu_tFVMy9WkDnf1rqqPwuQLQFwBL"
cd ../../../.. && python ml/src/mirgu_data.py    # -> data/processed/mirgu/, results/mirgu/mirgu_report.md
```

(`--timeout` matters: without it a stalled Google Drive transfer waits forever.)

Paper: Rajapaksha et al., "CAN-MIRGU: A Comprehensive CAN Bus Attack Dataset from
Moving Vehicles for Intrusion Detection System Evaluation", VehicleSec 2024,
doi 10.24432/C5H911.

ROAD has no per-frame labels. `road_data.py` labels a frame as an attack when it has the target ID,
lies inside the injection interval and matches the injected payload (from `capture_metadata.json`).
The 4 accelerator captures have no injected frames and are skipped.

## 3. Prepare the data and train the baseline

```bash
cd ml/src
python prepare_data.py               # clean, deduplicate, split 70/10/20 -> data/processed/
python baseline_rf.py                # Random Forest, scored on the validation set
```

Read `results/data_report.md` first: it gives the number of **unique** rows per class,
which decides what the model can honestly learn.

To show how much duplicate rows inflate the scores (the "honest evaluation" result):

```bash
python prepare_data.py --no-dedup    # -> data/processed_nodedup/
python baseline_rf.py --nodedup
```

The **test set is scored only with `--final`**. Use it once, at the very end, for the
numbers that go into the report.

### Notes on the method
- **Duplicates are removed before splitting.** Otherwise copies of the same frame end up in
  both train and test, and the model is graded on frames it has memorised.
- **Classes with fewer than 10 unique rows** (a DoS flood can be a single repeated frame)
  cannot be split. They are copied into all three splits and marked *memorised* in the report.
  Their score does not measure generalisation; the rule-based checks (unknown ID) cover them.
- **Label conflicts**: identical frames (same ID + bytes) labelled with different classes are
  counted in the report. A per-frame model cannot get those right, so they set an upper limit
  on its accuracy. `--drop-conflicts` removes them; keeping them is the honest default.
- **Metrics**: per-class F1, macro-F1, confusion matrix, and the false-positive rate on benign frames.
  Accuracy alone is meaningless with 87% benign traffic.

## 4. ROAD detector (the AI) and the STM32 version

```bash
cd ml/src
python road_data.py                  # parse the ROAD logs -> data/processed/road/
python road_rules.py                 # rules only (and builds results/road_profile.json)
python road_train_mlp.py             # train + int8 quantize + threshold on val
python road_train_mlp.py --final     # score the test split (results in RESULTS.md)
python synthetic_attacks.py          # model v2: preview the synthetic random-data attacks

python mcu_model.py                  # check the C arithmetic of the int8 network against TFLite
python export_c.py                   # write the firmware headers (tables, weights, self-test data)
python check_c_detector.py           # C detector vs Python on every val/test frame (bit-exact)
```

Which model these scripts train / export is set by `MODEL_VERSION` in
`ml/src/common.py`: `"v2"` (on the chip now: + synthetic random-data attacks, see
RESULTS.md section 5) or `"v1"` (the original model, files `results/road_mlp_*`).

Firmware: `firmware/can_ids_fw` (STM32CubeIDE project). At boot it runs the detector
self-test on 3,600 real ROAD frames and prints the result and the time per frame on
the serial port (`/dev/ttyACM0`, 921600 baud), then reports incidents as JSON lines. PC side of the bus: `pc/adapter_test.py`
(USB-CAN adapter, Robotell protocol, 1 Mbaud serial).

Build, sign and flash without the IDE (CubeIDE's compiler and STM32_Programmer_CLI). The
application runs behind a **secure bootloader** (`bootloader/`, see "Device protection"):
it starts only firmware signed with the private key in `keys/`.

```bash
bash firmware/build.sh                              # -> firmware/can_ids_fw/build/can_ids_fw.bin
python pc/sign_firmware.py sign --version 3         # version must be >= the last one installed
python pc/sign_firmware.py flash                    # header + application at 0x0800C000, then restart
```

Installing the bootloader on a new board (once; the full erase removes any old firmware):

```bash
python pc/sign_firmware.py keygen                   # once per project: keys/fw_signing_key.pem + bootloader/inc/fw_pubkey.h
bash bootloader/build.sh
STM32_Programmer_CLI -c port=SWD mode=UR reset=HWrst -e all -w bootloader/build/bootloader.elf -v
python pc/sign_firmware.py sign --version 1 && python pc/sign_firmware.py flash
```

Keep a backup of `keys/fw_signing_key.pem` (not in git): without it no new firmware can be
signed for boards that have this bootloader.

### CAN-MIRGU (second car)

The same scripts, with `IDS_DATASET=mirgu` (results in `results/mirgu/`):

```bash
cd ml/src
python mirgu_data.py                                  # logs -> data/processed/mirgu/ (+ data report)
IDS_DATASET=mirgu python road_profile.py              # profile (Days 1-4 + normal parts of training attack recordings)
IDS_DATASET=mirgu python road_train_mlp.py            # train + threshold on val (Day 5)
IDS_DATASET=mirgu python mirgu_eval.py --final        # rules only vs ROAD v2 cross-car vs MIRGU model, val + test
IDS_DATASET=mirgu python export_c.py                  # MIRGU headers for the firmware (plain export_c.py = ROAD)
IDS_DATASET=mirgu python check_c_detector.py          # C vs Python, bit-exact
cd ../.. && bash firmware/build.sh                    # then sign and flash as above
python pc/live_demo.py --dataset mirgu max_speedometer_attack
python pc/live_demo.py --dataset mirgu --all-test --clean-minutes 10    # ~2 h
```

Live demo (PC replays a ROAD recording on the CAN bus, the Nucleo detects it):

```bash
python pc/live_demo.py --list                                  # recordings
python pc/live_demo.py max_speedometer_attack_1_masquerade     # one attack, around the attack window
python pc/live_demo.py --all-test                              # whole test split (~31 min), results table
python pc/live_demo.py --latency                               # transport delay of the USB links alone
python pc/live_attacks.py --all                                # DoS floods + fuzzing on real IDs (not in ROAD), ~2 min
```

### Device protection (step 3)

```bash
python pc/security_demo.py status      # restart the Nucleo: reset cause, RDP / BOR / WRP settings
python pc/security_demo.py watchdog    # hang the main loop on purpose -> watchdog reset (~250 ms)
python pc/security_demo.py provision   # ECDH: the chip makes its own secret (refused if one is present)
python pc/entropy_check.py             # measure the on-chip entropy source (raw samples -> min-entropy)
python pc/secure_boot_demo.py          # modified / re-versioned / foreign-key / unsigned / older firmware: all refused
python pc/security_demo.py tamper      # press the blue button = enclosure opened -> secret erased
python pc/security_demo.py signing     # every JSON line is HMAC-signed: forged / replayed lines rejected
STM32_Programmer_CLI -c port=SWD mode=UR -ob BOR_LEV=0    # brown-out reset level 3 (2.70 V); BOR_LEV=3 = off
```

`provision` needs `uv pip install -r pc/requirements.txt` (the `cryptography` package). It keeps the
PC's copy of the derived device secret in `keys/device_secret.key` (git-ignored);
`live_demo.py` uses it to check every line from the Nucleo.

Never set RDP to Level 2 (0xCC): it is permanent and the board can never be reflashed.
