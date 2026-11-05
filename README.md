# TinyML Intrusion Detection for an Automotive CAN Bus (STM32F446)

An STM32 NUCLEO-F446RE on a CAN bus runs a small int8 neural network that classifies
every CAN frame in real time as normal traffic, DoS or one of four spoofing attacks.
It is trained on the public **CICIoV2024** dataset, recorded on a 2019 Ford. The device is
also protected at the physical, logical and network layers.

Full design and plan: [`docs/PROJECT_HANDOFF.md`](docs/PROJECT_HANDOFF.md).

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
