"""CAN-MIRGU train / val / test split. Fixed BEFORE any model was run on MIRGU.

Rules:
- normal driving is split by day: Day 1-4 train (profile + model), Day 5 val
  (threshold, false-alarm check), Day 6 test. Different days = different trips,
  so the false-alarm rate is measured on driving the detector never saw.
- attack recordings are split by attack type, never by frame. Copies of the same
  attack (real + masquerade, min speedometer 1/2/3, EMS replay + long replay,
  gear shifter 1/2) stay together. MIRGU has mostly one recording per attack
  type, so every val and test attack type is one the model never saw.
- multiple_attacks_1 contains the wiper attack (same payload), so it goes with
  wiper_warning (test). multiple_attacks_2 repeats attack types of the training
  set (FCA, brake warning, fuzzing...) in a new recording: test, the MIRGU
  equivalent of ROAD's "same attack, other instance".
- replays and suspensions are test only: the detector has no rule for them
  (a replay sends real values; a suspension sends nothing), so they measure a
  known limit, they are not used to tune anything.
  Found after the download (timestamps): the 5 suspension recordings are 26
  consecutive minutes of the 4 May drive, cut out between benign_day1_file5 and
  benign_day1_file6 (no frame is in both). Their normal parts therefore come
  from a training trip: false alarms in them are less independent than Day 6's.
- "Day 1" holds two dates: files 4-6 = 4 May 2023, files 1-3 = 5 May 2023.
- val gets one attack of each kind (masquerade, flam injection, flood of a
  known ID, fuzzing, constant payload) so the threshold is not tuned on one kind.

Profile cross-validation folds (like ROAD's FOLDS): Day 1 vs Days 2-4.

Synthetic random-data attacks (synthetic_attacks.py, same recipe as ROAD v2)
are cut from the same days: train attacks from Day 1-4, val from Day 5, test
from Day 6. LIVE_TEST_ID is a fast ID never attacked in MIRGU, always in the
synthetic test group, used for the live fuzz_masquerade test.
"""

AMBIENT_SPLIT_DAYS = {"day1": "train", "day2": "train", "day3": "train", "day4": "train",
                      "day5": "val", "day6": "test"}

ATTACK_SPLIT = {
    # ---- train
    "break_warning_attack": "train", "break_warning_masquerade_attack": "train",
    "steering_angle_attack": "train", "steering_angle_masquerade_attack": "train",
    "min_speedometer_attack_1": "train", "min_speedometer_masquerade_attack_1": "train",
    "min_speedometer_attack_2": "train", "min_speedometer_attack_3": "train",
    "fca_warning_attack": "train",
    "gear_shifter_attack_1": "train", "gear_shifter_attack_2": "train",
    "power_steering_attack": "train",
    "fuzzing_valid_ids": "train",
    "dos_attack": "train",
    # ---- val
    "break_and_fog_light_attack": "val", "break_and_fog_light_masquerade_attack": "val",
    "ems_attack": "val",
    "door_open_warning_attack": "val",
    "drive_mode_changing_attack": "val",
    "fuzzing_valid_ids_dos": "val",
    # ---- test
    "wiper_warning_attack": "test", "wiper_warning_masquerade_attack": "test",
    "multiple_attacks_1": "test",
    "max_speedometer_attack": "test",
    "parking_break_attack": "test",
    "steering_angle_replay": "test",
    "ems_replay_attack": "test", "ems_replay_long_attack": "test",
    "fuzzing_random_ids": "test",
    "reverse_speedometer_fuzzing_attack": "test",
    "multiple_attacks_2": "test",
    "id_07f_suspension_attack": "test", "id_160_suspension_attack": "test",
    "id_371_suspension_attack": "test", "id_386_suspension_attack": "test",
    "id_541_suspension_attack": "test",
}

FOLD_DAYS = [["day1"], ["day2", "day3", "day4"]]


def day_of(capture: str) -> str:
    """'benign_day3_file1' -> 'day3'"""
    return capture.split("_")[1]


def ambient_split(capture: str) -> str:
    return AMBIENT_SPLIT_DAYS[day_of(capture)]


def attack_split(capture: str) -> str:
    if capture not in ATTACK_SPLIT:
        raise KeyError(f"MIRGU recording {capture!r} has no split: add it to mirgu_split.ATTACK_SPLIT")
    return ATTACK_SPLIT[capture]


# 10 ms, 8 bytes (6 of them changing), never the target of a MIRGU spoofing attack
# (only the fuzzing recordings put FF on it): ROAD's 0x00E counterpart, chosen from
# the ID timing table, before any result.
LIVE_TEST_ID = 0x220
