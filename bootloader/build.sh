#!/usr/bin/env bash
# Build the secure bootloader (32 KB at 0x08000000) with CubeIDE's GCC, like firmware/build.sh.
#
#     python pc/sign_firmware.py keygen      # once: signing key pair -> keys/ + bootloader/inc/fw_pubkey.h
#     bash bootloader/build.sh               # -> bootloader/build/bootloader.elf
#
# Reuses the application's SHA-256 and micro-ecc sources (firmware/can_ids_fw/Core/Src).
# Install (once; erases the old application, then flash a signed one, see README):
#     STM32_Programmer_CLI -c port=SWD mode=UR reset=HWrst -e all -w bootloader/build/bootloader.elf -v
set -u
GCC_BIN=${GCC_BIN:-$(ls -d "$HOME"/Downloads/makeself_dir_*/y/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.*/tools/bin 2>/dev/null | tail -1)}
[ -x "$GCC_BIN/arm-none-eabi-gcc" ] || { echo "CubeIDE's arm-none-eabi-gcc not found: set GCC_BIN"; exit 1; }
export PATH="$GCC_BIN:$PATH"

R=$(cd "$(dirname "$0")/.." && pwd)
BL="$R/bootloader"; APP="$R/firmware/can_ids_fw"; B="$BL/build"
[ -f "$BL/inc/fw_pubkey.h" ] || { echo "bootloader/inc/fw_pubkey.h missing: run python pc/sign_firmware.py keygen"; exit 1; }
rm -rf "$B"; mkdir -p "$B"
ARCH="-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard"
CFLAGS="$ARCH -std=gnu11 -Os -g -Wall -ffunction-sections -fdata-sections --specs=nano.specs -DSTM32F446xx \
 -I$BL/inc -I$APP/Core/Inc -I$APP/Core/Src/uecc -I$APP/Drivers/CMSIS/Device/ST/STM32F4xx/Include -I$APP/Drivers/CMSIS/Include \
 -DuECC_SUPPORTS_secp160r1=0 -DuECC_SUPPORTS_secp192r1=0 -DuECC_SUPPORTS_secp224r1=0 -DuECC_SUPPORTS_secp256k1=0"
ok=1
for f in "$BL/src/main.c" "$APP/Core/Src/sha256.c"; do
  arm-none-eabi-gcc $CFLAGS -c "$f" -o "$B/$(basename "$f" .c).o" 2>>"$B/warn.txt" || ok=0
done
arm-none-eabi-gcc $CFLAGS -O2 -c "$APP/Core/Src/uecc/uECC.c" -o "$B/uECC.o" 2>>"$B/warn.txt" || ok=0
arm-none-eabi-gcc $ARCH -c "$BL/src/startup_stm32f446retx.s" -o "$B/startup.o" || ok=0
arm-none-eabi-gcc $ARCH --specs=nano.specs --specs=nosys.specs -T"$BL/STM32F446_BOOT.ld" -Wl,--gc-sections \
  -Wl,-Map="$B/bootloader.map" "$B"/*.o -o "$B/bootloader.elf" -Wl,--start-group -lc -lm -Wl,--end-group \
  2>>"$B/warn.txt" || ok=0
[ -f "$B/bootloader.elf" ] && arm-none-eabi-size "$B/bootloader.elf"
grep -E "error|warning:" "$B/warn.txt" | grep -v -e "has a LOAD segment with RWX" -e "is not implemented and will always fail" | head -15
[ $ok = 1 ] && echo "build OK: $B/bootloader.elf" || { echo "BUILD FAILED"; exit 1; }
