#!/usr/bin/env bash
# Build firmware/can_ids_fw without the IDE, with STM32CubeIDE's Debug flags.
#
#     bash firmware/build.sh                 # -> firmware/can_ids_fw/build/can_ids_fw.elf
#
# Uses the GNU Tools for STM32 bundled with CubeIDE (the system arm-none-eabi-gcc
# has no newlib). Set GCC_BIN to its tools/bin folder if it is not found.
# The detector (ids_detector.c) is compiled with -O2 through a #pragma, so the
# timings do not depend on this -O0 Debug build.
#
# Flash (CubeIDE's STM32_Programmer_CLI):
#     STM32_Programmer_CLI -c port=SWD mode=UR reset=HWrst -w firmware/can_ids_fw/build/can_ids_fw.elf -v -rst
set -u
GCC_BIN=${GCC_BIN:-$(ls -d "$HOME"/Downloads/makeself_dir_*/y/plugins/com.st.stm32cube.ide.mcu.externaltools.gnu-tools-for-stm32.*/tools/bin 2>/dev/null | tail -1)}
[ -x "$GCC_BIN/arm-none-eabi-gcc" ] || { echo "CubeIDE's arm-none-eabi-gcc not found: set GCC_BIN"; exit 1; }
export PATH="$GCC_BIN:$PATH"

P=$(cd "$(dirname "$0")/can_ids_fw" && pwd)
B="$P/build"
rm -rf "$B"; mkdir -p "$B"; cd "$P"
ARCH="-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard"
CFLAGS="$ARCH -std=gnu11 -O0 -g3 -Wall -ffunction-sections -fdata-sections --specs=nano.specs \
 -DUSE_NUCLEO_64 -DUSE_HAL_DRIVER -DSTM32F446xx -DDEBUG \
 -ICore/Inc -IDrivers/STM32F4xx_HAL_Driver/Inc -IDrivers/STM32F4xx_HAL_Driver/Inc/Legacy \
 -IDrivers/BSP/STM32F4xx-Nucleo -IDrivers/CMSIS/Device/ST/STM32F4xx/Include -IDrivers/CMSIS/Include"
ok=1
while IFS= read -r f; do
  arm-none-eabi-gcc $CFLAGS -c "$f" -o "$B/$(basename "$f" .c).o" 2>>"$B/warn.txt" || ok=0
done < <(find Core Drivers -name "*.c" -not -path "*/CMSIS/*")
arm-none-eabi-gcc $ARCH -c Core/Startup/startup_stm32f446retx.s -o "$B/startup.o" || ok=0
arm-none-eabi-gcc $ARCH --specs=nano.specs --specs=nosys.specs -TSTM32F446RETX_FLASH.ld -Wl,--gc-sections \
  -Wl,-Map="$B/can_ids_fw.map" "$B"/*.o -o "$B/can_ids_fw.elf" -Wl,--start-group -lc -lm -Wl,--end-group \
  2>>"$B/warn.txt" || ok=0
[ -f "$B/can_ids_fw.elf" ] && arm-none-eabi-size "$B/can_ids_fw.elf"
grep -E "error|warning:" "$B/warn.txt" | grep -v "has a LOAD segment with RWX" | head -15
[ $ok = 1 ] && echo "build OK: $B/can_ids_fw.elf" || { echo "BUILD FAILED"; exit 1; }
