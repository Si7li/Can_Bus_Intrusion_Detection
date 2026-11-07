/* On-chip entropy for key generation (the STM32F446 has no hardware RNG).
 *
 * Source: jitter of the internal LSI RC oscillator (~32 kHz), measured by TIM5 channel 4
 * (TI4 remapped to LSI, the path meant for LSI calibration) with the 90 MHz timer clock,
 * which comes from the 8 MHz crystal. The two oscillators are independent; the RC
 * oscillator's period wanders with thermal noise, so the low bits of each measured period
 * are unpredictable. Raw samples are measured on the PC (pc/entropy_check.py), then
 * conditioned with SHA-256 here.
 */
#ifndef IDS_ENTROPY_H
#define IDS_ENTROPY_H

#include <stdint.h>

/* LSI periods per sample (input-capture prescaler: 1, 2, 4 or 8). Measured on this board
   (results/entropy_check.txt): 1 period/sample gives ~2.8 bits of min-entropy per sample
   (most-common-value and previous-sample-predictor estimates agree), the lowest correlation
   between consecutive samples (+0.39), and the fastest rate (one sample per ~32 us). */
#ifndef ENTROPY_PERIODS
#define ENTROPY_PERIODS 1u
#endif
/* 4096 samples x ~2.8 bits = ~11,500 bits estimated for a 256-bit seed: still enough if the
   true entropy were 40 times lower than measured. Takes ~0.13 s. */
#define ENTROPY_SAMPLES 4096u

typedef struct {
  uint32_t samples;
  uint32_t max_repeat;               /* longest run of identical samples (repetition count test) */
  uint32_t max_same_low_byte;        /* most frequent low byte in a 512-sample window (adaptive proportion) */
  int ok;                            /* health tests passed */
} entropy_stats_t;

void entropy_start(uint32_t periods);    /* 1, 2, 4 or 8 */
uint32_t entropy_sample(void);           /* one measured period (in 90 MHz ticks) */
void entropy_stop(void);

/* ENTROPY_SAMPLES samples -> SHA-256 -> 32-byte seed, with the two SP 800-90B health tests.
   Returns 1 if the source looked healthy (seed usable), 0 otherwise. */
int entropy_seed(uint8_t seed[32], entropy_stats_t *st);

#endif
