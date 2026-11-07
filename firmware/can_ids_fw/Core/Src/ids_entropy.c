/* On-chip entropy: LSI period jitter measured by TIM5 (see ids_entropy.h). */
#include "ids_entropy.h"
#include "stm32f4xx.h"
#include "sha256.h"
#include <string.h>

static uint32_t prev;

void entropy_start(uint32_t periods)
{
  uint32_t psc = periods >= 8u ? 3u : periods >= 4u ? 2u : periods >= 2u ? 1u : 0u;
  RCC->CSR |= RCC_CSR_LSION;                      /* already on (IWDG, RTC); make sure */
  while (!(RCC->CSR & RCC_CSR_LSIRDY)) { }
  RCC->APB1ENR |= RCC_APB1ENR_TIM5EN;
  (void)RCC->APB1ENR;
  TIM5->CR1 = 0;
  TIM5->PSC = 0;                                  /* 2 x APB1 = 90 MHz, from the crystal */
  TIM5->ARR = 0xFFFFFFFFu;
  TIM5->OR = TIM_OR_TI4_RMP_0;                    /* TI4 = LSI (not the PA3 pin) */
  TIM5->CCER = 0;
  TIM5->CCMR2 = (1u << TIM_CCMR2_CC4S_Pos)        /* IC4 on TI4, no filter */
              | (psc << TIM_CCMR2_IC4PSC_Pos);    /* capture every 1/2/4/8 LSI periods */
  TIM5->CCER = TIM_CCER_CC4E;                     /* rising edge */
  TIM5->EGR = TIM_EGR_UG;
  TIM5->SR = 0;
  TIM5->CR1 = TIM_CR1_CEN;
  while (!(TIM5->SR & TIM_SR_CC4IF)) { }
  prev = TIM5->CCR4;
}

uint32_t entropy_sample(void)
{
  while (!(TIM5->SR & TIM_SR_CC4IF)) { }
  uint32_t v = TIM5->CCR4;                         /* reading clears CC4IF */
  uint32_t d = v - prev;
  prev = v;
  return d;
}

void entropy_stop(void)
{
  TIM5->CR1 = 0;
  RCC->APB1ENR &= ~RCC_APB1ENR_TIM5EN;
}

/* Health tests from NIST SP 800-90B section 4.4, cut-offs for H = 2.8 bits/sample (measured)
   and a false-alarm probability of 2^-30:
     repetition count: the same value 12 times in a row (1 + ceil(30 / H)) -> stuck source
     adaptive proportion: one low byte 125 times or more in a 512-sample window (binomial
       critical value) -> biased. Stricter than 90B, which only counts the window's first value.
   Measured on 32,768 samples: longest run 6, most frequent low byte 98 / 512. */
int entropy_seed(uint8_t seed[32], entropy_stats_t *st)
{
  sha256_ctx c;
  uint16_t window[256] = {0};
  uint32_t last = 0xFFFFFFFFu, run = 0;
  memset(st, 0, sizeof *st);
  sha256_init(&c);
  sha256_update(&c, "can-ids entropy v1", 18);
  entropy_start(ENTROPY_PERIODS);
  for (uint32_t i = 0; i < ENTROPY_SAMPLES; i++) {
    uint32_t d = entropy_sample();
    sha256_update(&c, &d, sizeof d);
    run = (d == last) ? run + 1 : 1;
    last = d;
    if (run > st->max_repeat) st->max_repeat = run;
    if (++window[d & 0xFFu] > st->max_same_low_byte) st->max_same_low_byte = window[d & 0xFFu];
    if ((i & 511u) == 511u) memset(window, 0, sizeof window);
    if ((i & 1023u) == 0u) IWDG->KR = 0xAAAAu;     /* ~0.13 s in total: keep the watchdog fed */
  }
  entropy_stop();
  sha256_final(&c, seed);
  st->samples = ENTROPY_SAMPLES;
  st->ok = st->max_repeat < 12u && st->max_same_low_byte < 125u;
  return st->ok;
}
