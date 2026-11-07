/* Status LEDs and buzzer, see ids_indicators.h. Register-level, non-blocking (except the
   0.3 s wiring check at boot, before the watchdog starts). */
#include "ids_indicators.h"
#include "stm32f4xx_hal.h"

#define BLUE_PORT   GPIOA
#define BLUE_PIN    9u
#define GREEN_PORT  GPIOA
#define GREEN_PIN   10u
#define YELLOW_PORT GPIOB
#define YELLOW_PIN  5u
#define RED_PORT    GPIOA
#define RED_PIN     8u

#define TONE_HZ     2700u          /* typical resonance of small passive buzzers */
#define BLINK_MS    40u            /* blue: toggle every 40 ms while frames arrive */
#define IDLE_MS     100u           /* blue off after 100 ms without frames */

static volatile uint32_t frames;
static uint32_t last_frame_ms, blue_ms;
static uint32_t beeps_left, beep_on_ms, beep_off_ms, beep_next_ms;
static int beep_on;

static void out_mode(GPIO_TypeDef *port, uint32_t pin)
{
  port->MODER = (port->MODER & ~(3u << (2 * pin))) | (1u << (2 * pin));
  port->OTYPER &= ~(1u << pin);
  port->PUPDR &= ~(3u << (2 * pin));
}
static void set(GPIO_TypeDef *port, uint32_t pin, int on) { port->BSRR = on ? (1u << pin) : (1u << (pin + 16)); }
static int get(GPIO_TypeDef *port, uint32_t pin) { return (port->ODR >> pin) & 1u; }

static void tone(int on)
{
  if (on) TIM3->CCER |= TIM_CCER_CC2E;
  else TIM3->CCER &= ~TIM_CCER_CC2E;
}

static void beeps(uint32_t n, uint32_t on_ms, uint32_t off_ms)
{
  beeps_left = n; beep_on_ms = on_ms; beep_off_ms = off_ms;
  beep_on = 0; beep_next_ms = HAL_GetTick();
}

void ind_init(void)
{
  RCC->AHB1ENR |= RCC_AHB1ENR_GPIOAEN | RCC_AHB1ENR_GPIOBEN | RCC_AHB1ENR_GPIOCEN;
  RCC->APB1ENR |= RCC_APB1ENR_TIM3EN;
  (void)RCC->APB1ENR;
  out_mode(BLUE_PORT, BLUE_PIN); out_mode(GREEN_PORT, GREEN_PIN);
  out_mode(YELLOW_PORT, YELLOW_PIN); out_mode(RED_PORT, RED_PIN);

  /* buzzer: PC7 = TIM3_CH2 (AF2), PWM mode 1, 50 % duty, output enabled only while beeping */
  GPIOC->MODER = (GPIOC->MODER & ~(3u << 14)) | (2u << 14);
  GPIOC->AFR[0] = (GPIOC->AFR[0] & ~(0xFu << 28)) | (2u << 28);
  uint32_t tim_hz = 2u * HAL_RCC_GetPCLK1Freq();                 /* 90 MHz */
  TIM3->PSC = tim_hz / 1000000u - 1u;                            /* 1 MHz count */
  TIM3->ARR = 1000000u / TONE_HZ - 1u;
  TIM3->CCR2 = (TIM3->ARR + 1u) / 2u;
  TIM3->CCMR1 = (TIM3->CCMR1 & ~(TIM_CCMR1_OC2M | TIM_CCMR1_CC2S)) | (6u << TIM_CCMR1_OC2M_Pos) | TIM_CCMR1_OC2PE;
  TIM3->EGR = TIM_EGR_UG;
  TIM3->CR1 = TIM_CR1_ARPE | TIM_CR1_CEN;

  /* wiring check: all LEDs on + short chirp */
  set(BLUE_PORT, BLUE_PIN, 1); set(GREEN_PORT, GREEN_PIN, 1); set(YELLOW_PORT, YELLOW_PIN, 1); set(RED_PORT, RED_PIN, 1);
  tone(1); HAL_Delay(80); tone(0); HAL_Delay(220);
  set(BLUE_PORT, BLUE_PIN, 0); set(YELLOW_PORT, YELLOW_PIN, 0); set(RED_PORT, RED_PIN, 0);
}

void ind_frame(void) { frames++; }
void ind_alert(void) { beeps(3, 120, 100); }
void ind_tamper(void) { beeps(5, 60, 60); }

void ind_poll(int incident_open, int level)
{
  uint32_t now = HAL_GetTick();

  /* blue: activity */
  if (frames) { frames = 0; last_frame_ms = now; }
  if (now - last_frame_ms < IDLE_MS) {
    if (now - blue_ms >= BLINK_MS) { blue_ms = now; set(BLUE_PORT, BLUE_PIN, !get(BLUE_PORT, BLUE_PIN)); }
  } else set(BLUE_PORT, BLUE_PIN, 0);

  /* exactly one of green / yellow / red */
  int red = incident_open && level >= 2, yellow = incident_open && level == 1;
  set(GREEN_PORT, GREEN_PIN, !incident_open);
  set(YELLOW_PORT, YELLOW_PIN, yellow);
  set(RED_PORT, RED_PIN, red);

  /* buzzer pattern */
  if (beeps_left && (int32_t)(now - beep_next_ms) >= 0) {
    if (!beep_on) { tone(1); beep_on = 1; beep_next_ms = now + beep_on_ms; }
    else { tone(0); beep_on = 0; beep_next_ms = now + beep_off_ms; beeps_left--; }
  }
}
