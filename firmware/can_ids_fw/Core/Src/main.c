/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <string.h>
#include "ids_detector.h"
#include "ids_selftest_data.h"
#ifndef IDS_DATASET_NAME            /* headers exported before the CAN-MIRGU version */
#define IDS_DATASET_NAME "ROAD"
#endif

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/

/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

CAN_HandleTypeDef hcan1;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
/* ---- Live intrusion detection: every received CAN frame goes through ids_process() ---- */
#define CAN_TEST_TX      0          /* 1 = also send test frame 0x123 every 100 ms (bus bring-up) */
#define UART_BAUD        921600u    /* serial port to the PC (/dev/ttyACM0) */
#define RX_QUEUE_LEN     256u       /* power of two; ~100 ms of traffic at 2,400 frames/s */
#define INCIDENT_GAP_US  1000000u   /* flagged frames less than 1 s apart = one incident */
#define IDLE_RESET_US    1000000u   /* bus silent > 1 s (car off, replay restarted): forget history */
#define INC_MAX_IDS      6u         /* IDs listed per incident (unknown IDs are only counted) */

typedef struct {
  uint32_t t_us;    /* TIM2 at reception, 1 MHz */
  uint16_t id;      /* 11-bit ID; 0xFFF for ROAD's extended 0xFFF; 0xFFFF = other extended ID */
  uint8_t  dlc;     /* 0..8 data bytes */
  uint8_t  data[8];
} can_frame_t;

/* Ring buffer filled by the RX interrupt, emptied by the main loop.
   The interrupt does nothing else (keeps it short). */
static volatile can_frame_t rx_queue[RX_QUEUE_LEN];
static volatile uint32_t rx_head = 0, rx_tail = 0, rx_overflow = 0, rx_count = 0;
#if CAN_TEST_TX
static uint32_t tx_count = 0, tx_fail = 0;
#endif

/* One incident = flagged frames less than 1 s apart (same definition as the evaluation). */
typedef struct { uint16_t id; uint8_t reasons, novel, pair; uint32_t frames; } inc_id_t;
static struct {
  uint8_t  active, level, n_ids;
  uint32_t start_us, last_us, frames, unknown_frames;
  inc_id_t ids[INC_MAX_IDS];
} inc;

/* Statistics over the last second */
static uint32_t st_frames, st_alert, st_warn, st_busy_cyc, st_qmax;
static uint32_t total_incidents;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_CAN1_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
/* printf() goes through _write(): send the text over USART2, which the
   ST-LINK forwards to the PC as /dev/ttyACM0 (115200 baud). */
int _write(int file, char *ptr, int len)
{
  (void)file;
  HAL_UART_Transmit(&huart2, (uint8_t *)ptr, (uint16_t)len, HAL_MAX_DELAY);
  return len;
}

/* Detector self-test: run the C detector on real frames (ROAD or CAN-MIRGU) stored in flash
   (ids_selftest_data.h) and compare every answer with what the Python pipeline
   gave for the same frames. Also measures the time per frame with the DWT
   cycle counter (1 cycle = 1/180 MHz = 5.6 ns). */
static void ids_selftest(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;     /* enable the cycle counter */
  DWT->CYCCNT = 0;
  DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;

  uint32_t bad_score = 0, bad_level = 0, forged = 0, forged_alert = 0, normal_flagged = 0;
  uint32_t n_known = 0, c_min = 0xFFFFFFFFu, c_max = 0;
  uint64_t c_sum = 0;
  ids_result_t r;

  for (uint32_t i = 0; i < IDS_SELFTEST_N; i++) {
    const ids_selftest_frame_t *s = &ids_selftest_frames[i];
    ids_frame_t f = { s->t_us, s->can_id, 8, {0} };
    for (int j = 0; j < 8; j++) f.data[j] = s->data[j];
    if (s->reset) ids_reset();

    uint32_t t0 = DWT->CYCCNT;
    ids_process(&f, &r);
    uint32_t cyc = DWT->CYCCNT - t0;

    if (!(r.reasons & IDS_R_UNKNOWN_ID)) {           /* frames that went through the AI */
      n_known++; c_sum += cyc;
      if (cyc < c_min) c_min = cyc;
      if (cyc > c_max) c_max = cyc;
    }
    const ids_selftest_expect_t *e = &ids_selftest_expect[i];
    if (r.score_q != e->score_q || r.level != e->level) {
      if (bad_score + bad_level < 5)
        printf("  mismatch frame %lu: id=0x%03X score %d (python %d) level %u (python %u)\r\n",
               i, s->can_id, r.score_q, e->score_q, r.level, e->level);
      bad_score += r.score_q != e->score_q;
      bad_level += r.level != e->level;
    }
    uint8_t is_forged = (ids_selftest_forged[i >> 3] >> (i & 7)) & 1u;
    forged += is_forged;
    forged_alert += is_forged && r.level == IDS_ALERT;
    normal_flagged += !is_forged && r.level != IDS_NORMAL;
  }
  ids_reset();

  /* model alone, on the features of the last frame */
  uint32_t m0 = DWT->CYCCNT;
  for (int k = 0; k < 100; k++) (void)ids_model_run(r.features_q);
  uint32_t model_cyc = (DWT->CYCCNT - m0) / 100u;

  uint32_t avg = (uint32_t)(c_sum / (n_known ? n_known : 1));
  uint32_t mhz = HAL_RCC_GetHCLKFreq() / 1000000u;
  printf("\r\n=== Detector self-test: %u real %s frames ===\r\n", (unsigned)IDS_SELFTEST_N, IDS_DATASET_NAME);
  printf("  same model output as Python : %lu / %u\r\n", IDS_SELFTEST_N - bad_score, (unsigned)IDS_SELFTEST_N);
  printf("  same ALERT/WARNING as Python: %lu / %u\r\n", IDS_SELFTEST_N - bad_level, (unsigned)IDS_SELFTEST_N);
  printf("  forged frames at ALERT      : %lu / %lu, normal frames flagged: %lu\r\n",
         forged_alert, forged, normal_flagged);
  printf("  time per frame (rules + features + int8 MLP): avg %lu cycles = %lu.%02lu us, min %lu, max %lu cycles\r\n",
         avg, avg / mhz, (avg % mhz) * 100u / mhz, c_min, c_max);
  printf("  of which int8 MLP alone: %lu cycles = %lu.%02lu us\r\n",
         model_cyc, model_cyc / mhz, (model_cyc % mhz) * 100u / mhz);
  printf("  -> %s\r\n\r\n", (bad_score || bad_level) ? "SELF-TEST FAILED" : "SELF-TEST PASSED (bit-exact)");
}

/* ---------------- live detection: JSON lines on the serial port ---------------- */
static inline uint32_t us_now(void) { return TIM2->CNT; }

static void json_reasons(uint8_t r, char *out)        /* -> ["model","strong"] */
{
  static const char *names[4] = { "unknown_id", "too_fast", "model", "strong" };
  char *p = out;
  *p++ = '[';
  for (int k = 0; k < 4; k++)
    if (r & (1u << k)) p += sprintf(p, "%s\"%s\"", p[-1] == '[' ? "" : ",", names[k]);
  *p++ = ']'; *p = 0;
}

static void json_bytes(uint8_t m, char *out)          /* bit mask -> [2,5] */
{
  char *p = out;
  *p++ = '[';
  for (int j = 0; j < 8; j++)
    if (m & (1u << j)) p += sprintf(p, "%s%d", p[-1] == '[' ? "" : ",", j);
  *p++ = ']'; *p = 0;
}

static void incident_end(void)
{
  char rs[64], nv[24], pr[24];
  printf("{\"type\":\"incident_end\",\"t_ms\":%lu,\"level\":\"%s\",\"duration_ms\":%lu,\"frames\":%lu,"
         "\"unknown_id_frames\":%lu,\"ids\":[",
         inc.last_us / 1000u, ids_level_name(inc.level), (inc.last_us - inc.start_us) / 1000u,
         inc.frames, inc.unknown_frames);
  for (uint32_t k = 0; k < inc.n_ids; k++) {
    inc_id_t *e = &inc.ids[k];
    json_reasons(e->reasons, rs); json_bytes(e->novel, nv); json_bytes(e->pair, pr);
    printf("%s{\"id\":\"0x%03X\",\"frames\":%lu,\"reasons\":%s,\"novel_bytes\":%s,\"pair_bytes\":%s}",
           k ? "," : "", e->id, e->frames, rs, nv, pr);
  }
  printf("]}\r\n");
  inc.active = 0;
  BSP_LED_Off(LED2);
}

/* A flagged frame: start or extend the incident; report when it starts or escalates. */
static void incident_add(const can_frame_t *c, const ids_result_t *r)
{
  if (inc.active && c->t_us - inc.last_us > INCIDENT_GAP_US) incident_end();
  if (!inc.active) {
    memset(&inc, 0, sizeof inc);
    inc.active = 1;
    inc.start_us = c->t_us;
    total_incidents++;
    BSP_LED_On(LED2);
  }
  inc.last_us = c->t_us;
  inc.frames++;
  if (r->reasons & IDS_R_UNKNOWN_ID) {
    inc.unknown_frames++;
  } else {
    inc_id_t *e = NULL;
    for (uint32_t k = 0; k < inc.n_ids; k++) if (inc.ids[k].id == c->id) e = &inc.ids[k];
    if (!e && inc.n_ids < INC_MAX_IDS) { e = &inc.ids[inc.n_ids++]; e->id = c->id; }
    if (e) { e->frames++; e->reasons |= r->reasons; e->novel |= r->novel_bytes; e->pair |= r->pair_bytes; }
  }
  if (r->level > inc.level) {          /* new incident, or WARNING -> ALERT */
    char rs[64], nv[24], pr[24];
    inc.level = r->level;
    json_reasons(r->reasons, rs); json_bytes(r->novel_bytes, nv); json_bytes(r->pair_bytes, pr);
    printf("{\"type\":\"alert\",\"t_ms\":%lu,\"level\":\"%s\",\"id\":\"0x%03X\",\"reasons\":%s,"
           "\"novel_bytes\":%s,\"pair_bytes\":%s,\"p\":%u}\r\n",
           c->t_us / 1000u, ids_level_name(r->level), c->id, rs, nv, pr,
           (unsigned)(((int)r->score_q + 128) * 100 / 256));
  }
}

static void process_frame(const can_frame_t *c)
{
  static uint32_t last_t;
  static uint8_t any;
  if (any && c->t_us - last_t > IDLE_RESET_US) {
    if (inc.active) incident_end();
    ids_reset();
    printf("{\"type\":\"info\",\"msg\":\"bus was idle > 1 s: detector history reset\"}\r\n");
  }
  last_t = c->t_us;
  any = 1;

  ids_frame_t f = { c->t_us, c->id, c->dlc, {0} };
  memcpy(f.data, c->data, 8);
  ids_result_t r;
  uint32_t t0 = DWT->CYCCNT;
  ids_process(&f, &r);
  st_busy_cyc += DWT->CYCCNT - t0;
  st_frames++;
  if (r.level == IDS_ALERT) st_alert++;
  else if (r.level == IDS_WARNING) st_warn++;
  if (r.level != IDS_NORMAL) incident_add(c, &r);
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_CAN1_Init();
  /* USER CODE BEGIN 2 */
  /* Faster serial port than CubeMX's 115200: alerts must not slow down reception. */
  huart2.Init.BaudRate = UART_BAUD;
  if (HAL_UART_Init(&huart2) != HAL_OK) Error_Handler();
  printf("\r\nCAN IDS firmware booted, core clock %lu Hz, APB1 %lu Hz\r\n",
         HAL_RCC_GetHCLKFreq(), HAL_RCC_GetPCLK1Freq());
  ids_selftest();                     /* before CAN starts: nothing arrives during the test */

  /* TIM2 = free-running 32-bit microsecond clock (timer clock = 2 x APB1 = 90 MHz). */
  __HAL_RCC_TIM2_CLK_ENABLE();
  TIM2->PSC = 2u * HAL_RCC_GetPCLK1Freq() / 1000000u - 1u;
  TIM2->ARR = 0xFFFFFFFFu;
  TIM2->EGR = TIM_EGR_UG;             /* load the prescaler now */
  TIM2->CR1 = TIM_CR1_CEN;

  /* Accept every ID: an intrusion detector must see unknown IDs too.
     Filter bank 0, mask 0 = match all, everything goes to RX FIFO 0. */
  CAN_FilterTypeDef filter = {0};
  filter.FilterBank = 0;
  filter.FilterMode = CAN_FILTERMODE_IDMASK;
  filter.FilterScale = CAN_FILTERSCALE_32BIT;
  filter.FilterIdHigh = 0; filter.FilterIdLow = 0;
  filter.FilterMaskIdHigh = 0; filter.FilterMaskIdLow = 0;
  filter.FilterFIFOAssignment = CAN_RX_FIFO0;
  filter.FilterActivation = ENABLE;
  filter.SlaveStartFilterBank = 14;
  if (HAL_CAN_ConfigFilter(&hcan1, &filter) != HAL_OK) Error_Handler();
  /* Automatic bus-off recovery (ABOM): after too many errors the controller
     goes bus-off; with ABOM it rejoins by itself after 128 x 11 recessive bits
     instead of staying off until reset. Must be set while still in init mode. */
  SET_BIT(hcan1.Instance->MCR, CAN_MCR_ABOM);
  /* HAL_CAN_Start waits until the controller sees an idle (recessive) bus on PB8.
     Without the transceiver wired, it never does: report it instead of hanging. */
  if (HAL_CAN_Start(&hcan1) != HAL_OK) {
    printf("ERROR: CAN1 did not start. Is the SN65HVD230 board wired (3V3, GND, PB8=CRX, PB9=CTX)?\r\n");
  }
  if (HAL_CAN_ActivateNotification(&hcan1, CAN_IT_RX_FIFO0_MSG_PENDING) != HAL_OK) Error_Handler();
  printf("{\"type\":\"info\",\"msg\":\"CAN1 started at 500 kbit/s, detector running on every frame\"}\r\n");

/* USER CODE END 2 */

  /* Initialize leds */
  BSP_LED_Init(LED2);

  /* Initialize USER push-button, will be used to trigger an interrupt each time it's pressed.*/
  BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    static uint32_t last_tx = 0, last_status = 0;
    uint32_t now = HAL_GetTick();

#if CAN_TEST_TX
    /* every 100 ms: send ID 0x123 = [counter (4 bytes, little endian), CA FE BA BE] */
    if (now - last_tx >= 100u) {
      last_tx = now;
      CAN_TxHeaderTypeDef tx = {0};
      uint8_t d[8] = { (uint8_t)tx_count, (uint8_t)(tx_count >> 8), (uint8_t)(tx_count >> 16),
                       (uint8_t)(tx_count >> 24), 0xCA, 0xFE, 0xBA, 0xBE };
      uint32_t mailbox;
      tx.StdId = 0x123;
      tx.IDE = CAN_ID_STD;
      tx.RTR = CAN_RTR_DATA;
      tx.DLC = 8;
      if (HAL_CAN_GetTxMailboxesFreeLevel(&hcan1) > 0 &&
          HAL_CAN_AddTxMessage(&hcan1, &tx, d, &mailbox) == HAL_OK) tx_count++;
      else tx_fail++;
    }
#else
    (void)last_tx;
#endif

    /* 1) run the detector on every received frame, in order */
    uint32_t depth = rx_head - rx_tail;
    if (depth > st_qmax) st_qmax = depth;
    while (rx_tail != rx_head) {
      can_frame_t f;
      uint32_t i = rx_tail % RX_QUEUE_LEN;
      f.t_us = rx_queue[i].t_us; f.id = rx_queue[i].id; f.dlc = rx_queue[i].dlc;
      for (int k = 0; k < 8; k++) f.data[k] = rx_queue[i].data[k];
      rx_tail++;
      process_frame(&f);
    }

    /* 2) an incident ends after 1 s without flagged frames */
    if (inc.active && us_now() - inc.last_us > INCIDENT_GAP_US) incident_end();

    /* 3) once per second: status. TEC/REC = CAN error counters (should stay 0). */
    if (now - last_status >= 1000u) {
      uint32_t ms = now - last_status;
      last_status = now;
      uint32_t esr = hcan1.Instance->ESR;
      uint32_t cpu10 = (uint32_t)((uint64_t)st_busy_cyc * 1000u / ((uint64_t)HAL_RCC_GetHCLKFreq() * ms / 1000u));
      printf("{\"type\":\"status\",\"t_ms\":%lu,\"fps\":%lu,\"cpu_pct\":%lu.%lu,\"queue_max\":%lu,\"overflow\":%lu,"
             "\"alert_frames\":%lu,\"warning_frames\":%lu,\"incidents\":%lu,\"tec\":%lu,\"rec\":%lu%s}\r\n",
             us_now() / 1000u, st_frames * 1000u / ms, cpu10 / 10u, cpu10 % 10u, st_qmax, rx_overflow,
             st_alert, st_warn, total_incidents, (esr >> 16) & 0xFF, (esr >> 24) & 0xFF,
             (esr & CAN_ESR_BOFF) ? ",\"bus_off\":true" : "");
      st_frames = st_alert = st_warn = st_busy_cyc = st_qmax = 0;
    }
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 180;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Activate the Over-Drive mode
  */
  if (HAL_PWREx_EnableOverDrive() != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief CAN1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_CAN1_Init(void)
{

  /* USER CODE BEGIN CAN1_Init 0 */

  /* USER CODE END CAN1_Init 0 */

  /* USER CODE BEGIN CAN1_Init 1 */

  /* USER CODE END CAN1_Init 1 */
  hcan1.Instance = CAN1;
  hcan1.Init.Prescaler = 5;
  hcan1.Init.Mode = CAN_MODE_NORMAL;
  hcan1.Init.SyncJumpWidth = CAN_SJW_1TQ;
  hcan1.Init.TimeSeg1 = CAN_BS1_15TQ;
  hcan1.Init.TimeSeg2 = CAN_BS2_2TQ;
  hcan1.Init.TimeTriggeredMode = DISABLE;
  hcan1.Init.AutoBusOff = DISABLE;
  hcan1.Init.AutoWakeUp = DISABLE;
  hcan1.Init.AutoRetransmission = DISABLE;
  hcan1.Init.ReceiveFifoLocked = DISABLE;
  hcan1.Init.TransmitFifoPriority = DISABLE;
  if (HAL_CAN_Init(&hcan1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN CAN1_Init 2 */

  /* USER CODE END CAN1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
/* Called from the CAN1 RX0 interrupt for each frame in FIFO 0: timestamp it,
   copy it into the ring buffer and return. Detection happens in the main loop. */
void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan)
{
  CAN_RxHeaderTypeDef h;
  uint8_t d[8];
  while (HAL_CAN_GetRxFifoFillLevel(hcan, CAN_RX_FIFO0) > 0) {
    uint32_t t = TIM2->CNT;
    if (HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &h, d) != HAL_OK) break;
    rx_count++;
    if (rx_head - rx_tail >= RX_QUEUE_LEN) { rx_overflow++; continue; }
    uint32_t i = rx_head % RX_QUEUE_LEN;
    /* ROAD's ID 0xFFF does not fit in 11 bits: the replay sends it as an extended
       frame. Any other extended frame is unknown to the whitelist (0xFFFF). */
    if (h.IDE == CAN_ID_STD) rx_queue[i].id = (uint16_t)h.StdId;
    else rx_queue[i].id = (h.ExtId == 0xFFFu) ? 0xFFFu : 0xFFFFu;
    rx_queue[i].dlc = (h.DLC > 8u) ? 8u : (uint8_t)h.DLC;     /* input validation */
    for (uint32_t k = 0; k < 8u; k++) rx_queue[i].data[k] = d[k];
    rx_queue[i].t_us = t;
    rx_head++;
  }
}

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
