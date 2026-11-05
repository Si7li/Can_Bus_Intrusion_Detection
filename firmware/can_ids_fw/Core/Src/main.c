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
#include "ids_detector.h"
#include "ids_selftest_data.h"

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
/* ---- CAN test (milestone 1): send 0x123 every 100 ms, print what we receive ---- */
#define RX_QUEUE_LEN 16u

typedef struct {
  uint32_t id;      /* 11-bit standard ID */
  uint8_t  dlc;     /* 0..8 data bytes */
  uint8_t  data[8];
  uint32_t tick;    /* HAL_GetTick() when received, ms */
} can_frame_t;

/* Ring buffer filled by the RX interrupt, emptied by the main loop.
   The interrupt does nothing else (keeps it short). */
static volatile can_frame_t rx_queue[RX_QUEUE_LEN];
static volatile uint32_t rx_head = 0, rx_tail = 0, rx_overflow = 0, rx_count = 0;
static uint32_t tx_count = 0, tx_fail = 0;

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

/* Detector self-test: run the C detector on real ROAD frames stored in flash
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
  printf("\r\n=== Detector self-test: %u real ROAD frames ===\r\n", (unsigned)IDS_SELFTEST_N);
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
  printf("CAN1 started: 500 kbit/s, PB8=RX PB9=TX, accepting all IDs, sending 0x123 every 100 ms\r\n");
  printf("\r\nCAN IDS firmware booted, core clock %lu Hz, APB1 %lu Hz\r\n",
         HAL_RCC_GetHCLKFreq(), HAL_RCC_GetPCLK1Freq());
  ids_selftest();

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

    /* 1) every 100 ms: send ID 0x123 = [counter (4 bytes, little endian), CA FE BA BE] */
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
          HAL_CAN_AddTxMessage(&hcan1, &tx, d, &mailbox) == HAL_OK) {
        tx_count++;
      } else {
        tx_fail++;
      }
    }

    /* 2) print every received frame and toggle the green LED */
    while (rx_tail != rx_head) {
      can_frame_t f;
      uint32_t i = rx_tail % RX_QUEUE_LEN;
      f.id = rx_queue[i].id; f.dlc = rx_queue[i].dlc; f.tick = rx_queue[i].tick;
      for (int k = 0; k < 8; k++) f.data[k] = rx_queue[i].data[k];
      rx_tail++;
      printf("RX %lu ms  id=0x%03lX  dlc=%u  data=", f.tick, f.id, f.dlc);
      for (int k = 0; k < f.dlc; k++) printf("%02X ", f.data[k]);
      printf("\r\n");
      BSP_LED_Toggle(LED2);
    }

    /* 3) once per second: status. TEC/REC = transmit/receive error counters of the
          CAN controller. TEC climbing to 128+ means nobody acknowledges our frames
          (wiring, missing termination, or the other node at a different bitrate). */
    if (now - last_status >= 1000u) {
      last_status = now;
      uint32_t esr = hcan1.Instance->ESR;
      printf("status: tx=%lu tx_fail=%lu rx=%lu rx_overflow=%lu  TEC=%lu REC=%lu%s%s  err=0x%08lX\r\n",
             tx_count, tx_fail, rx_count, rx_overflow,
             (esr >> 16) & 0xFF, (esr >> 24) & 0xFF,
             (esr & CAN_ESR_EPVF) ? " ERROR-PASSIVE" : "",
             (esr & CAN_ESR_BOFF) ? " BUS-OFF" : "",
             HAL_CAN_GetError(&hcan1));
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
/* Called from the CAN1 RX0 interrupt for each frame in FIFO 0: copy it into the
   ring buffer and return. Processing happens in the main loop. */
void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan)
{
  CAN_RxHeaderTypeDef h;
  uint8_t d[8];
  while (HAL_CAN_GetRxFifoFillLevel(hcan, CAN_RX_FIFO0) > 0) {
    if (HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &h, d) != HAL_OK) break;
    rx_count++;
    if (rx_head - rx_tail >= RX_QUEUE_LEN) { rx_overflow++; continue; }
    uint32_t i = rx_head % RX_QUEUE_LEN;
    rx_queue[i].id = (h.IDE == CAN_ID_STD) ? h.StdId : h.ExtId;
    rx_queue[i].dlc = (h.DLC > 8u) ? 8u : (uint8_t)h.DLC;     /* input validation */
    for (uint32_t k = 0; k < 8u; k++) rx_queue[i].data[k] = d[k];
    rx_queue[i].tick = HAL_GetTick();
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
