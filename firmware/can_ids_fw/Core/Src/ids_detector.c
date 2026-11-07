/* CAN intrusion detector, C version of the Python pipeline (ml/src/road_*.py).
 *
 * Per frame:
 *   1. whitelist   : unknown ID -> ALERT at once
 *   2. rate rule   : gap since the previous frame of this ID < 0.5 x its shortest normal gap
 *   3. 27 features : novelty per byte, signal-pair surprise, byte changes, time gap
 *   4. int8 MLP    : 27 -> 32 -> 16 -> 1, same integer/float32 arithmetic as TFLite
 *   5. severity    : k-of-n smoothing per ID, ALERT if backed by strong evidence, else WARNING
 *
 * Floating point: the only float operations are the time-gap feature and one
 * multiply per neuron (requantization). They must be evaluated exactly as written
 * (no fused multiply-add), hence fp-contract=off below.
 */
#pragma GCC optimize ("O2", "fp-contract=off")   /* also optimized in Debug builds, for stable timings */

#include "ids_detector.h"
#include "ids_model.h"
#ifndef IDS_RANGE_ALL_CHECKED   /* headers exported before this setting existed (ROAD) */
#define IDS_RANGE_ALL_CHECKED 0
#endif

#include <string.h>

/* ------------------------------------------------------------------ state */
typedef struct {
    uint32_t prev_t;
    uint8_t  prev[8];
    uint8_t  has_prev;
    uint16_t hist_alert;   /* last N frames: rate rule or (model and strong evidence) */
    uint16_t hist_ai;      /* last N frames: model */
} id_state_t;

typedef struct {           /* latest two values of a pair's partner byte */
    uint32_t t[2];
    uint8_t  v[2];
    uint8_t  n;            /* how many are valid (0..2), [0] = latest */
} partner_state_t;

static id_state_t      st[IDS_N_IDS];
static partner_state_t partner[IDS_N_PAIRS];
static uint8_t weights_ready;
static void prepare_weights(void);

void ids_reset(void)
{
    memset(st, 0, sizeof st);
    memset(partner, 0, sizeof partner);
    if (!weights_ready) prepare_weights();
}

/* ------------------------------------------------------------------ helpers */
#define INLINE static inline __attribute__((always_inline))

/* Round half to even for |x| < 2^22 (adding 1.5 * 2^23 pushes the fraction out of the mantissa). */
INLINE int32_t round_even(float x)
{
    union { float f; uint32_t u; } v;
    v.f = x + 12582912.0f;
    return (int32_t)v.u - 0x4B400000;
}

INLINE int8_t quantize(float x)        /* model input quantization */
{
    float q = x / IDS_IN_SCALE + (float)IDS_IN_ZERO;
    if (q < -128.0f) q = -128.0f;
    if (q > 127.0f)  q = 127.0f;
    return (int8_t)round_even(q);
}

INLINE uint8_t popcount10(uint16_t h)
{
    uint8_t c = 0;
    for (h &= (1u << IDS_SMOOTH_N) - 1u; h; h &= (uint16_t)(h - 1u)) c++;
    return c;
}

/* acc + a.lo * b.lo + a.hi * b.hi on two packed int16: one SMLAD instruction on
   the Cortex-M4 (DSP extension), plain C elsewhere (PC build). Exact integer math. */
INLINE int32_t smlad(uint32_t a, uint32_t b, int32_t acc)
{
#if defined(__ARM_FEATURE_DSP) && __ARM_FEATURE_DSP
    int32_t r;
    __asm ("smlad %0, %1, %2, %3" : "=r"(r) : "r"(a), "r"(b), "r"(acc));
    return r;
#else
    return acc + (int16_t)(a & 0xFFFFu) * (int16_t)(b & 0xFFFFu) + (int16_t)(a >> 16) * (int16_t)(b >> 16);
#endif
}

/* ------------------------------------------------------------------ int8 MLP */
/* Weights widened to int16 once, in RAM (no flash wait states), rows padded to
   a multiple of 4 (two 32-bit words = 4 weights per loop pass, for SMLAD). */
#define PAD4(n) (((n) + 3) & ~3)
#define IN1 PAD4(IDS_FEATURES)
static int16_t w1h[32][IN1], w2h[16][32], w3h[1][16];

static void widen(const int8_t *src, int n_out, int n_in, int16_t *dst, int stride)
{
    for (int o = 0; o < n_out; o++)
        for (int i = 0; i < stride; i++)
            dst[o * stride + i] = i < n_in ? src[o * n_in + i] : 0;
}

static void prepare_weights(void)
{
    widen(&ids_w1[0][0], 32, IDS_FEATURES, &w1h[0][0], IN1);
    widen(&ids_w2[0][0], 16, 32, &w2h[0][0], 32);
    widen(&ids_w3[0][0], 1, 16, &w3h[0][0], 16);
    weights_ready = 1;
}

/* One int8 fully connected layer, TFLite/XNNPACK arithmetic:
   acc = bias + sum (x - x_zero) * w ; y = round_even(clamp(acc * scale)) + y_zero */
static void dense(const int8_t *x, int n_in, int stride, const int16_t *w, const int32_t *b,
                  const float *scale, int32_t x_zero, int32_t y_zero, int n_out, int8_t *y)
{
    int16_t xs[32] __attribute__((aligned(4)));
    for (int i = 0; i < stride; i++) xs[i] = i < n_in ? (int16_t)(x[i] - x_zero) : 0;
    const float lo = (float)(-128 - y_zero), hi = (float)(127 - y_zero);
    for (int o = 0; o < n_out; o++) {
        int32_t acc = b[o];
        const int16_t *wr = w + o * stride;
        for (int i = 0; i < stride; i += 4) {        /* strides are multiples of 4: 2 x SMLAD per pass */
            uint32_t a0, a1, c0, c1;
            memcpy(&a0, &xs[i], 4);     memcpy(&c0, &wr[i], 4);
            memcpy(&a1, &xs[i + 2], 4); memcpy(&c1, &wr[i + 2], 4);
            acc = smlad(a0, c0, acc);
            acc = smlad(a1, c1, acc);
        }
        float f = (float)acc * scale[o];
        if (f < lo) f = lo;
        if (f > hi) f = hi;
        y[o] = (int8_t)(round_even(f) + y_zero);
    }
}

int8_t ids_model_run(const int8_t *in)
{
    int8_t h1[32], h2[16], logit;
    if (!weights_ready) prepare_weights();
    dense(in, IDS_FEATURES, IN1, &w1h[0][0], ids_b1, ids_s1, IDS_X1_ZERO, IDS_Y1_ZERO, 32, h1);
    dense(h1, 32, 32, &w2h[0][0], ids_b2, ids_s2, IDS_X2_ZERO, IDS_Y2_ZERO, 16, h2);
    dense(h2, 16, 16, &w3h[0][0], ids_b3, ids_s3, IDS_X3_ZERO, IDS_Y3_ZERO, 1, &logit);
    return ids_sigmoid[logit + 128];
}

/* ------------------------------------------------------------------ main entry */
void ids_process(const ids_frame_t *f, ids_result_t *r)
{
    uint8_t b[8] = {0};
    memcpy(b, f->data, f->dlc < 8 ? f->dlc : 8);
    memset(r, 0, sizeof *r);
    r->score_q = -128;

    /* 1. whitelist */
    uint8_t k = f->can_id < 4096 ? ids_index_of[f->can_id] : 0xFF;
    if (k == 0xFF) {
        r->reasons = IDS_R_UNKNOWN_ID;
        r->level = IDS_ALERT;
        return;
    }
    id_state_t *s = &st[k];
    int8_t *x = r->features_q;      /* nov0..7, nov_count, s0..7, s_max, d0..7, dt_norm */

    /* 2. rate rule + time gap feature */
    uint8_t too_fast = 0;
    if (s->has_prev) {
        uint32_t dt = f->t_us - s->prev_t;        /* unsigned: correct across wraparound */
        too_fast = dt < ids_fast_us[k];
        float dt_norm = (float)((double)dt / ids_period_us[k]);
        if (dt_norm > 4.0f) dt_norm = 4.0f;
        x[26] = quantize(dt_norm);
    } else {
        x[26] = IDS_Q_ONE;                       /* first frame of this ID: gap = nominal */
    }

    /* 3a. novelty */
    uint8_t novel = 0, outside = 0;
    for (int j = 0; j < 8; j++) {
        uint8_t m = ids_nov_mode[k][j];
        if (m == 1) {
            const uint8_t *bm = ids_seen[ids_seen_row[k][j]];
            if (!(bm[b[j] >> 3] & (0x80u >> (b[j] & 7)))) {
                novel |= 1u << j;
#if IDS_RANGE_ALL_CHECKED       /* CAN-MIRGU: impossible value on an exact-set byte too */
                if (b[j] < ids_range_lo[k][j] || b[j] > ids_range_hi[k][j]) outside = 1;
#endif
            }
        } else if (m == 2) {
            if (b[j] < ids_range_lo[k][j] || b[j] > ids_range_hi[k][j]) { novel |= 1u << j; outside = 1; }
        }
    }
    uint8_t count = 0;
    for (int j = 0; j < 8; j++) {
        uint8_t on = (novel >> j) & 1u;
        x[j] = on ? IDS_Q_ONE : IDS_Q_ZERO;
        count += on;
    }
    x[8] = ids_q_nov_count[count];

    /* 3b. signal-pair surprise: partner value strictly earlier than this frame */
    int8_t sq[8];
    for (int j = 0; j < 8; j++) sq[j] = IDS_Q_ZERO;
    uint8_t broken = 0;
    for (int p = 0; p < IDS_N_PAIRS; p++) {
        const ids_pair_def_t *d = &ids_pairs[p];
        if (d->id != k) continue;
        const partner_state_t *ps = &partner[p];
        int pv = -1;
        for (int i = 0; i < ps->n; i++)
            if ((int32_t)(f->t_us - ps->t[i]) > 0) { pv = ps->v[i]; break; }
        if (pv < 0) continue;
        uint8_t bs = ids_pair_b_slot[p][pv];
        if (bs == 0xFF) continue;                  /* partner value unknown: no information */
        uint8_t as = ids_pair_a_slot[p][b[d->byte]];
        int8_t q;
        uint8_t strong;
        if (as == 0xFF) { q = d->q_unseen; strong = d->strong_unseen; }
        else {
            uint16_t c = (uint16_t)(d->cell0 + as * d->n_b + bs);
            q = ids_pair_q[c];
            strong = ids_pair_strong[c];
        }
        if (q > sq[d->byte]) sq[d->byte] = q;
        if (strong) broken |= 1u << d->byte;
    }
    int8_t smax = IDS_Q_ZERO;
    for (int j = 0; j < 8; j++) { x[9 + j] = sq[j]; if (sq[j] > smax) smax = sq[j]; }
    x[17] = smax;

    /* 3c. byte changes since the previous frame of this ID */
    for (int j = 0; j < 8; j++)
        x[18 + j] = s->has_prev ? ids_q_delta[(int)b[j] - (int)s->prev[j] + 255] : IDS_Q_ZERO;

    /* 4. model */
    r->score_q = ids_model_run(x);
    uint8_t ai = r->score_q >= IDS_THRESHOLD_Q;
    uint8_t strong = outside || broken;

    /* 5. severity with k-of-n smoothing per ID */
    s->hist_alert = (uint16_t)((s->hist_alert << 1) | (too_fast || (ai && strong)));
    s->hist_ai    = (uint16_t)((s->hist_ai << 1) | ai);
    if (popcount10(s->hist_alert) >= IDS_SMOOTH_K) r->level = IDS_ALERT;
    else if (popcount10(s->hist_ai) >= IDS_SMOOTH_K) r->level = IDS_WARNING;

    r->reasons = (uint8_t)((too_fast ? IDS_R_TOO_FAST : 0) | (ai ? IDS_R_MODEL : 0) | (strong ? IDS_R_STRONG : 0));
    r->novel_bytes = novel;
    r->pair_bytes = broken;

    /* update history: this frame becomes the partner value of other pairs, and the previous frame of its ID */
    for (int p = 0; p < IDS_N_PAIRS; p++) {
        if (ids_pairs[p].partner != k) continue;
        partner_state_t *ps = &partner[p];
        ps->t[1] = ps->t[0]; ps->v[1] = ps->v[0];
        ps->t[0] = f->t_us;  ps->v[0] = b[ids_pairs[p].partner_byte];
        if (ps->n < 2) ps->n++;
    }
    s->prev_t = f->t_us;
    memcpy(s->prev, b, 8);
    s->has_prev = 1;
}

float ids_probability(int8_t score_q)
{
    return ((float)score_q - (float)IDS_OUT_ZERO) * IDS_OUT_SCALE;
}

const char *ids_level_name(uint8_t level)
{
    return level == IDS_ALERT ? "ALERT" : level == IDS_WARNING ? "WARNING" : "normal";
}
