/* PC build of the detector, for bit-exact comparison with Python
 * (driven by ml/src/check_c_detector.py).
 *
 * stdin : 16-byte records  {uint32 t_us, uint16 can_id, uint8 dlc, uint8 reset, uint8 data[8]}
 * stdout: 32-byte records  {int8 features[27], int8 score, uint8 level, reasons, novel_bytes, pair_bytes}
 * reset = 1 starts a new capture (all per-ID history is forgotten).
 */
#include <stdio.h>
#include <string.h>

#include "ids_detector.h"

#pragma pack(push, 1)
typedef struct { uint32_t t_us; uint16_t can_id; uint8_t dlc, reset; uint8_t data[8]; } in_rec_t;
typedef struct { int8_t features[IDS_FEATURES]; int8_t score; uint8_t level, reasons, novel, pair; } out_rec_t;
#pragma pack(pop)

int main(void)
{
    static in_rec_t in[4096];
    static out_rec_t out[4096];
    size_t n;
    ids_reset();
    while ((n = fread(in, sizeof in[0], 4096, stdin)) > 0) {
        for (size_t i = 0; i < n; i++) {
            ids_frame_t f = { in[i].t_us, in[i].can_id, in[i].dlc, {0} };
            memcpy(f.data, in[i].data, 8);
            if (in[i].reset) ids_reset();
            ids_result_t r;
            ids_process(&f, &r);
            memcpy(out[i].features, r.features_q, IDS_FEATURES);
            out[i].score = r.score_q;
            out[i].level = r.level;
            out[i].reasons = r.reasons;
            out[i].novel = r.novel_bytes;
            out[i].pair = r.pair_bytes;
        }
        fwrite(out, sizeof out[0], n, stdout);
    }
    return 0;
}
