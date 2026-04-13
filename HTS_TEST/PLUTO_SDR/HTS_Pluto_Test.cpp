// =============================================================================
// HTS_Pluto_Test.cpp — V14: USB + Cyclic TX + 최종 무결성
// =============================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
#error "[HTS_FATAL] PC 전용"
#endif
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iio.h>
#include <random>
#include <thread>
#include <vector>
#include "HTS_FEC_HARQ.hpp"
#include "HTS_V400_Dispatcher.hpp"

using ProtectedEngine::DecodedPacket;
using ProtectedEngine::FEC_HARQ;
using ProtectedEngine::HTS_V400_Dispatcher;
using ProtectedEngine::PayloadMode;
using ProtectedEngine::SoftClipPolicy;

static constexpr long long PLUTO_FREQ_HZ     = 915000000LL;
static constexpr long long PLUTO_SAMPLE_RATE  = 4000000LL;
static constexpr long long PLUTO_BW_HZ       = 4000000LL;
static constexpr int       PLUTO_BUF_SAMPLES = 32768;
static constexpr long long PLUTO_TX_GAIN_INIT = -89LL;
static constexpr long long PLUTO_RX_GAIN_INIT = 50LL;

static long long g_tx_gain = PLUTO_TX_GAIN_INIT;
static constexpr int16_t kAmp  = 1000;
static constexpr double  kAmpD = 1000.0;

struct PlutoCtx {
    struct iio_context *ctx    = nullptr;
    struct iio_device  *phy    = nullptr;
    struct iio_device  *tx_dev = nullptr;
    struct iio_device  *rx_dev = nullptr;
    struct iio_channel *tx_i   = nullptr;
    struct iio_channel *tx_q   = nullptr;
    struct iio_channel *rx_i   = nullptr;
    struct iio_channel *rx_q   = nullptr;
    struct iio_buffer  *tx_buf = nullptr;
    struct iio_buffer  *rx_buf = nullptr;
};

static bool wr_lli(struct iio_channel *c, const char *a, long long v) {
    return iio_channel_attr_write_longlong(c, a, v) >= 0;
}
static bool wr_str(struct iio_channel *c, const char *a, const char *v) {
    return iio_channel_attr_write(c, a, v) >= 0;
}

static void pluto_disable_dds(struct iio_device *d) {
    const char *alt[] = {"altvoltage0","altvoltage1","altvoltage2","altvoltage3"};
    for (auto nm : alt) {
        auto *ch = iio_device_find_channel(d, nm, true);
        if (ch) iio_channel_attr_write(ch, "raw", "0");
    }
}

static bool pluto_open(PlutoCtx &p) {
    p.ctx = iio_create_context_from_uri("usb:");
    if (!p.ctx) {
        std::printf("[PLUTO] USB 연결 실패. iio_info -s 로 URI 확인\n");
        return false;
    }
    p.phy = iio_context_find_device(p.ctx, "ad9361-phy");
    if (!p.phy) { std::printf("[PLUTO] PHY 미발견\n"); return false; }

    auto *tx_lo = iio_device_find_channel(p.phy, "altvoltage1", true);
    auto *tx_ph = iio_device_find_channel(p.phy, "voltage0", true);
    if (tx_lo) wr_lli(tx_lo, "frequency", PLUTO_FREQ_HZ);
    if (tx_ph) {
        wr_lli(tx_ph, "rf_bandwidth", PLUTO_BW_HZ);
        wr_lli(tx_ph, "sampling_frequency", PLUTO_SAMPLE_RATE);
        wr_lli(tx_ph, "hardwaregain", PLUTO_TX_GAIN_INIT);
    }

    auto *rx_lo = iio_device_find_channel(p.phy, "altvoltage0", true);
    auto *rx_ph = iio_device_find_channel(p.phy, "voltage0", false);
    if (rx_lo) wr_lli(rx_lo, "frequency", PLUTO_FREQ_HZ);
    if (rx_ph) {
        wr_lli(rx_ph, "rf_bandwidth", PLUTO_BW_HZ);
        wr_lli(rx_ph, "sampling_frequency", PLUTO_SAMPLE_RATE);
        wr_str(rx_ph, "gain_control_mode", "manual");
        wr_lli(rx_ph, "hardwaregain", PLUTO_RX_GAIN_INIT);
    }

    p.tx_dev = iio_context_find_device(p.ctx, "cf-ad9361-dds-core-lpc");
    p.rx_dev = iio_context_find_device(p.ctx, "cf-ad9361-lpc");
    if (!p.tx_dev || !p.rx_dev) return false;

    p.tx_i = iio_device_find_channel(p.tx_dev, "voltage0", true);
    p.tx_q = iio_device_find_channel(p.tx_dev, "voltage1", true);
    p.rx_i = iio_device_find_channel(p.rx_dev, "voltage0", false);
    p.rx_q = iio_device_find_channel(p.rx_dev, "voltage1", false);
    if (!p.tx_i || !p.tx_q || !p.rx_i || !p.rx_q) return false;

    pluto_disable_dds(p.tx_dev);
    iio_channel_enable(p.tx_i); iio_channel_enable(p.tx_q);
    iio_channel_enable(p.rx_i); iio_channel_enable(p.rx_q);

    p.tx_buf = iio_device_create_buffer(p.tx_dev, PLUTO_BUF_SAMPLES, true);
    p.rx_buf = iio_device_create_buffer(p.rx_dev, PLUTO_BUF_SAMPLES, false);
    if (!p.tx_buf || !p.rx_buf) return false;

    std::printf("[PLUTO] USB 연결 OK: %.0f MHz, TX=%lld dB, RX=%lld dB, Cyclic TX\n",
                PLUTO_FREQ_HZ / 1e6, PLUTO_TX_GAIN_INIT, PLUTO_RX_GAIN_INIT);
    return true;
}

static void pluto_close(PlutoCtx &p) {
    if (p.tx_buf) iio_buffer_destroy(p.tx_buf);
    if (p.rx_buf) iio_buffer_destroy(p.rx_buf);
    if (p.ctx)    iio_context_destroy(p.ctx);
    p = PlutoCtx{};
}

static void pluto_set_tx_gain(PlutoCtx &p, long long g) {
    if (g < -89) g = -89;
    if (g > -40) g = -40;
    auto *ch = iio_device_find_channel(p.phy, "voltage0", true);
    if (ch) wr_lli(ch, "hardwaregain", g);
    g_tx_gain = g;
}

static void pluto_flush_rx(PlutoCtx &p) {
    for (int i = 0; i < 6; ++i) iio_buffer_refill(p.rx_buf);
}

static bool pluto_tx_start(PlutoCtx &p, const int16_t *I, const int16_t *Q, int n) {
    if (p.tx_buf) {
        iio_buffer_destroy(p.tx_buf);
        p.tx_buf = nullptr;
    }
    p.tx_buf = iio_device_create_buffer(p.tx_dev, PLUTO_BUF_SAMPLES, true);
    if (!p.tx_buf) return false;

    char *s = (char *)iio_buffer_start(p.tx_buf);
    char *e = (char *)iio_buffer_end(p.tx_buf);
    ptrdiff_t step = iio_buffer_step(p.tx_buf);
    int idx = 0;
    for (char *ptr = s; ptr < e; ptr += step) {
        ((int16_t *)ptr)[0] = (idx < n) ? I[idx] : 0;
        ((int16_t *)ptr)[1] = (idx < n) ? Q[idx] : 0;
        idx++;
    }
    return iio_buffer_push(p.tx_buf) > 0;
}

static int pluto_rx(PlutoCtx &p, int16_t *I, int16_t *Q, int max_n) {
    if (iio_buffer_refill(p.rx_buf) < 0) return 0;
    char *s = (char *)iio_buffer_start(p.rx_buf);
    char *e = (char *)iio_buffer_end(p.rx_buf);
    ptrdiff_t step = iio_buffer_step(p.rx_buf);
    int idx = 0;
    for (char *ptr = s; ptr < e && idx < max_n; ptr += step) {
        I[idx] = ((int16_t *)ptr)[0];
        Q[idx] = ((int16_t *)ptr)[1];
        idx++;
    }
    return idx;
}

static int pluto_tx_then_rx(PlutoCtx &p,
                            const int16_t *txI, const int16_t *txQ, int n_tx,
                            int16_t *rxI, int16_t *rxQ, int max_rx) {
    if (!pluto_tx_start(p, txI, txQ, n_tx)) return 0;
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    pluto_flush_rx(p);
    return pluto_rx(p, rxI, rxQ, max_rx);
}

static void apply_digital_agc(int16_t *I, int16_t *Q, int n, int target = 1000) {
    int32_t mx = 1;
    for (int i = 0; i < n; ++i) {
        int32_t ai = I[i] < 0 ? -I[i] : I[i];
        int32_t aq = Q[i] < 0 ? -Q[i] : Q[i];
        if (ai > mx) mx = ai;
        if (aq > mx) mx = aq;
    }
    if (mx < 30) return;
    float gain = (float)target / mx;
    for (int i = 0; i < n; ++i) {
        int32_t vi = (int32_t)(I[i] * gain);
        int32_t vq = (int32_t)(Q[i] * gain);
        if (vi > 32767) vi = 32767; if (vi < -32768) vi = -32768;
        if (vq > 32767) vq = 32767; if (vq < -32768) vq = -32768;
        I[i] = (int16_t)vi; Q[i] = (int16_t)vq;
    }
}

// 기존 성공했던 함수로 교체
static void apply_phase_correction(int16_t *I, int16_t *Q, int n) {
    int64_t sumI = 0, sumQ = 0;
    for (int i = 0; i < n; ++i) {
        int32_t mag2 = (int32_t)I[i] * I[i] + (int32_t)Q[i] * Q[i];
        if (mag2 > 3500) {
            sumI += I[i];
            sumQ += Q[i];
        }
    }
    double theta = std::atan2((double)sumQ, (double)sumI);
    double cosT = std::cos(theta);
    double sinT = std::sin(theta);
    for (int i = 0; i < n; ++i) {
        double di = (double)I[i];
        double dq = (double)Q[i];
        double ri = di * cosT + dq * sinT;
        double rq = -di * sinT + dq * cosT;
        if (ri > 32767) ri = 32767; if (ri < -32768) ri = -32768;
        if (rq > 32767) rq = 32767; if (rq < -32768) rq = -32768;
        I[i] = (int16_t)std::lround(ri);
        Q[i] = (int16_t)std::lround(rq);
    }
}

static int find_signal_start(const int16_t *rxI, const int16_t *rxQ, int n_rx,
                             const int16_t *sigI, const int16_t *sigQ, int sig_len) {
    if (n_rx <= sig_len) return 0;
    int best = 0;
    int64_t best_c = -1;
    int cl = sig_len > 256 ? 256 : sig_len;
    for (int i = 0; i <= n_rx - sig_len; ++i) {
        int64_t cI = 0, cQ = 0;
        for (int j = 0; j < cl; ++j) {
            cI += (int64_t)rxI[i+j] * sigI[j] + (int64_t)rxQ[i+j] * sigQ[j];
            cQ += (int64_t)rxQ[i+j] * sigI[j] - (int64_t)rxI[i+j] * sigQ[j];
        }
        int64_t cs = (cI/256), qs = (cQ/256);
        int64_t c = cs*cs + qs*qs;
        if (c > best_c) { best_c = c; best = i; }
    }
    return best;
}

static constexpr int GUARD_CHIPS = 512;

static void fill_tx_repeated(int16_t *txI, int16_t *txQ, int buf_len,
                             const int16_t *sigI, const int16_t *sigQ, int sig_len) {
    std::memset(txI, 0, buf_len * sizeof(int16_t));
    std::memset(txQ, 0, buf_len * sizeof(int16_t));
    int block = sig_len + GUARD_CHIPS;
    int offset = GUARD_CHIPS;
    while (offset + sig_len <= buf_len) {
        std::memcpy(&txI[offset], sigI, sig_len * sizeof(int16_t));
        std::memcpy(&txQ[offset], sigQ, sig_len * sizeof(int16_t));
        offset += block;
    }
}

static uint32_t popc32(uint32_t x) {
    x -= ((x>>1)&0x55555555u);
    x = (x&0x33333333u)+((x>>2)&0x33333333u);
    return (((x+(x>>4))&0x0F0F0F0Fu)*0x01010101u)>>24;
}

static void walsh_enc(uint8_t sym, int nc, int16_t amp, int16_t *oI, int16_t *oQ) {
    for (int j = 0; j < nc; ++j) {
        int p = popc32((uint32_t)sym & (uint32_t)j) & 1;
        int16_t ch = (int16_t)(amp * (1 - 2*p));
        oI[j] = ch; oQ[j] = ch;
    }
}

static void gen_info(uint32_t seed, uint8_t *info) {
    uint32_t s = seed;
    for (int b = 0; b < 8; ++b) {
        s ^= s<<13; s ^= s>>17; s ^= s<<5;
        info[b] = (uint8_t)(s & 0xFF);
    }
}

static void add_barrage(int16_t *I, int16_t *Q, int n, double js_db, std::mt19937 &rng) {
    if (js_db < 0) return;
    double sigma = kAmpD * std::sqrt(std::pow(10.0, js_db/10.0));
    std::normal_distribution<double> nd(0.0, sigma);
    for (int i = 0; i < n; ++i) {
        double vi = (double)I[i] + nd(rng);
        double vq = (double)Q[i] + nd(rng);
        if (vi>2047) vi=2047; if (vi<-2048) vi=-2048;
        if (vq>2047) vq=2047; if (vq<-2048) vq=-2048;
        I[i]=(int16_t)std::lround(vi); Q[i]=(int16_t)std::lround(vq);
    }
}

static void add_cw(int16_t *I, int16_t *Q, int n, double js_db) {
    if (js_db < 0) return;
    double a = kAmpD * std::sqrt(std::pow(10.0, js_db/10.0));
    for (int i = 0; i < n; ++i) {
        double ph = 2.0*3.14159265358979*i/8.0;
        double vi = (double)I[i]+a*std::cos(ph);
        double vq = (double)Q[i]+a*std::sin(ph);
        if (vi>2047) vi=2047; if (vi<-2048) vi=-2048;
        if (vq>2047) vq=2047; if (vq<-2048) vq=-2048;
        I[i]=(int16_t)std::lround(vi); Q[i]=(int16_t)std::lround(vq);
    }
}

static DecodedPacket g_last{};
static void on_pkt(const DecodedPacket &pkt) { g_last = pkt; }

// ════════════════════════════════════════════════════════════
//  공통: FEC 직접 TX→RX→정렬→디코딩
// ════════════════════════════════════════════════════════════
static bool fec_txrx_decode(PlutoCtx &p, const uint8_t *info, uint32_t il,
                            int bps, int nc, int rv,
                            FEC_HARQ::IR_RxState &ir, FEC_HARQ::WorkBuf &wb,
                            uint8_t *out, int *olen,
                            const int16_t *jamI = nullptr,
                            const int16_t *jamQ = nullptr, int jam_len = 0) {
    const int nsym = FEC_HARQ::nsym_for_bps(bps);
    const int total = nsym * nc;

    uint8_t syms[FEC_HARQ::NSYM64]{};
    std::memset(&wb, 0, sizeof(wb));
    if (FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv&3, wb) <= 0) return false;

    std::vector<int16_t> sigI(total), sigQ(total);
    for (int s = 0; s < nsym; ++s)
        walsh_enc(syms[s], nc, kAmp, &sigI[s*nc], &sigQ[s*nc]);

    std::vector<int16_t> refI = sigI, refQ = sigQ;

    if (jamI && jamQ && jam_len == total) {
        for (int i = 0; i < total; ++i) { sigI[i] = jamI[i]; sigQ[i] = jamQ[i]; }
    }

    std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
    fill_tx_repeated(txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                     sigI.data(), sigQ.data(), total);

    std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
    int n_rx = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
    if (n_rx < total) return false;

    apply_digital_agc(rxI.data(), rxQ.data(), n_rx);
    apply_phase_correction(rxI.data(), rxQ.data(), n_rx);
    int ss = find_signal_start(rxI.data(), rxQ.data(), n_rx,
                               refI.data(), refQ.data(), total);
    if (ss + total > n_rx) ss = 0;

    std::memset(&wb, 0, sizeof(wb));
    bool dec = FEC_HARQ::Decode64_IR(&rxI[ss], &rxQ[ss], nsym, nc, bps,
                                     il, rv&3, ir, out, olen, wb);
    return dec && *olen == 8 && std::memcmp(out, info, 8) == 0;
}

static bool fec16_txrx_decode(PlutoCtx &p, const uint8_t *info, uint32_t il,
                              int rv, FEC_HARQ::IR_RxState &ir,
                              FEC_HARQ::WorkBuf &wb, uint8_t *out, int *olen) {
    const int nc = 16, nsym = FEC_HARQ::NSYM16;
    const int total = nsym * nc;

    uint8_t syms[FEC_HARQ::NSYM16]{};
    std::memset(&wb, 0, sizeof(wb));
    if (FEC_HARQ::Encode16_IR(info, 8, syms, il, rv&3, wb) <= 0) return false;

    std::vector<int16_t> sigI(total), sigQ(total);
    for (int s = 0; s < nsym; ++s)
        walsh_enc(syms[s], nc, kAmp, &sigI[s*nc], &sigQ[s*nc]);
    std::vector<int16_t> refI = sigI, refQ = sigQ;

    std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
    fill_tx_repeated(txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                     sigI.data(), sigQ.data(), total);

    std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
    int n_rx = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
    if (n_rx < total) return false;

    apply_digital_agc(rxI.data(), rxQ.data(), n_rx);
    apply_phase_correction(rxI.data(), rxQ.data(), n_rx);
    int ss = find_signal_start(rxI.data(), rxQ.data(), n_rx,
                               refI.data(), refQ.data(), total);
    if (ss + total > n_rx) ss = 0;

    std::memset(&wb, 0, sizeof(wb));
    bool dec = FEC_HARQ::Decode16_IR(&rxI[ss], &rxQ[ss], nsym, nc,
                                     FEC_HARQ::BPS16, il, rv&3, ir, out, olen, wb);
    return dec && *olen == 8 && std::memcmp(out, info, 8) == 0;
}

// ════════════════════════════════════════════════════════════
//  T0~T9 + 진단 printf 추가
// ════════════════════════════════════════════════════════════
static long long test_T0(PlutoCtx &p) {
    std::printf("\n══ T0: 수신 레벨 탐색 ══\n");
    std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
    for (int i = 0; i < PLUTO_BUF_SAMPLES; ++i) {
        int16_t v = ((i/32)&1) ? 1000 : -1000;
        txI[i] = v; txQ[i] = v;
    }
    long long best = -80;
    for (long long gain = -80; gain <= -40; gain += 5) {
        pluto_set_tx_gain(p, gain);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
        int n = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                 rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
        int32_t mx = 0;
        for (int i = 0; i < n; ++i) {
            int32_t a = rxI[i]<0 ? -rxI[i] : rxI[i];
            if (a > mx) mx = a;
        }
        std::printf("  TX=%3lld dB → RX max=%5d", gain, (int)mx);
        if (mx > 1800) { std::printf(" ← 포화!\n"); break; }
        if (mx >= 300 && mx < 1500) { best=gain; std::printf(" ← 적정 ✓\n"); break; }
        if (mx >= 50) { best=gain; std::printf(" ← 감지\n"); }
        else std::printf(" ← 미감지\n");
    }
    std::printf("  TX gain: %lld dB\n", best);
    pluto_set_tx_gain(p, best);
    return best;
}

static bool test_T1(PlutoCtx &p) {
    std::printf("\n══ T1: 연결 확인 ══\n");
    pluto_flush_rx(p);
    std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
    int n = pluto_rx(p, rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
    std::printf("  RX %d samples\n  T1: %s\n", n, n>0?"PASS":"FAIL");
    return n > 0;
}

static void test_T2(PlutoCtx &p) {
    std::printf("\n══ T2: 클린 루프백 ══\n");
    FEC_HARQ::Set_IR_Erasure_Enabled(false);
    FEC_HARQ::Set_IR_Rs_Post_Enabled(true);
    int ok = 0;
    for (int t = 0; t < 10; ++t) {
        uint32_t ts = 0xB40730u ^ (uint32_t)(t*0x9E3779B9u);
        uint8_t info[8]; gen_info(ts, info);
        FEC_HARQ::IR_RxState ir{}; FEC_HARQ::IR_Init(ir);
        FEC_HARQ::WorkBuf wb{};
        uint8_t out[8]{}; int olen=0;
        bool dec = fec_txrx_decode(p, info, 0xA5A5A5A5u^ts, 4, 64, 0, ir, wb, out, &olen);
        std::printf("  [%2d] %s\n", t, dec?"OK":"FAIL");
        if (dec) ok++;
    }
    std::printf("  T2: %d/10\n", ok);
}

static void test_T3(PlutoCtx &p, long long base) {
    std::printf("\n══ T3: TX gain 스윕 ══\n");
    for (long long off = 0; off >= -30; off -= 5) {
        long long g = base+off; if (g<-89) g=-89;
        pluto_set_tx_gain(p, g);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        int ok = 0;
        for (int t = 0; t < 10; ++t) {
            uint32_t ts = 0xCAFE00u ^ (uint32_t)(t*0x9E3779B9u);
            uint8_t info[8]; gen_info(ts, info);
            FEC_HARQ::IR_RxState ir{}; FEC_HARQ::IR_Init(ir);
            FEC_HARQ::WorkBuf wb{};
            uint8_t out[8]{}; int olen=0;
            if (fec_txrx_decode(p, info, 0xA5A5A5A5u^ts, 4, 64, 0, ir, wb, out, &olen)) ok++;
        }
        std::printf("  TX=%3lld dB (%+lld) %d/10\n", g, off, ok);
    }
    pluto_set_tx_gain(p, base);
}

static void test_T4(PlutoCtx &p) {
    std::printf("\n══ T4: 바라지 재밍 ══\n");
    const double js[] = {0,5,10,15,20,25,30};
    const int bps = 3, nc = 64;
    const int nsym = FEC_HARQ::nsym_for_bps(bps);
    const int total = nsym * nc;

    for (double j : js) {
        // DAC 클리핑 방지: 3σ < 2048 조건
        // safe = 2047 / (1 + 3×√(10^(j/10)))
        const double lin = std::pow(10.0, j / 10.0);
        const double denom = 1.0 + 3.0 * std::sqrt(lin);
        int16_t amp_t4 = static_cast<int16_t>(
            std::min(static_cast<double>(kAmp), 2047.0 / denom));
        if (amp_t4 < 30)
            amp_t4 = 30; // Pluto 채널 SNR 하한

        int ok = 0; double ar = 0;
        for (int t = 0; t < 10; ++t) {
            uint32_t ts = 0xDEAD00u ^ (uint32_t)(t * 0x9E3779B9u);
            uint32_t il = 0xA5A5A5A5u ^ ts;
            uint8_t info[8]; gen_info(ts, info);

            HTS_V400_Dispatcher disp;
            disp.Set_Seed(0xA5A5A5A5u ^ ts);
            disp.Set_IR_Mode(true);
            disp.Set_CW_Cancel(true);
            disp.Set_AJC_Enabled(true);
            disp.Set_SoftClip_Policy(SoftClipPolicy::ALWAYS);
            disp.Set_Packet_Callback(on_pkt);
            disp.Set_Lab_BPS64(bps);
            disp.Set_Lab_IQ_Mode_Jam_Harness();

            bool dec = false; int rnd = 0;
            for (int rv = 0; rv < 32 && !dec; ++rv) {
                g_last = DecodedPacket{};

                // 페이로드만 인코딩
                FEC_HARQ::WorkBuf wb{};
                uint8_t syms[FEC_HARQ::NSYM64]{};
                std::memset(&wb, 0, sizeof(wb));
                FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb);

                std::vector<int16_t> sI(total), sQ(total);
                for (int s = 0; s < nsym; ++s)
                    walsh_enc(syms[s], nc, amp_t4, &sI[s * nc], &sQ[s * nc]);

                // 재밍 추가 (페이로드에만) — amp_t4 기준 바라지
                std::mt19937 rng(ts ^ (uint32_t)(rv * 0x85EBCA6Bu));
                {
                    double sigma_t4 =
                        static_cast<double>(amp_t4) * std::sqrt(lin);
                    std::normal_distribution<double> nd(0.0, sigma_t4);
                    for (int i = 0; i < total; ++i) {
                        double vi = (double)sI[i] + nd(rng);
                        double vq = (double)sQ[i] + nd(rng);
                        if (vi > 2047) vi = 2047;
                        if (vi < -2048) vi = -2048;
                        if (vq > 2047) vq = 2047;
                        if (vq < -2048) vq = -2048;
                        sI[i] = (int16_t)std::lround(vi);
                        sQ[i] = (int16_t)std::lround(vq);
                    }
                }

                // TX → RX
                std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
                fill_tx_repeated(txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                 sI.data(), sQ.data(), total);
                std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
                int nr = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                          rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
                if (nr <= 0) break;

                apply_digital_agc(rxI.data(), rxQ.data(), nr);
                apply_phase_correction(rxI.data(), rxQ.data(), nr);

                // 클린 레퍼런스로 정렬 (재밍 전 원본, amp_t4와 동일 진폭)
                std::vector<int16_t> refI(total), refQ(total);
                for (int s = 0; s < nsym; ++s)
                    walsh_enc(syms[s], nc, amp_t4, &refI[s * nc], &refQ[s * nc]);
                int ss = find_signal_start(rxI.data(), rxQ.data(), nr,
                                           refI.data(), refQ.data(), total);
                if (ss + total > nr) ss = 0;

                // 디스패처: 동기 건너뛰고 페이로드 직접 진입
                if (rv == 0) {
                    disp.Inject_Payload_Phase(PayloadMode::DATA, bps);
                }

                // Feed — ECCM 파이프라인 경유
                for (int i = 0; i < total; ++i) {
                    if (rv == 0) {
                        disp.Feed_Chip(rxI[ss + i], rxQ[ss + i]);
                    } else {
                        disp.Feed_Retx_Chip(rxI[ss + i], rxQ[ss + i]);
                    }
                }

                dec = (g_last.success_mask == DecodedPacket::DECODE_MASK_OK);
                rnd = rv + 1;
                if (dec && (g_last.data_len != 8 ||
                    std::memcmp(g_last.data, info, 8) != 0)) dec = false;
            }
            if (dec) { ok++; ar += rnd; }
        }
        if (ok > 0) ar /= ok;
        std::printf("  J/S=%2.0f dB %d/10 avg %.1fR\n", j, ok, ar);
        if (ok == 0) break;
    }
}

static void test_T5(PlutoCtx &p) {
    std::printf("\n══ T5: CW 재밍 ══\n");
    const double js[] = {0,5,10,15,20};
    const int bps = 4, nc = 64;
    const int nsym = FEC_HARQ::nsym_for_bps(bps);
    const int total = nsym * nc;

    for (double j : js) {
        int ok = 0; double ar = 0;
        for (int t = 0; t < 10; ++t) {
            uint32_t ts = 0xCCCC00u ^ (uint32_t)(t * 0x9E3779B9u);
            uint32_t il = 0xA5A5A5A5u ^ ts;
            uint8_t info[8]; gen_info(ts, info);

            HTS_V400_Dispatcher disp;
            disp.Set_Seed(0xA5A5A5A5u ^ ts);
            disp.Set_IR_Mode(true);
            disp.Set_CW_Cancel(true);
            disp.Set_AJC_Enabled(true);
            disp.Set_SoftClip_Policy(SoftClipPolicy::ALWAYS);
            disp.Set_Packet_Callback(on_pkt);
            disp.Set_Lab_BPS64(bps);
            disp.Set_Lab_IQ_Mode_Jam_Harness();

            bool dec = false; int rnd = 0;
            for (int rv = 0; rv < 32 && !dec; ++rv) {
                g_last = DecodedPacket{};

                FEC_HARQ::WorkBuf wb{};
                uint8_t syms[FEC_HARQ::NSYM64]{};
                std::memset(&wb, 0, sizeof(wb));
                FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb);

                std::vector<int16_t> sI(total), sQ(total);
                for (int s = 0; s < nsym; ++s)
                    walsh_enc(syms[s], nc, kAmp, &sI[s * nc], &sQ[s * nc]);

                std::vector<int16_t> refI = sI, refQ = sQ;

                // 매 라운드 동일 CW (위상 연속)
                add_cw(sI.data(), sQ.data(), total, j);

                std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
                fill_tx_repeated(txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                 sI.data(), sQ.data(), total);
                std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
                int nr = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                          rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
                if (nr <= 0) break;

                apply_digital_agc(rxI.data(), rxQ.data(), nr);
                apply_phase_correction(rxI.data(), rxQ.data(), nr);
                int ss = find_signal_start(rxI.data(), rxQ.data(), nr,
                                           refI.data(), refQ.data(), total);
                if (ss + total > nr) ss = 0;

                if (rv == 0) {
                    disp.Inject_Payload_Phase(PayloadMode::DATA, bps);
                }

                for (int i = 0; i < total; ++i) {
                    if (rv == 0)
                        disp.Feed_Chip(rxI[ss + i], rxQ[ss + i]);
                    else
                        disp.Feed_Retx_Chip(rxI[ss + i], rxQ[ss + i]);
                }

                dec = (g_last.success_mask == DecodedPacket::DECODE_MASK_OK);
                rnd = rv + 1;
                if (dec && (g_last.data_len != 8 ||
                    std::memcmp(g_last.data, info, 8) != 0)) dec = false;
            }
            if (dec) { ok++; ar += rnd; }
        }
        if (ok > 0) ar /= ok;
        std::printf("  CW J/S=%2.0f dB %d/10 avg %.1fR\n", j, ok, ar);
        if (ok == 0) break;
    }
}

static void test_T6(PlutoCtx &p) {
    std::printf("\n══ T6: 디스패처 동기화 ══\n");
    static constexpr int kMaxC = 256 + (FEC_HARQ::NSYM64+12)*64;
    int sync_ok = 0;
    for (int t = 0; t < 10; ++t) {
        g_last = DecodedPacket{};
        uint32_t ds = 0xF00D00u^(uint32_t)(t*0x9E3779B9u);
        HTS_V400_Dispatcher disp;
        disp.Set_IR_Mode(true); disp.Set_Seed(ds);
        disp.Set_Preamble_Boost(16); disp.Set_Preamble_Reps(1);
        disp.Set_CW_Cancel(false); disp.Set_AJC_Enabled(false);
        disp.Set_SoftClip_Policy(SoftClipPolicy::NEVER);
        disp.Set_Packet_Callback(on_pkt);
        disp.Update_Adaptive_BPS(1000);
        uint8_t info[8]{};
        for (int b=0;b<8;++b) info[b]=(uint8_t)((ds>>(b*4))^(unsigned)(t+b));
        std::vector<int16_t> sigI(kMaxC), sigQ(kMaxC);
        int n = disp.Build_Packet(PayloadMode::DATA, info, 8, kAmp, sigI.data(), sigQ.data(), kMaxC);
        if (n<=0) continue;
        std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
        fill_tx_repeated(txI.data(), txQ.data(), PLUTO_BUF_SAMPLES, sigI.data(), sigQ.data(), n);
        std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
        int nr = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES, rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
        if (nr<=0) continue;
        apply_digital_agc(rxI.data(), rxQ.data(), nr);
        apply_phase_correction(rxI.data(), rxQ.data(), nr);
        for (int i=0;i<nr;++i) disp.Feed_Chip(rxI[i], rxQ[i]);
        bool ok = (g_last.success_mask == DecodedPacket::DECODE_MASK_OK);
        int phase_val = static_cast<int>(disp.Get_Phase());
        std::printf("  [%2d] tx=%d rx=%d phase=%d %s\n", t, n, nr, phase_val, ok?"OK":"FAIL");
        if (ok) sync_ok++;
    }
    std::printf("  T6: %d/10\n", sync_ok);
}

static void test_T7(PlutoCtx &p) {
    std::printf("\n══ T7: IR-HARQ 바라지 20dB ══\n");
    const int bps = 3, nc = 64;
    const int nsym = FEC_HARQ::nsym_for_bps(bps);
    const int total = nsym * nc;
    int ok = 0; double ar = 0;

    for (int t = 0; t < 10; ++t) {
        uint32_t ts = 0xBEEF00u ^ (uint32_t)(t * 0x9E3779B9u);
        uint32_t il = 0xA5A5A5A5u ^ ts;
        uint8_t info[8]; gen_info(ts, info);

        HTS_V400_Dispatcher disp;
        disp.Set_Seed(0xA5A5A5A5u ^ ts);
        disp.Set_IR_Mode(true);
        disp.Set_CW_Cancel(true);
        disp.Set_AJC_Enabled(true);
        disp.Set_SoftClip_Policy(SoftClipPolicy::ALWAYS);
        disp.Set_Packet_Callback(on_pkt);
        disp.Set_Lab_BPS64(bps);
        disp.Set_Lab_IQ_Mode_Jam_Harness();

        bool dec = false; int rnd = 0;
        for (int rv = 0; rv < 32 && !dec; ++rv) {
            g_last = DecodedPacket{};

            FEC_HARQ::WorkBuf wb{};
            uint8_t syms[FEC_HARQ::NSYM64]{};
            std::memset(&wb, 0, sizeof(wb));
            FEC_HARQ::Encode64_IR(info, 8, syms, il, bps, rv & 3, wb);

            std::vector<int16_t> sI(total), sQ(total);
            // DAC 클리핑 방지: J/S=20dB에서 3σ=1800 < 2048
            static constexpr int16_t kAmpT7 = 60;
            for (int s = 0; s < nsym; ++s)
                walsh_enc(syms[s], nc, kAmpT7, &sI[s * nc], &sQ[s * nc]);

            std::vector<int16_t> refI = sI, refQ = sQ;

            std::mt19937 rng(ts ^ (uint32_t)(rv * 0x85EBCA6Bu));
            // kAmpT7 기준 바라지 (kAmpD 대신 60.0)
            {
                double sigma_t7 = 60.0 * std::sqrt(std::pow(10.0, 20.0/10.0));
                std::normal_distribution<double> nd(0.0, sigma_t7);
                for (int i = 0; i < total; ++i) {
                    double vi = (double)sI[i] + nd(rng);
                    double vq = (double)sQ[i] + nd(rng);
                    if (vi>2047) vi=2047; if (vi<-2048) vi=-2048;
                    if (vq>2047) vq=2047; if (vq<-2048) vq=-2048;
                    sI[i]=(int16_t)std::lround(vi);
                    sQ[i]=(int16_t)std::lround(vq);
                }
            }

            std::vector<int16_t> txI(PLUTO_BUF_SAMPLES), txQ(PLUTO_BUF_SAMPLES);
            fill_tx_repeated(txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                             sI.data(), sQ.data(), total);
            std::vector<int16_t> rxI(PLUTO_BUF_SAMPLES), rxQ(PLUTO_BUF_SAMPLES);
            int nr = pluto_tx_then_rx(p, txI.data(), txQ.data(), PLUTO_BUF_SAMPLES,
                                      rxI.data(), rxQ.data(), PLUTO_BUF_SAMPLES);
            if (nr <= 0) break;

            apply_digital_agc(rxI.data(), rxQ.data(), nr);
            apply_phase_correction(rxI.data(), rxQ.data(), nr);
            int ss = find_signal_start(rxI.data(), rxQ.data(), nr,
                                       refI.data(), refQ.data(), total);
            if (ss + total > nr) ss = 0;

            if (rv == 0) {
                disp.Inject_Payload_Phase(PayloadMode::DATA, bps);
            }

            for (int i = 0; i < total; ++i) {
                if (rv == 0)
                    disp.Feed_Chip(rxI[ss + i], rxQ[ss + i]);
                else
                    disp.Feed_Retx_Chip(rxI[ss + i], rxQ[ss + i]);
            }

            dec = (g_last.success_mask == DecodedPacket::DECODE_MASK_OK);
            rnd = rv + 1;
            if (dec && (g_last.data_len != 8 ||
                std::memcmp(g_last.data, info, 8) != 0)) dec = false;
        }
        std::printf("  [%2d] %s R=%d\n", t, dec ? "OK" : "FAIL", rnd);
        if (dec) { ok++; ar += rnd; }
    }
    if (ok > 0) ar /= ok;
    std::printf("  T7: %d/10 avg %.1fR\n", ok, ar);
}

static void test_T8(PlutoCtx &p) {
    std::printf("\n══ T8: 16칩 VOICE ══\n");
    int ok=0;
    for (int t=0;t<10;++t) {
        uint32_t ts=0xAAAA00u^(uint32_t)(t*0x9E3779B9u);
        uint8_t info[8]; gen_info(ts,info);
        FEC_HARQ::IR_RxState ir{}; FEC_HARQ::IR_Init(ir);
        FEC_HARQ::WorkBuf wb{};
        uint8_t out[8]{}; int ol=0;
        bool dec = fec16_txrx_decode(p,info,0xA5A5A5A5u^ts,0,ir,wb,out,&ol);
        std::printf("  [%2d] %s\n", t, dec?"OK":"FAIL");
        if (dec) ok++;
    }
    std::printf("  T8: %d/10\n", ok);
}

static void test_T9(PlutoCtx &p) {
    std::printf("\n══ T9: 내구 (100패킷) ══\n");
    int ok=0;
    auto t0=std::chrono::steady_clock::now();
    for (int t=0;t<100;++t) {
        uint32_t ts=0x999900u^(uint32_t)(t*0x9E3779B9u);
        uint8_t info[8]; gen_info(ts,info);
        FEC_HARQ::IR_RxState ir{}; FEC_HARQ::IR_Init(ir);
        FEC_HARQ::WorkBuf wb{};
        uint8_t out[8]{}; int ol=0;
        if (fec_txrx_decode(p,info,0xA5A5A5A5u^ts,4,64,0,ir,wb,out,&ol)) ok++;
        if ((t+1)%25==0) std::printf("  %d/100 (ok=%d)\n", t+1, ok);
    }
    auto t1=std::chrono::steady_clock::now();
    double sec=std::chrono::duration<double>(t1-t0).count();
    std::printf("  T9: %d/100 %.1fs\n", ok, sec);
}

int main() {
    std::printf("╔══════════════════════════════════════════════╗\n");
    std::printf("║  HTS B-CDMA ADALM-PLUTO V14                 ║\n");
    std::printf("║  USB + Cyclic TX + RX 50dB + 스레드 없음     ║\n");
    std::printf("╚══════════════════════════════════════════════╝\n\n");
    PlutoCtx pluto{};
    if (!pluto_open(pluto)) { std::printf("[FATAL] 초기화 실패\n"); return 1; }
    pluto_flush_rx(pluto);

    // ── Pluto RF 웜업 (T0 직전: PLL/RX 경로 정착) ──
    std::printf("══ RF 웜업 ══\n");
    pluto_set_tx_gain(pluto, -40);
    {
        std::vector<int16_t> wtx(PLUTO_BUF_SAMPLES), wtq(PLUTO_BUF_SAMPLES);
        std::memset(wtx.data(), 0, PLUTO_BUF_SAMPLES * sizeof(int16_t));
        std::memset(wtq.data(), 0, PLUTO_BUF_SAMPLES * sizeof(int16_t));
        std::vector<int16_t> wrx(PLUTO_BUF_SAMPLES), wrq(PLUTO_BUF_SAMPLES);
        for (int w = 0; w < 3; ++w) {
            pluto_tx_then_rx(pluto, wtx.data(), wtq.data(), PLUTO_BUF_SAMPLES,
                             wrx.data(), wrq.data(), PLUTO_BUF_SAMPLES);
            std::printf("  warmup %d/3\n", w + 1);
        }
    }

    test_T0(pluto);
    const long long tx_gain = -40;
    pluto_set_tx_gain(pluto, tx_gain);
    // 안정성 확인: TX=-40 dB에서 RX max (T0와 동일 칩 패턴), 200 미만이면 1회 재측정
    {
        std::vector<int16_t> chk_txI(PLUTO_BUF_SAMPLES), chk_txQ(PLUTO_BUF_SAMPLES);
        for (int i = 0; i < PLUTO_BUF_SAMPLES; ++i) {
            int16_t v = ((i / 32) & 1) ? 1000 : -1000;
            chk_txI[i] = v;
            chk_txQ[i] = v;
        }
        std::vector<int16_t> chk_rxI(PLUTO_BUF_SAMPLES), chk_rxQ(PLUTO_BUF_SAMPLES);
        int n_chk = pluto_tx_then_rx(pluto, chk_txI.data(), chk_txQ.data(),
                                     PLUTO_BUF_SAMPLES, chk_rxI.data(), chk_rxQ.data(),
                                     PLUTO_BUF_SAMPLES);
        int32_t rx_max = 0;
        for (int i = 0; i < n_chk; ++i) {
            int32_t a = chk_rxI[i] < 0 ? -chk_rxI[i] : chk_rxI[i];
            if (a > rx_max)
                rx_max = a;
        }
        if (rx_max < 200) {
            n_chk = pluto_tx_then_rx(pluto, chk_txI.data(), chk_txQ.data(),
                                     PLUTO_BUF_SAMPLES, chk_rxI.data(), chk_rxQ.data(),
                                     PLUTO_BUF_SAMPLES);
            rx_max = 0;
            for (int i = 0; i < n_chk; ++i) {
                int32_t a = chk_rxI[i] < 0 ? -chk_rxI[i] : chk_rxI[i];
                if (a > rx_max)
                    rx_max = a;
            }
        }
        std::printf("  TX gain 고정: %lld dB, RX max 확인: %d\n", tx_gain,
                    static_cast<int>(rx_max));
    }
    test_T1(pluto);
    test_T2(pluto);
    test_T6(pluto);
    test_T3(pluto, tx_gain);
    test_T8(pluto);
    test_T9(pluto);
    test_T4(pluto);
    test_T5(pluto);
    test_T7(pluto);
    pluto_close(pluto);
    std::printf("\n══ 완료 ══\n");
    return 0;
}
