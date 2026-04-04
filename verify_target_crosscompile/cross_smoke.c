/* 장벽 1: 32비트·정렬 — 패딩 없는 레이아웃만 사용(-Wpadded 통과).
 * 장벽 2: 배리어·REV·WFI가 실제 명령으로 번역되는지 objdump로 검증.
 */
#include <stdalign.h>
#include <stdint.h>

/* 패딩 제거: 큰 멤버 우선 배치 */
typedef struct {
    uint32_t w0;
    uint32_t w1;
    uint16_t h0;
    uint16_t h1;
} hts_packed_layout_t;

_Static_assert(sizeof(hts_packed_layout_t) == 12u, "layout size");
_Static_assert(alignof(hts_packed_layout_t) == 4u, "layout align");

/* .data에 상주 — LMA/RAM 복사 경로 검증 */
volatile uint32_t g_cross_init_magic = 0xC0550001u;

static uint32_t g_cross_bss_sink;

/* ARMv7-M 메모리 배리어 + 엔디안 + 슬립 (CMSIS 매크로 없이 직접 ASM — 툴체인 내장) */
void hts_cross_dsb_dmb_isb(void)
{
    __asm volatile("dsb sy" ::: "memory");
    __asm volatile("dmb sy" ::: "memory");
    __asm volatile("isb sy" ::: "memory");
}

uint32_t hts_cross_rev_u32(uint32_t x)
{
    return __builtin_bswap32(x);
}

void hts_cross_wfi_once(void)
{
    __asm volatile("wfi" ::: "memory");
}

/* 정렬된 버퍼에서만 워드 로드 — 비정렬 캐스트 금지(-Wcast-align 우회 없음) */
static uint32_t hts_load_aligned_word(const uint32_t* p)
{
    return *p;
}

int main(void)
{
    alignas(16) uint32_t block[4];
    block[0] = g_cross_init_magic;
    block[1] = hts_cross_rev_u32(0x11223344u);
    hts_cross_dsb_dmb_isb();
    g_cross_bss_sink = hts_load_aligned_word(&block[1]);
    hts_cross_wfi_once();
    (void)g_cross_bss_sink;
    return 0;
}
