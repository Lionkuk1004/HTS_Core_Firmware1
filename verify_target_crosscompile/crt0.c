/* Cortex-M4 최소 부트: 벡터 테이블, .data 복사, .bss 클리어, main 호출 */
#include <stdint.h>

/* stm32f4_verify.ld 의 ORIGIN(RAM)+LENGTH(RAM) 과 반드시 일치 */
enum {
    kHtsVerifyRamBase = 0x20000000u,
    kHtsVerifyRamSize = 128u * 1024u
};
#define HTS_VERIFY_SP_INIT ((void*)(uintptr_t)(kHtsVerifyRamBase + kHtsVerifyRamSize))
extern uint32_t _sidata;
extern uint32_t _sdata;
extern uint32_t _edata;
extern uint32_t _sbss;
extern uint32_t _ebss;

extern int main(void);

static void Default_Handler(void)
{
    while (1) {
        __asm volatile("wfi" ::: "memory");
    }
}

void Reset_Handler(void) __attribute__((noreturn));

void Reset_Handler(void)
{
    uint32_t* src = &_sidata;
    uint32_t* dst = &_sdata;
    while (dst < &_edata) {
        *dst = *src;
        ++dst;
        ++src;
    }
    dst = &_sbss;
    while (dst < &_ebss) {
        *dst = 0u;
        ++dst;
    }
    (void)main();
    while (1) {
        __asm volatile("wfi" ::: "memory");
    }
}

/* ARMv7-M: 상위 16 벡터(시스템 예외) — 미사용은 Default_Handler */
__attribute__((section(".isr_vector"), used))
const void* const g_pfn_vectors[16u] = {
    HTS_VERIFY_SP_INIT,
    (const void*)Reset_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
    (const void*)Default_Handler,
};
