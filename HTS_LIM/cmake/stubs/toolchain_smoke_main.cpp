/**
 * @file toolchain_smoke_main.cpp
 * @brief arm-none-eabi 툴체인·링커 스크립트 스모크용 최소 엔트리 (제품 코어 아님)
 */
int main(void)
{
    for (;;) {
        __asm volatile ("" ::: "memory");
    }
}
