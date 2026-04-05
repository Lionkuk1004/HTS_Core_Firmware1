/**
 * @file minimal_cortex_m4f.S
 * @brief STM32F407-class (Cortex-M4F) 최소 벡터·Reset — 툴체인 검증용
 *
 * 제품 펌웨어는 CMSIS/Device 벤더 startup으로 교체하는 것을 권장합니다.
 */
    .syntax unified
    .cpu cortex-m4
    .fpu fpv4-sp-d16
    .thumb

    .section .isr_vector,"a",%progbits
    .align 2
    .global g_pfnVectors
    .type g_pfnVectors, %object
g_pfnVectors:
    .word _estack
    .word Reset_Handler
    .word NMI_Handler
    .word HardFault_Handler
    .word MemManage_Handler
    .word BusFault_Handler
    .word UsageFault_Handler
    .word 0
    .word 0
    .word 0
    .word 0
    .word SVCall_Handler
    .word DebugMon_Handler
    .word 0
    .word PendSV_Handler
    .word SysTick_Handler

    .section .text.Default_Handler
    .thumb_func
    .type Default_Handler, %function
Default_Handler:
    b Default_Handler

    .macro weak_handler name
    .weak \name
    .thumb_set \name, Default_Handler
    .endm

    weak_handler NMI_Handler
    weak_handler HardFault_Handler
    weak_handler MemManage_Handler
    weak_handler BusFault_Handler
    weak_handler UsageFault_Handler
    weak_handler SVCall_Handler
    weak_handler DebugMon_Handler
    weak_handler PendSV_Handler
    weak_handler SysTick_Handler

    .section .text.Reset_Handler
    .thumb_func
    .global Reset_Handler
    .type Reset_Handler, %function
Reset_Handler:
    /* .data 복사 (FLASH -> RAM) */
    ldr r0, =_sidata
    ldr r1, =_sdata
    ldr r2, =_edata
    subs r2, r2, r1
    ble 1f
0:
    ldr r3, [r0]
    str r3, [r1]
    adds r0, r0, #4
    adds r1, r1, #4
    subs r2, r2, #4
    bgt 0b
1:
    /* .bss 제로 */
    movs r0, #0
    ldr r1, =_sbss
    ldr r2, =_ebss
    subs r2, r2, r1
    ble 3f
2:
    str r0, [r1]
    adds r1, r1, #4
    subs r2, r2, #4
    bgt 2b
3:
    bl main
    b .
