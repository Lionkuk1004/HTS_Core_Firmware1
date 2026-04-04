/* HTS Verify_Target_CrossCompile — 가상 타겟 메모리 맵 (Flash 512KiB, SRAM 128KiB, 힙 0바이트)
 * 실제 STM32F407(1MiB/192KiB)보다 빡빡한 한계로 이식성·섹션 침범 조기 검출용.
 */
MEMORY
{
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 512K
  RAM   (rwx) : ORIGIN = 0x20000000, LENGTH = 128K
}

_Min_Heap_Size   = 0;
_Min_Stack_Size  = 0x800; /* 2KiB 예약 — 스택만 허용, 힙 금지 */

/* 초기 스택 포인터: RAM 최상단 (성장 방향은 구현체 관례에 따름) */
_estack = ORIGIN(RAM) + LENGTH(RAM);

ENTRY(Reset_Handler)

SECTIONS
{
  .isr_vector : {
    KEEP(*(.isr_vector))
    . = ALIGN(4);
  } > FLASH

  .text : {
    *(.text .text.*)
    *(.gnu.linkonce.t.*)
    . = ALIGN(4);
  } > FLASH

  .rodata : {
    *(.rodata .rodata.*)
    *(.gnu.linkonce.r.*)
    . = ALIGN(4);
  } > FLASH

  _etext = .;

  .data : AT (_etext) {
    . = ALIGN(4);
    _sdata = .;
    *(.data .data.*)
    *(.gnu.linkonce.d.*)
    . = ALIGN(4);
    _edata = .;
  } > RAM

  _sidata = LOADADDR(.data);
  _flash_image_end = LOADADDR(.data) + SIZEOF(.data);

  .bss (NOLOAD) : {
    . = ALIGN(4);
    _sbss = .;
    *(.bss .bss.*)
    *(COMMON)
    . = ALIGN(4);
    _ebss = .;
  } > RAM

  /* 힙 0바이트 + 스택 예약 — 링커가 RAM 상한을 단일 지점에서 검증 */
  ._heap_stack (NOLOAD) : {
    . = ALIGN(8);
    __heap_start = .;
    . = . + _Min_Heap_Size;
    . = ALIGN(8);
    __heap_end = .;
    . = ALIGN(8);
    . = . + _Min_Stack_Size;
    . = ALIGN(8);
    __ram_alloc_end = .;
  } > RAM

  ASSERT(__heap_end == __heap_start, "heap must be 0 bytes (see _Min_Heap_Size)");
  ASSERT(_flash_image_end <= ORIGIN(FLASH) + LENGTH(FLASH), "FLASH overflow");
  ASSERT(__ram_alloc_end <= (ORIGIN(RAM) + LENGTH(RAM)), "RAM overflow");
}
