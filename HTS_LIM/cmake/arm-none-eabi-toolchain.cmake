# =============================================================================
# arm-none-eabi-gcc CMake toolchain — INNOViD CORE-X Pro B-CDMA (AMI IoT / Cortex-M)
#
# 사용법 (빌드 트리는 소스 외부 권장):
#   cmake -S arm_firmware -B ../build-arm-m4 ^
#     -DCMAKE_TOOLCHAIN_FILE=../cmake/arm-none-eabi-toolchain.cmake ^
#     -G Ninja
#   cmake --build ../build-arm-m4
#
# 환경 변수로 컴파일러 경로 지정 가능:
#   ARM_GNU_TOOLCHAIN_BIN = "C:/Program Files (x86)/GNU Arm Embedded Toolchain/10 2021.10/bin"
# =============================================================================

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)

# 크로스 컴파일: 호스트에서 실행 파일 실행·링크 테스트 생략
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

if(DEFINED ENV{ARM_GNU_TOOLCHAIN_BIN} AND NOT "$ENV{ARM_GNU_TOOLCHAIN_BIN}" STREQUAL "")
  file(TO_CMAKE_PATH "$ENV{ARM_GNU_TOOLCHAIN_BIN}" _arm_bin)
  list(PREPEND CMAKE_PROGRAM_PATH "${_arm_bin}")
endif()

set(_triple arm-none-eabi)
find_program(CMAKE_C_COMPILER   ${_triple}-gcc   REQUIRED)
find_program(CMAKE_CXX_COMPILER ${_triple}-g++   REQUIRED)
find_program(CMAKE_ASM_COMPILER ${_triple}-gcc   REQUIRED)
find_program(CMAKE_OBJCOPY      ${_triple}-objcopy REQUIRED)
find_program(CMAKE_OBJDUMP      ${_triple}-objdump REQUIRED)
find_program(CMAKE_SIZE         ${_triple}-size    REQUIRED)
find_program(CMAKE_RANLIB       ${_triple}-ranlib  REQUIRED)
find_program(CMAKE_AR           ${_triple}-ar      REQUIRED)

set(CMAKE_ASM_COMPILER_TARGET ${_triple})
set(CMAKE_C_COMPILER_TARGET   ${_triple})
set(CMAKE_CXX_COMPILER_TARGET ${_triple})

# 호스트(Windows/Linux) 프로그램은 찾지 않음
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# ---------------------------------------------------------------------------
# 타깃 CPU (기본: STM32F407-class Cortex-M4F — 기준서 0-1과 정합)
# 캐시에서 덮어쓰기: -DHTS_MCPU=cortex-m33 -DHTS_MFPU=fpv5-sp-d16 -DHTS_MFLOAT_ABI=hard
# ---------------------------------------------------------------------------
set(HTS_MCPU "cortex-m4" CACHE STRING "ARM GCC -mcpu= value")
set(HTS_MFPU "fpv4-sp-d16" CACHE STRING "ARM GCC -mfpu= value (empty for M0/M3)")
set(HTS_MFLOAT_ABI "hard" CACHE STRING "ARM GCC -mfloat-abi: hard|soft|softfp")

set(_hts_fpu_flags "")
if(NOT "${HTS_MFPU}" STREQUAL "")
  set(_hts_fpu_flags "-mfpu=${HTS_MFPU};-mfloat-abi=${HTS_MFLOAT_ABI}")
endif()

# 초기 플래그 (프로젝트에서 add_subdirectory 전에 적용)
set(CMAKE_C_FLAGS_INIT
  "-mthumb;-mcpu=${HTS_MCPU};${_hts_fpu_flags};-ffunction-sections;-fdata-sections;-fno-common"
)
set(CMAKE_CXX_FLAGS_INIT
  "${CMAKE_C_FLAGS_INIT};-fno-exceptions;-fno-rtti;-fno-use-cxa-atexit"
)
set(CMAKE_ASM_FLAGS_INIT "${CMAKE_C_FLAGS_INIT}")

# 링커 (초기값) — 최종 타깃에는 HTS_EmbeddedCommon 에서도 --gc-sections 주입
set(CMAKE_EXE_LINKER_FLAGS_INIT
  "-mthumb;-mcpu=${HTS_MCPU};${_hts_fpu_flags};-Wl,--gc-sections"
)

unset(_hts_fpu_flags)
