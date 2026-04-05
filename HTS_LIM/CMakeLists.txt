# =============================================================================
# HTS_LIM — CMake 루트 (ARM 크로스 전용)
#
# PowerShell 예 (경로는 반드시 따옴표로 감쌀 것):
#   cmake -B build-arm-m4 -G Ninja `
#     "-DCMAKE_TOOLCHAIN_FILE=${PWD}/cmake/arm-none-eabi-toolchain.cmake" `
#     -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-arm-m4
#
# 또는: cmake --preset arm-m4-release
# =============================================================================

cmake_minimum_required(VERSION 3.20)

if(NOT CMAKE_TOOLCHAIN_FILE OR CMAKE_TOOLCHAIN_FILE STREQUAL "")
  message(FATAL_ERROR
    "ARM 펌웨어 크로스 빌드만 지원합니다. 예:\n"
    "  cmake -B build-arm-m4 -G Ninja \"-DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_SOURCE_DIR}/cmake/arm-none-eabi-toolchain.cmake\"\n"
    "툴체인 bin 경로는 환경 변수 ARM_GNU_TOOLCHAIN_BIN 에 추가하십시오.")
endif()

project(HTS_BCDMA_ARM_FIRMWARE LANGUAGES C CXX ASM)

if(NOT CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "툴체인 파일이 arm-none-eabi 를 가리키는지 확인하십시오 (CMAKE_CROSSCOMPILING=TRUE 이어야 함).")
endif()

add_subdirectory(arm_firmware)
