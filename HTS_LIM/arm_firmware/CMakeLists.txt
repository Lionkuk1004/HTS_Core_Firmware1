# =============================================================================
# HTS B-CDMA — ARM 타깃 타깃·스모크 실행 파일
# (상위 CMakeLists.txt 가 project() 및 툴체인 검증을 수행)
# =============================================================================

if(NOT CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "arm_firmware: 크로스 컴파일 환경이 아닙니다.")
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Debug|Release|RelWithDebInfo|MinSizeRel" FORCE)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/../cmake/HTS_EmbeddedCommon.cmake")

set(_hts_linker_script "${CMAKE_CURRENT_LIST_DIR}/../cmake/linker/STM32F407VG_FLASH.ld")

add_executable(hts_arm_toolchain_smoke
  "${CMAKE_CURRENT_LIST_DIR}/../cmake/startup/minimal_cortex_m4f.S"
  "${CMAKE_CURRENT_LIST_DIR}/../cmake/stubs/toolchain_smoke_main.cpp"
)

hts_apply_embedded_properties(hts_arm_toolchain_smoke)

target_link_options(hts_arm_toolchain_smoke PRIVATE
  "SHELL:-T${_hts_linker_script}"
)

set_target_properties(hts_arm_toolchain_smoke PROPERTIES
  LINK_DEPENDS "${_hts_linker_script}"
  SUFFIX ".elf"
)

add_custom_command(TARGET hts_arm_toolchain_smoke POST_BUILD
  COMMAND "${CMAKE_OBJCOPY}" -O ihex "$<TARGET_FILE:hts_arm_toolchain_smoke>" "$<TARGET_FILE_DIR:hts_arm_toolchain_smoke>/hts_arm_toolchain_smoke.hex"
  COMMAND "${CMAKE_OBJCOPY}" -O binary "$<TARGET_FILE:hts_arm_toolchain_smoke>" "$<TARGET_FILE_DIR:hts_arm_toolchain_smoke>/hts_arm_toolchain_smoke.bin"
  COMMAND "${CMAKE_SIZE}" "$<TARGET_FILE:hts_arm_toolchain_smoke>"
  COMMENT "arm-none-eabi: generate .hex / .bin and print size"
)
