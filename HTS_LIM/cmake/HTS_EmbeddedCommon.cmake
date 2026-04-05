# =============================================================================
# HTS 펌웨어 공통 컴파일/링크 정책 (arm-none-eabi)
# toolchain 파일 로드 후, arm_firmware/CMakeLists.txt 에서 include().
# 코어 알고리즘 소스는 수정하지 않음 — 빌드 정책만 정의.
# =============================================================================

include_guard(GLOBAL)

get_filename_component(HTS_EMBED_CMAKE_ROOT "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)

option(HTS_ARM_STRICT_CONVERSION "암묵적 변환 검사 (-Wconversion/-Wsign-conversion/-Wdouble-promotion)" ON)
option(HTS_ARM_STRICT_CXX "C++ 추가 엄격 경고 (-Wold-style-cast 등)" OFF)
option(HTS_ARM_ENFORCE_NO_HEAP_LINK "malloc/newlib 힙 래핑(호출 시 트랩) + -fno-builtin-*" ON)

# --- 엄격 경고 / Werror -------------------------------------------------------
set(_hts_wflags_c
  -Wall
  -Wextra
  -Werror
  -Wshadow
  -Wformat=2
  -Wstrict-overflow=2
  -Wcast-align
  -Wwrite-strings
  -Wundef
  $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes>
  $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
  # 암묵적 정수·부동 변환 검증 (레거시 정리 전에는 OFF 권장)
  $<$<BOOL:${HTS_ARM_STRICT_CONVERSION}>:-Wconversion>
  $<$<BOOL:${HTS_ARM_STRICT_CONVERSION}>:-Wsign-conversion>
  $<$<BOOL:${HTS_ARM_STRICT_CONVERSION}>:-Wdouble-promotion>
)

# C++: 암묵적 변환·구식 캐스트 검출 (필요 시 HTS_ARM_STRICT_CXX=OFF)
set(_hts_wflags_cxx_extra "")
if(HTS_ARM_STRICT_CXX)
  list(APPEND _hts_wflags_cxx_extra -Wold-style-cast -Wnon-virtual-dtor)
endif()

# --- 용량 최적화 / freestanding 친화 ----------------------------------------
set(_hts_opt_flags
  -Os
  -ffunction-sections
  -fdata-sections
  -fno-common
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
)

# new/malloc 등 내장 최적화 우회 → 래핑/감사 가능
set(_hts_no_builtin_alloc
  -fno-builtin-malloc
  -fno-builtin-calloc
  -fno-builtin-realloc
  -fno-builtin-free
  -fno-builtin-aligned_alloc
)

# =============================================================================
# 함수: hts_apply_embedded_properties(<target>)
# =============================================================================
function(hts_apply_embedded_properties _tgt)
  if(NOT TARGET "${_tgt}")
    message(FATAL_ERROR "hts_apply_embedded_properties: target '${_tgt}' not found")
  endif()

  target_compile_features(${_tgt} PUBLIC cxx_std_20 c_std_11)

  target_compile_options(${_tgt} PRIVATE
    ${_hts_opt_flags}
    ${_hts_wflags_c}
    ${_hts_wflags_cxx_extra}
    ${_hts_no_builtin_alloc}
    $<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-threadsafe-statics>
  )

  # 링크: 섹션 GC + newlib nano / nosys (시스템 콜은 보드 BSP에서 제공)
  target_link_options(${_tgt} PRIVATE
    LINKER:--gc-sections
    LINKER:--no-wchar-size-warning
    -Wl,--print-memory-usage
    -specs=nano.specs
    -specs=nosys.specs
  )

  if(HTS_ARM_ENFORCE_NO_HEAP_LINK)
    target_sources(${_tgt} PRIVATE
      "${HTS_EMBED_CMAKE_ROOT}/stubs/no_heap_wrap.c"
    )
    target_link_options(${_tgt} PRIVATE
      LINKER:--wrap=malloc
      LINKER:--wrap=calloc
      LINKER:--wrap=realloc
      LINKER:--wrap=free
      LINKER:--wrap=_malloc_r
      LINKER:--wrap=_free_r
      LINKER:--wrap=_realloc_r
      LINKER:--wrap=_calloc_r
    )
    # libstdc++ operator new → malloc 경로를 래핑으로 흡수
    target_compile_options(${_tgt} PRIVATE
      $<$<COMPILE_LANGUAGE:CXX>:-fno-builtin-malloc>
    )
  endif()

  if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options(${_tgt} PRIVATE -g3)
  endif()
endfunction()
