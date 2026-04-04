# Verify_Target_CrossCompile — CMake
# cmake -S . -B build -G Ninja -DCMAKE_TOOLCHAIN_FILE=arm-none-eabi-gcc.cmake
# cmake --build build

cmake_minimum_required(VERSION 3.16)
project(HTS_Verify_Target_CrossCompile LANGUAGES C)

set(CMAKE_EXECUTABLE_SUFFIX ".elf")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(cross_verify
	crt0.c
	cross_smoke.c
)

target_compile_options(cross_verify PRIVATE
	-mthumb
	-mcpu=cortex-m4
	-mfpu=fpv4-sp-d16
	-mfloat-abi=hard
	-ffreestanding
	-Wall
	-Wextra
	-Werror
	-Wcast-align
	-Wpadded
	-Wconversion
	-Wsign-conversion
	-ffunction-sections
	-fdata-sections
	-fno-common
)

target_link_options(cross_verify PRIVATE
	-T "${CMAKE_CURRENT_SOURCE_DIR}/stm32f4_verify.ld"
	-nostdlib
	-lgcc
	-Wl,--gc-sections
	"-Wl,-Map=$<TARGET_FILE_DIR:cross_verify>/cross_verify.map"
)

add_custom_command(TARGET cross_verify POST_BUILD
	COMMAND arm-none-eabi-size -A -d $<TARGET_FILE:cross_verify>
	COMMAND arm-none-eabi-size $<TARGET_FILE:cross_verify>
	COMMENT "arm-none-eabi-size after link"
)
