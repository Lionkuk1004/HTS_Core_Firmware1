# Verify_Target_CrossCompile — GNU Arm Embedded (arm-none-eabi-gcc) Cortex-M4F 하드 플로트
# 사용: make clean && make all
# Windows: mingw32-make 또는 Git Bash make; 없으면 Verify_Target_CrossCompile.ps1 사용

PREFIX ?= arm-none-eabi-
CC      := $(PREFIX)gcc
OBJDUMP := $(PREFIX)objdump
SIZE    := $(PREFIX)size

TARGET  := cross_verify

# 실칩 양산에 가깝게: Thumb, M4, FPU hard, 경고 전부 오류
CFLAGS  := -std=c11 -mthumb -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard \
	-ffreestanding -Wall -Wextra -Werror -Wcast-align -Wpadded \
	-Wconversion -Wsign-conversion \
	-ffunction-sections -fdata-sections -fno-common \
	-MMD

LDFLAGS := $(CFLAGS) -T stm32f4_verify.ld -nostdlib \
	-Wl,--gc-sections -Wl,-Map=$(TARGET).map -lgcc

SRCS := crt0.c cross_smoke.c
OBJS := $(SRCS:.c=.o)
DEPS := $(SRCS:.c=.d)

.PHONY: all clean verify-asm

all: $(TARGET).elf
	@echo "==== arm-none-eabi-size -A -d ===="
	$(SIZE) -A -d $(TARGET).elf
	@echo "==== arm-none-eabi-size (totals) ===="
	$(SIZE) $(TARGET).elf
	@echo "==== disassembly -> $(TARGET).lst ===="
	$(OBJDUMP) -d $(TARGET).elf > $(TARGET).lst

$(TARGET).elf: $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(OBJS) $(DEPS) $(TARGET).elf $(TARGET).map $(TARGET).lst

verify-asm: $(TARGET).elf
	$(OBJDUMP) -d $(TARGET).elf

-include $(DEPS)
