#Requires -Version 5.1
<#
.SYNOPSIS
  HTS 10단계 — Cortex-M4 타겟 크로스 컴파일·링크·intrinsic·메모리 맵 검증

.DESCRIPTION
  장벽1: -Wcast-align -Wpadded -Wconversion -Wsign-conversion + -Werror
  장벽2: objdump 에 dsb/dmb/isb/wfi/rev 패턴 존재 확인
  장벽3: stm32f4_verify.ld (Flash 512KiB, RAM 128KiB, heap 0) + ASSERT — size 출력

  GNU Arm Embedded Toolchain (arm-none-eabi-gcc) 가 PATH 또는 HTS_ARM_GNU_BIN 에 있어야 함.
#>
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

function Find-ArmGcc {
    $envDir = $env:HTS_ARM_GNU_BIN
    if ($envDir) {
        $p = Join-Path $envDir "arm-none-eabi-gcc.exe"
        if (Test-Path -LiteralPath $p) { return $p }
        $p = Join-Path $envDir "arm-none-eabi-gcc"
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $cmd = Get-Command "arm-none-eabi-gcc.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command "arm-none-eabi-gcc" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$gcc = Find-ArmGcc
if (-not $gcc) {
    Write-Host "[Verify_Target_CrossCompile] FAIL: arm-none-eabi-gcc not found."
    Write-Host "  Install GNU Arm Embedded Toolchain and add to PATH, or set HTS_ARM_GNU_BIN to its bin folder."
    exit 2
}

$binDir = Split-Path -Parent $gcc
$prefix = Join-Path $binDir "arm-none-eabi-"
$objdump = "${prefix}objdump.exe"
if (-not (Test-Path $objdump)) { $objdump = "${prefix}objdump" }
$size = "${prefix}size.exe"
if (-not (Test-Path $size)) { $size = "${prefix}size" }

$elf = Join-Path $Root "cross_verify.elf"
$map = Join-Path $Root "cross_verify.map"
$lst = Join-Path $Root "cross_verify.lst"

$cflags = @(
    "-std=c11", "-mthumb", "-mcpu=cortex-m4", "-mfpu=fpv4-sp-d16", "-mfloat-abi=hard",
    "-ffreestanding", "-Wall", "-Wextra", "-Werror", "-Wcast-align", "-Wpadded",
    "-Wconversion", "-Wsign-conversion",
    "-ffunction-sections", "-fdata-sections", "-fno-common"
)

Write-Host "Using GCC: $gcc"
Write-Host "==== compile crt0.c ===="
& $gcc @cflags "-c" (Join-Path $Root "crt0.c") "-o" (Join-Path $Root "crt0.o")
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Host "==== compile cross_smoke.c ===="
& $gcc @cflags "-c" (Join-Path $Root "cross_smoke.c") "-o" (Join-Path $Root "cross_smoke.o")
if ($LASTEXITCODE -ne 0) { exit 1 }

$ldflags = @(
    "-o", $elf,
    (Join-Path $Root "crt0.o"),
    (Join-Path $Root "cross_smoke.o"),
    "-T", (Join-Path $Root "stm32f4_verify.ld"),
    "-nostdlib", "-lgcc",
    "-Wl,--gc-sections", "-Wl,-Map=$map"
) + $cflags

Write-Host "==== link cross_verify.elf ===="
& $gcc @ldflags
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "==== arm-none-eabi-size ===="
& $size $elf
if ($LASTEXITCODE -ne 0) { exit 1 }
Write-Host "==== arm-none-eabi-size -A -d (excerpt) ===="
& $size "-A" "-d" $elf | Select-Object -First 40

Write-Host "==== objdump (intrinsic / barrier scan) ===="
& $objdump "-d" $elf | Out-File -FilePath $lst -Encoding ascii
$text = Get-Content -Path $lst -Raw
$patterns = @("dsb", "dmb", "isb", "wfi", "rev")
foreach ($pat in $patterns) {
    if ($text -notmatch $pat) {
        Write-Host "[Verify_Target_CrossCompile] FAIL: disassembly missing pattern '$pat' (see $lst)"
        exit 3
    }
}
Write-Host "ASM patterns OK: $($patterns -join ', ')"

# 장벽3: 링크 성공 시 ld ASSERT로 Flash/RAM/heap=0 이미 검증됨. 수치 상한 이중 확인.
$sizeLine = (& $size $elf | Select-Object -Last 1)
if ($sizeLine -match '\s+(\d+)\s+(\d+)\s+(\d+)') {
    $textB = [int64]$Matches[1]
    $dataB = [int64]$Matches[2]
    $bssB = [int64]$Matches[3]
    $flashUsed = $textB + $dataB
    $ramUsed = $dataB + $bssB + 0x800  # ld 예약 스택
    $flashLim = 512 * 1024
    $ramLim = 128 * 1024
    if ($flashUsed -gt $flashLim) {
        Write-Host "FAIL: Flash used $flashUsed > limit $flashLim"
        exit 4
    }
    if ($ramUsed -gt $ramLim) {
        Write-Host "FAIL: RAM used (data+bss+stack) $ramUsed > limit $ramLim"
        exit 5
    }
    Write-Host "Barrier3 check: flash_used=$flashUsed / $flashLim , ram_est=$ramUsed / $ramLim — OK"
}

Write-Host "[Verify_Target_CrossCompile] PASS"
exit 0
