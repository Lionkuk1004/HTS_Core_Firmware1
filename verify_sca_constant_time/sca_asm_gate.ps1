param(
    [Parameter(Mandatory = $false)]
    [string]$CodPath = ""
)
if ($CodPath -eq "" -or -not (Test-Path -LiteralPath $CodPath)) {
    Write-Host "SCA_ASM: listing not found (skip): $CodPath"
    exit 0
}
$raw = Get-Content -LiteralPath $CodPath -Raw
$sym = "sca_extern_ct_xor32"
$p0 = $raw.IndexOf("$sym PROC")
$p1 = $raw.IndexOf("$sym ENDP")
if ($p0 -lt 0 -or $p1 -lt 0 -or $p1 -le $p0) {
    Write-Host "SCA_ASM: FAIL — $sym PROC/ENDP not found in $CodPath"
    exit 1
}
$chunk = $raw.Substring($p0, $p1 - $p0 + 32)
# 조건부 점프(데이터 의존 분기 의심) — 루프 벡터화/조기종료 색출
$pat = '(?im)^\s*(je|jne|jz|jnz|jb|jbe|ja|jae)\s+'
$n = ([regex]::Matches($chunk, $pat)).Count
$cap = 8
if ($n -gt $cap) {
    Write-Host "SCA_ASM: FAIL — $sym conditional branches count=$n (cap $cap)"
    exit 1
}
Write-Host "SCA_ASM: PASS — $sym conditional branches count=$n (cap $cap)"
exit 0
