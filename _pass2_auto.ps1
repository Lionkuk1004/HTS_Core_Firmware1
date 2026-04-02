$root='D:/HTS_ARM11_Firmware/HTS_LIM/HTS_LIM'
$logCsv='D:/HTS_ARM11_Firmware/HTS_LIM/HTS_전수검사_로그_v5_auto.csv'
$reportOut='D:/HTS_ARM11_Firmware/HTS_LIM/HTS_전수검사_2차패스_보고서_v5_auto.md'
$skip=@('HTS_3D_Tensor_FEC.h','HTS_3D_Tensor_FEC.cpp','HTS_Server_Stress_Test.h')
$files=Get-ChildItem -Path $root -Recurse -File | ? { $_.Extension -in '.cpp','.h','.hpp' -and ($skip -notcontains $_.Name)}
$bugRemovedTotal=0; $additionalFixes=0
$fixList=New-Object System.Collections.Generic.List[object]
$reviewList=New-Object System.Collections.Generic.List[object]
$nvicList=New-Object System.Collections.Generic.List[object]
$guide=[string]::Join("
",@('// ─────────────────────────────────────────────────────────','//  외주 업체 통합 가이드','// ─────────────────────────────────────────────────────────','//  [사용법] 기본 사용 예시를 여기에 기재하세요.','//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.','//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).','//','//  ⚠ [파트너사 필수 확인]','//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.','//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.','// ─────────────────────────────────────────────────────────',''))
$likely=[string]::Join("
",@('#if __cplusplus >= 202002L || \\','    (defined(_MSVC_LANG) && _MSVC_LANG >= 202002L)','#define HTS_LIKELY   [[likely]]','#define HTS_UNLIKELY [[unlikely]]','#else','#define HTS_LIKELY','#define HTS_UNLIKELY','#endif',''))

foreach($f in $files){
 $p=$f.FullName; $text=Get-Content -Raw -Path $p -Encoding UTF8; $orig=$text; $changed=$false
 $lines=$text -split "?
",0,'SimpleMatch'; $out=New-Object System.Collections.Generic.List[string]; $removed=0; $block=$false
 foreach($ln in $lines){
  if($block){ if($ln -match '^\s*//\s*=+' -or $ln -match '^\s*$'){$block=$false;$removed++;continue}; if($ln -match '^\s*//'){$removed++;continue}; $block=$false }
  if($ln -match '^\s*//\s*\[양산 수정\s*—'){$block=$true;$removed++;continue}
  if($ln -match '^\s*//\s*(BUG-|BUG-FIX|BUG-AIRCR|BUG-NVIC|BUG-MPU)'){$removed++;continue}
  if($ln -match '^\s*//\s*\[(BUG-|FIX-|PENDING|요검토)'){$removed++;continue}
  if($ln -match '^\s*//\s*──\s*세션'){$removed++;continue}
  $out.Add($ln)|Out-Null
 }
 if($removed -gt 0){ $text=[string]::Join("
",$out); $bugRemovedTotal+=$removed; $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'BUG이력제거',"$removed줄 삭제"))|Out-Null }

 if($f.Extension -in '.h','.hpp' -and $text -notmatch '(?m)^\s*#pragma\s+once\s*$'){ $text="#pragma once
"+$text; $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'HDR-1','#pragma once 추가'))|Out-Null }
 $b=$text; $text=$text -replace '__asm__\s+__volatile__\(""\s*:\s*:\s*"r"\(([^\)]+)\)\s*\);','__asm__ __volatile__("" : : "r"() : "memory");'; if($text -ne $b){ $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'X-5-1','asm memory clobber 추가'))|Out-Null }
 $b=$text; $text=[regex]::Replace($text,'\bNULL\b','nullptr'); if($text -ne $b){ $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'M-9','NULL -> nullptr'))|Out-Null }
 if($text -match '\[\[(likely|unlikely)\]\]'){
  if($text -notmatch '(?m)^\s*#define\s+HTS_LIKELY'){ if($text -match '(?m)^\s*#pragma\s+once\s*$'){ $text=[regex]::Replace($text,'(?m)^\s*#pragma\s+once\s*$',"#pragma once
$likely",1)} else {$text=$likely+$text}; $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'U-D','likely 매크로 가드 추가'))|Out-Null }
  $b=$text; $text=$text -replace '\[\[likely\]\]','HTS_LIKELY'; $text=$text -replace '\[\[unlikely\]\]','HTS_UNLIKELY'; if($text -ne $b){ $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'U-D','raw likely/unlikely 치환'))|Out-Null }
 }
 if($f.Extension -in '.h','.hpp' -and $text -notmatch '외주 업체 통합 가이드' -and $text -notmatch '외부업체'){
  if($text -match '(?m)^\s*#pragma\s+once\s*$'){ $text=[regex]::Replace($text,'(?m)^\s*#pragma\s+once\s*$',"#pragma once
$guide",1)} else { $text=$guide+$text }
  $additionalFixes++; $changed=$true; $fixList.Add(@($f.Name,'EXT-1','외주 업체 통합 가이드 삽입'))|Out-Null
 }
 if($text -match 'NVIC_SetPriority\s*\(' -or $text -match 'IRQn_Type'){ $nvicList.Add(@($f.Name,'플레이스홀더','RM0090 기준 실제 보드값 교체'))|Out-Null }
 if($changed -and $text -ne $orig){ [System.IO.File]::WriteAllText($p,$text,[System.Text.UTF8Encoding]::new($false)) }
}
if(Test-Path $logCsv){ $rows=Import-Csv -Path $logCsv; foreach($r in $rows){ if($r.결과 -eq '[요검토]'){ $reviewList.Add(@($r.파일명,$r.항목,$r.처리,'수동 검토 필요'))|Out-Null } } }
$rp=New-Object System.Collections.Generic.List[string]
$rp.Add('2차 패스 최종 보고서:')|Out-Null
$rp.Add("총 BUG 이력 제거: $bugRemovedTotal줄")|Out-Null
$rp.Add("총 추가 자동 수정: $additionalFixes건")|Out-Null
$rp.Add("최종 [요검토] 잔여: $($reviewList.Count)건")|Out-Null
$rp.Add('')|Out-Null; $rp.Add('[추가 수정 목록]')|Out-Null; foreach($x in $fixList){ $rp.Add("$($x[0]) | $($x[1]) | $($x[2])")|Out-Null }
$rp.Add('')|Out-Null; $rp.Add('[최종 요검토 잔여 목록]')|Out-Null; foreach($y in $reviewList){ $rp.Add("$($y[0]) | $($y[1]) | $($y[2]) | $($y[3])")|Out-Null }
$rp.Add('')|Out-Null; $rp.Add('[NVIC/IRQ 교체 필요]')|Out-Null; foreach($n in ($nvicList | Sort-Object -Unique)){ $rp.Add("$($n[0]) | $($n[1]) | $($n[2])")|Out-Null }
[System.IO.File]::WriteAllLines($reportOut,$rp,[System.Text.UTF8Encoding]::new($false))
Write-Output "BUGREM=$bugRemovedTotal FIX=$additionalFixes REVIEW=$($reviewList.Count)"
Write-Output $reportOut
