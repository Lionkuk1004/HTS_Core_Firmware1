# HTS B-CDMA 전수검사 통합 기준서
**INNOViD CORE-X Pro HTS B-CDMA 보안통신 펌웨어**
**버전 5.0 — 2026.04 (완전판 — 자동 실행 통합)**

---

## 0. 타겟 플랫폼 스펙

### 0-1. B-CDMA 보안 코프로세서 (메인 타겟 — 임베디드 전용)

| 항목 | 사양 |
|------|------|
| MCU | STM32F407VGT6 |
| 코어 | ARM Cortex-M4F (하드웨어 FPU) |
| 클럭 | 168 MHz (max), AHB=168MHz, APB1=42MHz, APB2=84MHz |
| Flash | 1 MB (단일 뱅크, 섹터 0~11) |
| SRAM | 192 KB (112KB 메인 + 16KB SRAM2 + 64KB CCM) |
| CCM | 64 KB (Core Coupled Memory, DMA 접근 불가, HARQ 버퍼 전용) |
| FPU | 단정밀도 FPU (float 하드웨어, double 소프트웨어 에뮬) |
| MPU | 8개 리전 (코드 실행 보호, 스택 가드, DMA 분리) |
| NVIC | 82 인터럽트, 16단계 우선순위 (4비트 프리엠션) |
| DMA | DMA1(8ch) + DMA2(8ch), 이중 버퍼 모드 |
| 암호 | 소프트웨어 KCMVP(ARIA/LEA/LSH) + FIPS 140-3(AES-256/SHA-256) |
| 버스 | AHB1(GPIO/DMA), AHB2(USB OTG), APB1(SPI2/3, UART4/5), APB2(SPI1, USART1/6) |
| 패키지 | LQFP-100 |
| 전압 | 1.8~3.6V (PVD 감시) |
| 온도 | -40~85°C (산업용) |

### 0-2. 유무선 변환 프로세서 (보조 — 검수 대상 아님)

| 항목 | 사양 |
|------|------|
| SoC | Cortex-A55 Linux |
| 역할 | 유선↔무선 변환, 기본 보안 (TLS) |
| IPC | SPI(최대 42Mbps) + UART(115200bps) 이중 채널 |

### 0-3. SRAM 메모리 맵 (확정)

| 영역 | 주소 | 크기 | 용도 |
|------|------|------|------|
| SRAM 메인 | 0x2000_0000 | 112 KB | 코드 + BSS + 스택 + 오버레이 풀 |
| SRAM2 | 0x2001_C000 | 16 KB | ISR 스택 + 보안 버퍼 |
| CCM | 0x1000_0000 | 64 KB | HARQ 버퍼 (DMA 접근 불가) |
| 오버레이 풀 | SRAM 내 | ~80 KB | 시분할 모듈 로딩 |

### 0-4. 빌드 구성

| 프리셋 | 암호 알고리즘 | 대상 |
|--------|--------------|------|
| HTS_CRYPTO_KCMVP | ARIA/LEA/LSH256/HMAC | 국내 (NIS/KT) |
| HTS_CRYPTO_FIPS | AES-256/SHA-256 | 국제 수출 |
| HTS_CRYPTO_DUAL | 양쪽 모두 | 이중 인증 |

### 0-5. Cortex-M4 하드웨어 제약 (검수 시 필수 고려)

| 제약 | 상세 | 검수 영향 |
|------|------|-----------|
| 비정렬 접근 | LDM/STM/LDRD → UsageFault | alignas 강제 |
| 64비트 원자성 없음 | atomic<uint64_t> → tearing | PRIMASK 크리티컬 섹션 |
| 소프트웨어 나눗셈 | 64비트 → __aeabi_uldivmod(~200cyc) | 시프트+마스크 대체 |
| 32비트 UDIV | 하드웨어 지원 (2~12cyc) | 허용 |
| FPU 단정밀도 | double → 소프트웨어 에뮬(~100cyc) | double 전면 금지 |
| 스택 크기 | MSP 2~4KB 일반 | 대형 로컬 배열 금지 |
| Flash 대기 | 5 Wait State @168MHz | constexpr 최소화 |
| ISR 지연 | 12~16사이클 진입 | ISR 내 긴 로직 금지 |

---

## 1. 자동 검수 실행 규칙

### 1-1. 실행 원칙

- 사람 개입 없이 Layer 0 → Layer 17 자동 순차 처리 (Layer 18 제외)
- 모든 결과는 로그에 누적 기록, 완료 후 최종 보고서 1회 출력
- 멈추지 말고 다음 파일로 자동 진행
- 최종 보고서의 [요검토] 목록만 사람이 확인

### 1-2. 자동 수정 허용 조건 (5가지 모두 충족 시에만 수정)

```
조건 1. 본 기준서에 해당 항목이 명시되어 있을 것
조건 2. 함수 시그니처 / 파라미터 타입 / 반환 타입을 변경하지 않을 것
조건 3. 알고리즘 본문 / 수식 / 상수값을 변경하지 않을 것
조건 4. 파이프라인 호출 순서를 변경하지 않을 것
조건 5. 수정 결과에 100% 확신이 있을 것
```

→ 하나라도 불충족 시: [요검토] 태그 기록 후 자동 진행

### 1-3. 절대 금지 (자동 처리 중 어떤 상황에서도)

```
- 본 기준서 근거 없는 수정
- 함수 시그니처 / 반환 타입 변경
- 알고리즘 본문 / 수식 / 상수값 임의 변경
- 파이프라인 호출 순서 변경
- 계층 순서 임의 변경
- NVIC IRQ 번호 임의 확정 (플레이스홀더 + 경고 주석만)
- Secure_Wipe 3중 방어 패턴 임의 변경
- AIRCR → DBGMCU → dsb/isb → for(;;) 순서 변경
- 확신 없는 항목 수정 → [요검토] 기록 후 자동 진행
```

---

## 2. PC 전용 코드 제외 규칙 (임베디드 ARM 전용 검수)

### 2-1. 파일 전체 SKIP — 열지도 말고 다음 파일로 자동 진행

```
[Layer 9]
  HTS_3D_Tensor_FEC.h / HTS_3D_Tensor_FEC.cpp
  → 파일 상단 ARM 빌드 시 #error 명시된 PC 전용 파일
  → Dual_Tensor_16bit의 PENDING 의존 항목 → N/A 처리

[Layer 18 — 테스트 파일 전체 제외]
  HTS_HMAC_Bridge_Test.cpp
  HTS_Adaptive_BPS_Test.cpp
  AJC_TEST.cpp
  AMI_종합_TEST.cpp
  HTS_AMI_Measurement_Test.cpp
  HTS_AMI_Industrial_Field_Stress_Test.cpp
  HTS_AMI_Realistic_Integration_Test.cpp
  재밍_종합_테스트.cpp
  재밍_이엠피테스트_16칩.cpp
  재임_이엠피_테스트_16칩_종합.cpp
  재밍테스트_노드2048_16칩_64칩.cpp
  홀로그램_4D_4096_TEST.cpp
  HTS_Server_Stress_Test.h
```

### 2-2. 코드 블록 SKIP — 파일은 검수하되 해당 구간 N/A 처리

```
패턴 1: #else 블록 (ARM 가드의 반대편)
  #if defined(__arm__) || defined(__TARGET_ARCH_ARM) || ...
      [ARM 코드 — 검사 대상]
  #else
      [PC 코드 — N/A]  ← 이 구간 건드리지 않음
  #endif

패턴 2: PC 전용 명시 가드
  #if !defined(__arm__) && !defined(__TARGET_ARCH_ARM) && ...
      [PC 코드 — N/A]  ← 이 구간

패턴 3: _HTS_CREATOR_MODE 블록
  #ifdef _HTS_CREATOR_MODE
      [개발자 전용 — N/A]  ← 이 구간
  #endif
```

### 2-3. ARM에서 제외되는 검사 항목 (N/A 처리)

```
N-2.  Mutex/Lock (PC용)
N-8.  조건 변수 (PC용)
N-9.  비동기 처리 (PC용)
N-12. 스레드 종료 Join/Detach (PC용)
N-13. shared_ptr 멀티스레드 안전 (PC용)
N-15. thread_local (PC용)
O-14. 경로 조작 방지 (파일시스템 없음)
O-15. 파일 크기/형식 검증 (파일시스템 없음)
```

### 2-4. 실제 검수 파일 수

```
전체 파일:    211개
PC 전용 제외:  -14개
실제 검수:    약 197개
```

---

## 3. 작업 계층 순서 (파이프라인 의존성 기반)

```
Layer 0  — 플랫폼 기반 [최우선]
  HTS_Types.h / HTS_BitOps.h / HTS_PHY_Config.h
  common.h / config.h / util.h / arm_arch.h

Layer 1  — 하드웨어 초기화
  HTS_Hardware_Init.h → .cpp
  HTS_Hardware_Bridge.hpp → .cpp
  HTS_Hardware_Auto_Scaler.h → .cpp
  HTS_Hardware_Shield.h → .cpp
  HTS_POST_Manager.h → .cpp
  HTS_Power_Manager.h → .cpp

Layer 2  — 보안 메모리 / 소거 [모든 보안 모듈 기반]
  HTS_Secure_Memory.h → .cpp
  HTS_Secure_Memory_Manager.hpp
  HTS_ConstantTimeUtil.h → .cpp
  HTS_Crc32Util.h → .cpp

Layer 3  — KCMVP/FIPS 암호 엔진
  lea.h 계열 전체 / lsh.h 계열 전체
  hmac.h / KISA_SHA256.h / KISA_HMAC.h
  HTS_ARIA_Bridge.hpp → .cpp
  HTS_LEA_Bridge.h → .cpp
  HTS_LSH256_Bridge.h → .cpp
  HTS_AES_Bridge.h → .cpp
  HTS_SHA256_Bridge.h → .cpp
  HTS_HMAC_Bridge.hpp → .cpp
  HTS_CTR_DRBG.h → .cpp
  HTS_TRNG_Collector.h → .cpp
  HTS_Physical_Entropy_Engine.h → .cpp
  HTS_Entropy_Monitor.h → .cpp

Layer 4  — KAT 검증
  HTS_Crypto_KAT.h → .cpp
  HTS_ARIA_KCMVP_KAT.cpp / HTS_LEA_KCMVP_KAT.cpp
  HTS_LSH256_KCMVP_KAT.cpp / HTS_HMAC_KCMVP_KAT.cpp
  HTS_Conditional_SelfTest.h → .cpp

Layer 5  — 키 관리 / 보안 부팅
  HTS_Key_Provisioning.h → .cpp
  HTS_Key_Rotator.h → .cpp
  HTS_Dynamic_Key_Rotator.hpp → .cpp
  HTS_PUF_Adapter.h → .cpp
  HTS_Secure_Boot_Verify.h → .cpp
  HTS_Anchor_Vault.hpp → .cpp
  HTS_Entropy_Arrow.hpp → .cpp

Layer 6  — 안티디버그 / 물리 보안
  HTS_Anti_Debug.h → .cpp
  HTS_Anti_Glitch.h → .cpp
  HTS_Tamper_HAL.h → .cpp
  HTS_AntiAnalysis_Shield.h → .cpp
  HTS_Polymorphic_Shield.h → .cpp
  HTS_Pointer_Auth.hpp → .cpp
  HTS_Auto_Rollback_Manager.hpp → .cpp

Layer 7  — 로깅 / 설정 / 프로파일
  HTS_Secure_Logger.h → .cpp
  HTS_Config.h → .cpp
  HTS_Dynamic_Config.h → .cpp
  HTS_Device_Profile.h → .cpp
  HTS_Device_Status_Reporter.h → .cpp
  HTS_Creator_Telemetry.h → .cpp

Layer 8  — DSP/PHY 코어
  HTS_Gaussian_Pulse.h → .cpp
  HTS_Rx_Matched_Filter.h → .cpp
  HTS_Rx_Sync_Detector.h → .cpp
  HTS_Antipodal_Core.h → .cpp
  HTS_Adaptive_BPS_Controller.h → .cpp
  AnchorEncoder.h → .cpp
  AnchorDecoder.h → .cpp
  AnchorManager.h → .cpp
  TensorCodec.hpp → .cpp
  HTS_Orbital_Mapper.hpp → .cpp
  HTS_Sparse_Recovery.h → .cpp

Layer 9  — 텐서 엔진 [핵심 알고리즘]
  HTS_Holo_Tensor_Engine.h → .cpp
  HTS_Holo_Tensor_4D.h → .cpp
  HTS_Dual_Tensor_16bit.h → .cpp
  HTS_3D_Tensor_FEC.h / .cpp  ← SKIP (PC 전용)

Layer 10 — FEC/HARQ
  HTS_FEC_HARQ.hpp → .cpp
  HTS_Tx_Scheduler.hpp → .cpp
  BB1_Core_Engine.hpp → .cpp
  HTS64_Native_ECCM_Core.hpp → .cpp

Layer 11 — 디스패처
  HTS_Holo_Dispatcher.h → .cpp
  HTS_V400_Dispatcher.hpp → .cpp

Layer 12 — 보안 파이프라인 / 세션
  HTS_AEAD_Integrity.hpp
  HTS_Security_Pipeline.h → .cpp
  HTS_Security_Session.h → .cpp
  HTS_Session_Gateway.hpp → .cpp
  HTS_Remote_Attestation.hpp → .cpp
  HTS_Role_Auth.h → .cpp

Layer 13 — 스토리지
  HTS_Storage_Interface.h → .cpp
  HTS_Storage_Adapter.hpp

Layer 14 — 통신 프로토콜
  HTS_IPC_Protocol.h → .cpp
  HTS_IPC_Protocol_A55.h → .cpp
  HTS_Network_Bridge.h → .cpp
  HTS_KT_DSN_Adapter.h → .cpp
  HTS_CoAP_Engine.h → .cpp
  HTS_Mesh_Router.h → .cpp
  HTS_Mesh_Sync.h → .cpp
  HTS_Neighbor_Discovery.h → .cpp
  HTS_Universal_Adapter.h / .hpp → .cpp

Layer 15 — AMI / OTA
  HTS_AMI_Protocol.h → .cpp
  HTS_OTA_AMI_Manager.h → .cpp
  HTS_OTA_Manager.h → .cpp
  HTS_Meter_Data_Manager.h → .cpp
  HTS_Modbus_Gateway.h → .cpp
  HTS_BLE_NFC_Gateway.h → .cpp

Layer 16 — IoT / 센서 / 비상
  HTS_IoT_Codec.h → .cpp
  HTS_Sensor_Aggregator.h → .cpp
  HTS_Sensor_Fusion.h → .cpp
  HTS_Gyro_Engine.h → .cpp
  HTS_Location_Engine.h → .cpp
  HTS_Emergency_Beacon.h → .cpp
  HTS_CCTV_Security.h → .cpp

Layer 17 — 스케줄러 / 최상위 API
  HTS_Priority_Scheduler.h → .cpp
  HTS_Unified_Scheduler.hpp → .cpp
  HTS_Console_Manager.h → .cpp
  HTS_Universal_API.h / .hpp → .cpp
  HTS_API.h → .cpp

Layer 18 — 테스트 [전체 SKIP — PC 전용]
```

---

## 4. 파일당 처리 절차

```
[Step 1] 파일 전체 읽기
[Step 2] 섹션 5 검사 항목을 번호 순서대로 적용
          PASS → 다음 항목 자동 진행
          FAIL → 자동 수정 조건 5가지 확인
                 충족 → 수정 후 로그 기록
                 불충족 → [요검토] 로그 기록
          N/A  → PC 전용 / 해당 없음
[Step 3] 섹션 6 BUG 이력 주석 제거
[Step 4] 로그 기록
[Step 5] 다음 파일 자동 시작 (멈추지 않음)
```

---

## 5. 전체 검사 항목 281개

### [필수 17항] ①~⑰

**① memory_order 배리어**
```
- seq_cst 사용 위치 전수 확인
- 생산자-소비자: acquire/release 쌍 일치
- 독립 카운터: relaxed 사용
- DMA/ISR 공유 영역: atomic_thread_fence + volatile 병행
FAIL: seq_cst가 불필요한 경로에 사용됨
수정: release/acquire/relaxed 다운그레이드
금지: 보안 소거 fence 변경 금지
```

**② std::abs → fast_abs**
```
- ARM 경로 std::abs(int32_t) → float 오버로드 위험
FAIL: ARM 경로에서 std::abs 사용
수정: 프로젝트 내 fast_abs 함수로 교체
```

**③ 힙 할당 금지 (ARM 경로)**
```
- new / malloc / shared_ptr / unique_ptr ARM 경로 잔존
- std::vector / std::string ARM 경로 잔존
FAIL: ARM 경로에 동적 할당 발견
수정: placement new + 정적 배열 전환
금지: PC 전용 #else 블록 수정 금지
```

**④ double/float 금지 (ARM 경로)**
```
- ARM 경로 double 연산 실제 실행 여부
- 파라미터 double → 진입 즉시 float 변환 여부 확인
FAIL: ARM 경로에서 double 연산 실행
수정: static_cast<float> 또는 Q16 정수 전환
금지: 알고리즘 수식·계수 변경 금지
```

**⑤ try-catch 금지 (-fno-exceptions)**
```
- try / catch / throw ARM 또는 전역 경로 잔존
FAIL: 발견 시
수정: 블록 제거, 반환값 기반 처리
금지: 제거 후 빈 함수 → [요검토] 표시
```

**⑥ 스택 사용량**
```
- 로컬 배열 512B 초과 여부
- 재귀 호출 여부
FAIL: 512B 초과 또는 재귀 발견
수정: static/전역 버퍼로 이동
금지: 인덱스·크기 변경 금지
```

**⑦ 주석-코드 불일치**
```
- 파일 상단 BUG 수정 이력과 실제 코드 일치
FAIL: 주석은 수정됐다고 하는데 코드에 미반영
수정: 주석을 코드에 맞게 수정
금지: 코드를 주석에 맞게 변경 금지
```

**⑧ SRAM static_assert**
```
- sizeof(Impl) <= IMPL_BUF_SIZE 검증 존재
- alignof(Impl) <= IMPL_BUF_ALIGN 검증 존재
FAIL: Pimpl 구조체에 static_assert 없음
수정: static_assert 삽입
금지: IMPL_BUF_SIZE 값 변경 금지
```

**⑨ 나눗셈 → 시프트 전환**
```
- 2의 거듭제곱: / → >> 또는 & (mask)
- 비2의제곱: Q16 역수 곱셈+시프트 또는 불가피 주석
- constexpr 나눗셈: 허용
- HW 레지스터 주소 상수: 허용
- 32비트 UDIV: 허용
- Fisher-Yates 등 불가피 경우: 주석 명시
FAIL: 런타임 루프 내 가변 분모 64비트 나눗셈 (불가피 주석 없음)
수정: >> 또는 & 전환, 불가피 주석 추가
```

**⑩ const& + zero-copy**
```
- 64B 초과 구조체를 값으로 전달
FAIL: 대형 구조체 값 전달 발견
수정: const& 추가
금지: 반환 타입·의미 변경 금지
```

**⑪ 엔디안 독립**
```
- 멀티바이트 직렬화 시 포인터 캐스팅 사용
FAIL: reinterpret_cast로 구조체→바이트 배열 직접 캐스팅
수정: 명시적 비트 시프트 직렬화로 교체
```

**⑫ static_cast (암묵적 형변환 금지)**
```
- C스타일 캐스팅 (type)value 사용
- dynamic_cast / typeid 사용
- 암묵적 정수 축소 변환
FAIL: 위 항목 발견
수정: static_cast 명시
금지: 변환 의미 자체 변경 금지
```

**⑬ CFI 상태전이 검증**
```
- 상태 머신 전이 시 이전 상태 유효성 검증 여부
- 불법 전이 시 ERROR_RECOVERY 전환
FAIL: 상태 전이에 검증 없음
수정: 검증 조건 추가
금지: 상태 정의·전이 로직 변경 금지
```

**⑭ PC 코드 삭제**
```
- <iostream>/<cstdlib>/<windows.h>/<unistd.h>/std::abort()
  ARM 경로 물리 배제 여부
- <thread>/<mutex>/<condition_variable>/<future>
  ARM 경로 발견 즉시 FAIL
FAIL: ARM 빌드에서 위 헤더 컴파일됨
수정: #ifndef HTS_PLATFORM_ARM 가드 추가
금지: PC 경로 기능 삭제 금지
```

**⑮ HW 레지스터 폴링 타임아웃**
```
⚠ [외부업체 주의] SPI/UART/DMA 대기루프 무한 행업 위험
- while(flag) {} 무한 루프 여부
- 폴링 루프 상한 카운터 여부
FAIL: 폴링 루프에 탈출 조건 없음
수정: 타임아웃 카운터 추가 + 경고 주석 삽입:
// ⚠ [HW 주의] 이 폴링 루프는 실제 보드의 타임아웃 값으로 교체 필수.
//   플레이스홀더 값으로 양산 금지.
```

**⑯ 전원강하/EMI 비트플립 방어**
```
- PVD 연동 여부
- Flash 쓰기 원자성 (Read-Back 검증) 여부
FAIL: Flash 쓰기 후 검증 없음
수정: 위험 주석 명시
금지: Flash HAL 코드 변경 금지
```

**⑰ 하드 리얼타임 데드라인**
```
⚠ [외부업체 최우선 확인] NVIC 우선순위 미설정 시 타임슬롯 마감 실패
- NVIC 설정 위치 확인 (파일 전체 grep)
- ISR WCET 루프 상한 여부
FAIL: ISR 내 무제한 루프 또는 NVIC 설정 없음
수정: 루프 상한 추가 + 아래 경고 블록 삽입:
#ifdef HTS_TARGET_ARM_BAREMETAL
// ⚠══════════════════════════════════════════════════════
// [외부업체 필수 교체] IRQ 번호는 플레이스홀더입니다.
// 실제 보드 회로도 및 STM32F407 RM0090 벡터 테이블 확인 후 교체.
//
// RM0090 주요 IRQ 번호:
//   TIM2=28, TIM3=29, TIM4=30, TIM5=50
//   DMA1_Stream0=11 ~ DMA1_Stream7=47
//   DMA2_Stream0=56 ~ DMA2_Stream7=70
//   SPI1=35, SPI2=36, SPI3=51
//   USART1=37, USART2=38, USART3=39
//
// ※ IPC_Protocol이 DMA2_Stream0(56번)을 SPI1 RX로 사용 중.
//   Tx 스케줄러 DMA는 반드시 다른 Stream 번호로 설정하세요.
// ⚠══════════════════════════════════════════════════════
NVIC_SetPriority(static_cast<IRQn_Type>(28), 2u); // 교체 필요
NVIC_SetPriority(static_cast<IRQn_Type>(59), 3u); // 교체 필요
#endif
```

---

### [보충 4항] A~D

**A. sizeof 전파 경고**
```
- 1KB 이상 멤버 포함 클래스: Doxygen @warning에 sizeof 근사값 명시
- @warning에 "전역/정적 배치 필수" 문구 포함
- 연쇄 래퍼(A→B→C): 최상위에도 누적 sizeof 경고
FAIL: 대형 멤버 포함 클래스에 @warning 없음
수정: @warning 추가
예시:
/// @warning sizeof(HTS_Xxx) ≈ NKB (YYY impl_buf_ 내장)
///          반드시 전역/정적 변수로 배치. 스택 선언 시 Cortex-M4 즉시 오버플로우.
```

**B. 래퍼 클래스 static_assert**
```
- 1KB 이상 멤버 포함 클래스: sizeof <= SRAM예산 검증
- static_assert 위에 SRAM 예산 산출 근거 주석
- 메시지에 어떤 멤버를 줄여야 하는지 가이드
FAIL: static_assert 없음
수정: static_assert 삽입
```

**C. 원자적 초기화 CAS**
```
- atomic<bool> 1회성 가드: compare_exchange_strong(expected=false, true, acq_rel)
- load→if(false)→store(true) 패턴 → FAIL
- CAS 실패 시 즉시 반환
FAIL: 비CAS 패턴 사용
수정: compare_exchange_strong 전환
```

**D. C++20 속성 가드 매크로**
```
- [[likely]]/[[unlikely]]: #if __cplusplus >= 202002L 가드
- 프로젝트 전체 동일 매크로 (HTS_LIKELY/HTS_UNLIKELY)
- [[nodiscard]]: C++17 이상이면 가드 불필요
FAIL: raw [[likely]] 직접 사용
수정: 가드 매크로 추가
```

---

### [A항] 동시성 및 메모리 배리어

| No | 항목 | 기준 |
|----|------|------|
| A-1 | seq_cst 다운그레이드 | relaxed/acquire/release 최적화 |
| A-2 | 컴파일러/CPU 재배치 방어 | DMA/ISR 공유 영역 → atomic_thread_fence + volatile |
| A-3 | Lock-free/Wait-free | ISR/실시간루프 → mutex/spinlock 배제, CAS 링 버퍼 |

---

### [B항] 메모리 및 리소스 무결성

| No | 항목 | 기준 |
|----|------|------|
| B-1 | Zero-Copy | const& 또는 포인터, 런타임 동적 할당 금지 |
| B-2 | 정렬(Alignment) | alignas 누락 → Unaligned Access Fault |
| B-3 | 스택 무결성 | 대형 로컬 배열 → static/전역, 재귀 배제 |

---

### [C항] 제어 흐름 무결성

| No | 항목 | 기준 |
|----|------|------|
| C-1 | CFI | 상태 머신 전이 합법성 검증 (ROP/JOP 방어) |
| C-2 | 예외 배제 | try-catch/throw 제거 |
| C-3 | HardFault 폴백 | 안전 핸들러, 레지스터 로깅 + 리셋 |

---

### [D항] 보안 및 안티포렌식

| No | 항목 | 기준 |
|----|------|------|
| D-1 | Constant-time | 암호 연산 내 if/switch 금지 → 비트마스크 |
| D-2 | 보안 소거 3중 방어 | volatile + asm clobber "memory" + release fence |
| D-3 | JTAG/SWD 감지 리셋 | AIRCR → DBGMCU → dsb/isb → for(;;) 순서 |

**D-2 표준 패턴 (이 패턴에서 1자도 변경 금지)**
```cpp
volatile uint8_t* q = static_cast<volatile uint8_t*>(p);
for (size_t i = 0u; i < n; ++i) { q[i] = 0u; }
__asm__ __volatile__("" : : "r"(p) : "memory");  // "memory" 필수
std::atomic_thread_fence(std::memory_order_release);
```

**D-3 AIRCR 리셋 순서 (순서 변경 금지)**
```
AIRCR 쓰기(0x05FA0004)
→ DBGMCU_APB1_FZ &= ~(WWDG_STOP(bit11) | IWDG_STOP(bit12))
→ dsb sy / isb
→ for(;;) { nop; }
```

---

### [E항] DSP 및 알고리즘 최적화

| No | 항목 | 기준 |
|----|------|------|
| E-1 | ALU 병목 제거 | 나눗셈/모듈로 → 시프트+비트마스크 (32비트 UDIV 허용) |
| E-2 | HW Intrinsics | __builtin_popcount, __clz 단일사이클 명령 |
| E-3 | 분기 예측 최적화 | Hot Path → HTS_LIKELY/HTS_UNLIKELY (C++20 가드) |

---

### [F항] 데이터 무결성 및 통신

| No | 항목 | 기준 |
|----|------|------|
| F-1 | 엔디안 독립 | 포인터 캐스팅 금지 → 명시적 비트 시프트 |
| F-2 | 오류 검출 | 통신 페이로드 + 설정값 → CRC-16/32 또는 해시 |

---

### [G항] 빌드 타임 검증

| No | 항목 | 기준 |
|----|------|------|
| G-1 | static_assert | 구조체 크기, 비트마스크, 배열 길이 빌드타임 검증 |
| G-2 | 엄격한 형변환 | 암묵적 캐스팅 금지 → static_cast 명시 |
| G-3 | 경고 에러화 | -Wall -Wextra -Werror (경고 0개) |

---

### [H항] 포인터 및 메모리 관리 (20항)

| No | 항목 |
|----|------|
| H-1 | NULL 포인터 역참조 방지 |
| H-2 | 댕글링 포인터 (해제 후 재참조) |
| H-3 | 버퍼 오버플로우 (memcpy/strcpy 경계) |
| H-4 | 동적 메모리 할당 제한 (malloc/free 금지) |
| H-5 | 정렬 위반 (Cortex-M4 Fault) |
| H-6 | new/malloc 후 delete/free 쌍 |
| H-7 | 메모리 누수 (모든 경로 해제) |
| H-8 | 더블 프리 방지 |
| H-9 | 스택 버퍼 오버플로우 (512B 초과 로컬) |
| H-10 | 힙 무결성 |
| H-11 | 초기화되지 않은 변수 |
| H-12 | strcpy/strcat 금지 → strncpy/snprintf |
| H-13 | sprintf 금지 → snprintf |
| H-14 | gets() 금지 → fgets() |
| H-15 | memcpy 크기 소스/타겟 일치 |
| H-16 | 포인터 연산 유효 범위 |
| H-17 | 상속 구조 가상 소멸자 |
| H-18 | 생성자/소멸자 내 가상 함수 호출 자제 |
| H-19 | 지역 변수 주소 반환 금지 |
| H-20 | ASan 설정 확인 |

---

### [I항] 제어 흐름 및 예외 처리

| No | 항목 |
|----|------|
| I-1 | ISR 내 긴 로직 금지 |
| I-2 | 무한 루프 탈출 조건 |
| I-3 | switch default 케이스 명시 |
| I-4 | 재귀 호출 금지 |

---

### [J항] 타입 안정성

| No | 항목 |
|----|------|
| J-1 | 형 변환 안전성 (큰→작은 데이터 유실) |
| J-2 | Unsigned 언더/오버플로우 |
| J-3 | 매직 넘버 금지 → constexpr/enum (SWAR/CRC/LCG/비트마스크 예외, HW 레지스터 주소 constexpr 상수화) |
| J-4 | volatile 올바른 사용 (동기화 목적 volatile 금지, atomic 사용) |

---

### [K항] Cortex-M4 전용

| No | 항목 |
|----|------|
| K-1 | MPU 설정 (Flash RO, 8개 리전, 스택 가드 256B, DMA Shared Device) |
| K-2 | DSP 명령어 데이터 범위 검사 |
| K-3 | FPU 레지스터 컨텍스트 저장 (ISR 진입 시) |

---

### [L항] 가독성 및 유지보수

| No | 항목 |
|----|------|
| L-1 | 함수 복잡도 (Cyclomatic Complexity ≤ 10 권장) |
| L-2 | 변수 초기화 (선언 시 즉시) |
| L-3 | 미사용 코드/변수 제거 |

---

### [M항] 정적 분석 및 표준 준수 (20항)

| No | 항목 |
|----|------|
| M-1 | Cppcheck 결함 탐지 |
| M-2 | Clang-tidy 모던 C++ |
| M-3 | -Wall -Wextra -Wpedantic |
| M-4 | -Werror (경고 0개) |
| M-5 | const/constexpr 상수화 |
| M-6 | enum class 명시적 타입 |
| M-7 | explicit 생성자 |
| M-8 | static_cast/reinterpret_cast (C스타일 금지) |
| M-9 | nullptr (NULL 금지) |
| M-10 | auto 남용 자제 |
| M-11 | 범위 기반 for 활용 |
| M-12 | std::move 적절한 활용 |
| M-13 | 템플릿 과용 자제 |
| M-14 | DRY 원칙 (중복 코드 제거) |
| M-15 | 데드 코드 제거 |
| M-16 | 함수 길이 적정 (100줄 초과 시 분할 권장) |
| M-17 | 주석-코드 일치 |
| M-18 | ProtectedEngine 네임스페이스 (전역 오염 방지) |
| M-19 | unsigned/signed 혼용 주의 |
| M-20 | placement new (베어메탈 Pimpl 표준) |

---

### [N항] 동시성 (15항 — ARM 해당 없는 항목 N/A)

| No | 항목 | ARM 적용 |
|----|------|---------|
| N-1 | 데이터 레이스 방어 | ✅ |
| N-2 | Mutex/Lock | N/A (PC용) |
| N-3 | 데드락 방지 (PRIMASK 크리티컬 섹션) | ✅ |
| N-4 | std::atomic 사용 | ✅ |
| N-5 | 공유 상태 최소화 | ✅ |
| N-6 | 스레드 비안전 함수 주의 | ✅ |
| N-7 | volatile 오용 금지 (atomic 사용) | ✅ |
| N-8 | 조건 변수 | N/A (PC용) |
| N-9 | 비동기 처리 | N/A (PC용) |
| N-10 | 락 범위 최소화 | ✅ |
| N-11 | 재진입성 (ISR 안전 설계) | ✅ |
| N-12 | 스레드 종료 Join/Detach | N/A (PC용) |
| N-13 | shared_ptr 멀티스레드 안전 | N/A (PC용) |
| N-14 | 예외 시 락 해제 (RAII) | ✅ |
| N-15 | thread_local | N/A (PC용) |

---

### [O항] 입력 검증 및 보안 (15항)

| No | 항목 | ARM 적용 |
|----|------|---------|
| O-1 | 입력 값 범위 검사 | ✅ |
| O-2 | 명령어 인젝션 방지 | ✅ |
| O-3 | 형식 문자열 취약점 | ✅ |
| O-4 | 버퍼 크기 검증 | ✅ |
| O-5 | NULL 바이트 삽입 방지 | ✅ |
| O-6 | UTF-8 인코딩 검증 | ✅ |
| O-7 | 화이트리스트 입력 | ✅ |
| O-8 | 오류 메시지 정보 노출 방지 | ✅ |
| O-9 | 평문 키/비밀번호 저장 금지 | ✅ |
| O-10 | 암호학적 난수 (PUF+PRNG) | ✅ |
| O-11 | 세션 관리 | ✅ |
| O-12 | 코드 주입 방지 | ✅ |
| O-13 | 인자 경계 검사 | ✅ |
| O-14 | 경로 조작 방지 | N/A (파일시스템 없음) |
| O-15 | 파일 크기/형식 검증 | N/A (파일시스템 없음) |

---

### [P항] 런타임 성능 (15항)

| No | 항목 |
|----|------|
| P-1 | assert (디버그 모드) |
| P-2 | RTTI 비용 (dynamic_cast 자제) |
| P-3 | noexcept 지정 |
| P-4 | 알고리즘 복잡도 (O(n²)+ 경보) |
| P-5 | 컨테이너 선택 (ARM: 정적 배열, std::vector 금지) |
| P-6 | 캐시 지역성 |
| P-7 | const T& 전달 |
| P-8 | RVO/NRVO 활성화 |
| P-9 | 임시 객체 최소화 |
| P-10 | 루프 불변식 외부 이동 |
| P-11 | 정적 라이브러리 불필요 링크 제거 |
| P-12 | 런타임 무결성 해시 체크 |
| P-13 | 예외 안전성 (RAII) |
| P-14 | 스트림 오버헤드 (ARM: std::cout/cin 금지) |
| P-15 | 핫 루프 최적화 |

---

### [Q항] 프로젝트 구조 (15항)

| No | 항목 |
|----|------|
| Q-1 | 헤더 가드 (#pragma once) |
| Q-2 | include 최소화 (삭제 금지, 추가만 허용) |
| Q-3 | 전방 선언 (Pimpl 은닉화) |
| Q-4 | Debug/Release 분리 |
| Q-5 | 코드 스타일 일관성 |
| Q-6 | Doxygen API 문서화 (공개 API 전체) |
| Q-7 | 외부 라이브러리 버전 고정 |
| Q-8 | ARM/PC 플랫폼 분리 (#ifdef __arm__ 3단 분기) |
| Q-9 | Self-Contained 헤더 |
| Q-10 | ProtectedEngine 네임스페이스 |
| Q-11 | 복사/이동 = delete (보안 객체) |
| Q-12 | [[nodiscard]] (반환값 무시 위험 함수) |
| Q-13 | constexpr 컴파일타임 상수화 |
| Q-14 | inline constexpr (ODR 준수) |
| Q-15 | static_assert 아키텍처 검증 |

---

### [R항] 보안 부팅 및 펌웨어 검증 (30항)

| No | 항목 |
|----|------|
| R-1 | 부트 코드 ROM 불변성 |
| R-2 | 펌웨어 디지털 서명 (RSA/ECC) |
| R-3 | SHA-256/SHA-3 해시 무결성 |
| R-4 | OTP 안전 부팅 설정 |
| R-5 | Anti-rollback |
| R-6 | 안전 키 저장소 |
| R-7 | 부트 영역 쓰기 보호 |
| R-8 | QSPI 외부 Flash 검증 |
| R-9 | Flash ECC 쓰기 확인 |
| R-10 | 설정값 CRC-32 |
| R-11 | MPU 보안 영역 분리 (8개 리전) |
| R-12 | 스택 Guard Value 감시 |
| R-13 | 힙 오버플로우 검출 |
| R-14 | Read-only 데이터 보호 |
| R-15 | 부팅 시 전체 CRC |
| R-16 | 런타임 코드 변경 감지 |
| R-17 | WDT — 메인 루프 최상단만 킥 |
| R-18 | 윈도우 워치독 (WWDG) |
| R-19 | HardFault → 레지스터 로깅 + 리셋 |
| R-20 | 클럭 감시 (CSS) |
| R-21 | 저전력 모드 상태 검사 |
| R-22 | JTAG/SWD 비활성화 |
| R-23 | 입력 경계 검사 |
| R-24 | 암호화 펌웨어 |
| R-25 | 코드 주입 방지 |
| R-26 | 보안 HW 가속기 활용 |
| R-27 | 서명 키 주기 변경 |
| R-28 | 동적 펌웨어 갱신 차단 |
| R-29 | Secure Boot State 확인 |
| R-30 | 무결성 실패 → 안전 모드 전환 |

---

### [U항] 구조적 안전성 (4항)

| No | 항목 | 기준 |
|----|------|------|
| U-A | sizeof 전파 경고 | 1KB+ 멤버 → @warning sizeof + "전역/정적 필수" |
| U-B | 래퍼 static_assert | sizeof≤SRAM예산 빌드타임 검증 |
| U-C | 원자적 초기화 CAS | compare_exchange_strong(acq_rel) |
| U-D | C++20 속성 가드 | [[likely]]/[[unlikely]] → `#if __cplusplus >= 202002L` |

---

### [V항] 모듈별 특수 취약점 (35항)

**V-1. BLE/NFC 게이트웨이 (10항)**

| No | 항목 |
|----|------|
| V-1-1 | AT TX 버퍼 독립 할당 |
| V-1-2 | 오버플로 라인 즉시 폐기 |
| V-1-3 | 인밴드 AT 인젝션 차단 |
| V-1-4 | 프레임 밀반입 차단 |
| V-1-5 | 세션 암살 방지 |
| V-1-6 | 64비트 국가지점번호 검증 |
| V-1-7 | msg_type 프로토콜 분기 |
| V-1-8 | Send_* 세션 게이트키퍼 |
| V-1-9 | 일괄 틱 갱신 철거 |
| V-1-10 | SPSC 링 버퍼 PRIMASK 보호 |

**V-2. CCTV 보안 (8항)**

| No | 항목 |
|----|------|
| V-2-1 | Event Storm DoS → Edge 트리거 |
| V-2-2 | 시계열 정합성 |
| V-2-3 | nullptr → detail_len=0 클램프 |
| V-2-4 | MAC 키 역산 방어 |
| V-2-5 | 1틱 격리 |
| V-2-6 | 틱 보상 폭주 방지 |
| V-2-7 | 무한 락다운 방지 |
| V-2-8 | OFFLINE 전이 합법화 |

**V-3. CoAP 엔진 (14항)**

| No | 항목 |
|----|------|
| V-3-1 | URI 버퍼 오버플로 → 클램프 |
| V-3-2 | 스택 평문 잔류 → Secure_Wipe |
| V-3-3 | next_mid/token → atomic |
| V-3-4 | TKL 미검증 → 즉각 폐기 |
| V-3-5 | Piggybacked Response 처리 |
| V-3-6 | 0xFF Payload Marker 삽입 |
| V-3-7 | 파서 스머글링 방어 |
| V-3-8 | safe_streq XOR 상수 시간 |
| V-3-9 | safe_shift 21 클램프 |
| V-3-10 | alloc_state 4단계 CAS |
| V-3-11 | ACK CAS(READY→WIPING) 독점 |
| V-3-12 | Enqueue → PRIMASK 외부 |
| V-3-13 | atomic 객체 Wipe UB 금지 |
| V-3-14 | Register URI 사전 소거 |

**V-4. 자가진단 + Config (3항)**

| No | 항목 |
|----|------|
| V-4-1 | alignas(uint32_t) LEA 버퍼 |
| V-4-2 | HMAC ctx 5경로 Wipe |
| V-4-3 | 곱셈(*) → 시프트(<<) |

---

### [W항] 수석 아키텍트 규약 (4항)

| No | 항목 | 기준 |
|----|------|------|
| W-1 | DMA 캐시 일관성 | D-Cache Invalidate/Clean 또는 Non-cacheable |
| W-2 | WDT 펫팅 제한 | ISR/데드락 루프 내 금지, 메인 루프 최상단만 |
| W-3 | Flash 마모 평준화 | NVRAM 링 버퍼 Wear-Leveling |
| W-4 | 인터럽트 폭주 차단 | ISR 내 디바운싱/일시적 마스킹 |

---

### [X항] 추가 정밀검사 (20항)

| No | 항목 | 기준 |
|----|------|------|
| X-1-1 | HW 레지스터 주소 constexpr | AIRCR/VECTKEY 등 매직넘버 금지 |
| X-1-2 | 레지스터 RMW 원자성 | PRIMASK 또는 비트밴딩 |
| X-1-3 | 페리페럴 클럭 활성화 | RCC ON 후 접근 |
| X-2-1 | DMA 버퍼 Non-cacheable | 32바이트 경계 정렬 |
| X-2-2 | DMA 완료 콜백 배리어 | DSB/DMB 발행 |
| X-2-3 | DMA 이중 버퍼 교차 오염 방지 | 핑퐁 전환 시 잠금 |
| X-3-1 | PVD 임계값 (2.7V) | Flash 오류 방지 |
| X-3-2 | 브라운아웃 NVM 쓰기 중단 | 원자적 폴백 |
| X-3-3 | 웨이크업 후 클럭 재설정 | STOP/STANDBY 복귀 시 PLL |
| X-4-1 | SPI NSS 관리 | 크리티컬 섹션 내 토글 |
| X-4-2 | UART 프레이밍 에러 처리 | ORE/NE/FE 클리어 |
| X-4-3 | I2C 행업 복구 | SCL 토글 10회 + SWRST |
| X-4-4 | 버스 타임아웃 | HW 타이머 연동 |
| X-5-1 | Secure Wipe 3중 방어 | volatile + asm "memory" + release fence |
| X-5-2 | 키 유도 함수 | nonce/salt 포함 |
| X-5-3 | 사이드 채널 방어 | 암호 비교 → 상수 시간 XOR |
| X-5-4 | Write Suppression 방어 | 보안 비교 반환형 → uint32_t |
| X-5-5 | Boolean Coercion 방어 | bool 반환 보안 함수 → uint32_t |
| X-5-6 | 64비트 Data Tearing 방어 | atomic<uint64_t> → 두 개 atomic<uint32_t> |
| X-6-1 | systick 래핑 안전성 | uint32_t ms 49.7일 elapsed 계산 |
| X-6-2 | 타이머 오버플로우 | TIM 16/32비트 경계 처리 |

---

### [HDR항] 헤더 파일 전용 검사 (신규 8항)

| No | 항목 | 기준 |
|----|------|------|
| HDR-1 | #pragma once | 이중 include 가드 존재 |
| HDR-2 | 구현 코드 금지 | 함수 본문 직접 작성 금지 (inline/constexpr/template 예외) |
| HDR-3 | 전역 변수 금지 | extern 선언만 허용 |
| HDR-4 | using namespace 금지 | 헤더 내 전면 금지 |
| HDR-5 | Pimpl 확인 | struct Impl; 전방 선언만, 정의는 .cpp에만 |
| HDR-6 | ARM 전용 선언 가드 | #if defined(__arm__) 내부에만 |
| HDR-7 | Self-Contained | 헤더 단독 컴파일 가능 여부 |
| HDR-8 | 외부 업체 가이드 섹션 | 공개 헤더 상단에 통합 가이드 블록 존재 |

---

### [PIMPL항] Pimpl 은닉화 검사 (신규 6항)

| No | 항목 | 기준 |
|----|------|------|
| PIMPL-1 | Impl 정의 위치 | .cpp에만 존재, 헤더에 멤버 노출 금지 |
| PIMPL-2 | impl_buf_ 선언 | alignas(N) uint8_t impl_buf_[SIZE], 플랫폼 분기 |
| PIMPL-3 | get_impl() 검증 | static_assert(sizeof(Impl) <= IMPL_BUF_SIZE) 내부 존재 |
| PIMPL-4 | 생성자 순서 | Secure_Wipe → placement new → impl_valid_ store(true) |
| PIMPL-5 | 소멸자 순서 | p->~Impl() → Secure_Wipe(impl_buf_) |
| PIMPL-6 | 복사/이동 차단 | = delete 선언 |

---

### [EXT항] 외부 업체 가이드 검사 (신규 7항)

| No | 항목 | 기준 |
|----|------|------|
| EXT-1 | 통합 가이드 섹션 | 공개 헤더 상단에 사용법/메모리/보안/교체항목 명시 |
| EXT-2 | 교체 필요 HW 상수 경고 | `⚠ [파트너사 필수 교체]` 주석 |
| EXT-3 | NVIC/IRQ 플레이스홀더 경고 | RM0090 벡터 테이블 참조 주석 삽입 |
| EXT-4 | 전역/정적 배치 경고 | `⚠ [배치 주의]` @warning 명시 |
| EXT-5 | 파트너사 교체 레지스터 목록 | UART/WDT 커스텀 주소 명시 |
| EXT-6 | Cortex-M7 마이그레이션 가이드 | Cache 함수 교체 필요 주석 |
| EXT-7 | 빌드 프리셋 가이드 | KCMVP/FIPS/DUAL 활성화 방법 명시 |

---

### [NVIC항] NVIC/인터럽트 경고 특별 검사 (신규 5항)

```
⚠ 외부 업체가 가장 많이 놓치는 항목입니다.
  모든 NVIC 관련 코드에 아래 경고를 반드시 삽입하세요.
```

| No | 항목 | 기준 |
|----|------|------|
| NVIC-1 | NVIC 설정 위치 전수 검색 | 발견 위치 목록 출력, 미발견 시 [요검토] |
| NVIC-2 | IRQ 번호 플레이스홀더 경고 | RM0090 벡터 테이블 주석 삽입 |
| NVIC-3 | ISR 핸들러 명 검증 | DMA2_Stream0_IRQHandler ↔ 실제 IRQ 일치 |
| NVIC-4 | ISR WDT 킥 금지 주석 | `⚠ [WDT 규칙] ISR 내 Kick_Watchdog() 호출 금지` |
| NVIC-5 | 우선순위 역전 경보 | 보안 ISR > 통신 ISR 확인 |

**NVIC-2 삽입 주석 표준:**
```cpp
// ⚠════════════════════════════════════════════════════════
// [외부업체 필수 확인] IRQ 번호 교체 필요 — 양산 사용 금지
//
// STM32F407 RM0090 벡터 테이블:
//   TIM2=28, TIM3=29, TIM4=30, TIM5=50
//   DMA1_Stream0=11 ~ DMA1_Stream7=47
//   DMA2_Stream0=56 ~ DMA2_Stream7=70
//   SPI1=35, SPI2=36, SPI3=51
//   USART1=37, USART2=38, USART3=39
//
// ※ IPC_Protocol이 DMA2_Stream0(56번)을 SPI1 RX로 사용 중.
//   Tx 스케줄러 DMA는 반드시 다른 Stream 번호로 설정하세요.
// ⚠════════════════════════════════════════════════════════
```

---

### [AIRCR항] AIRCR/DBGMCU 리셋 패턴 검사 (신규 4항)

| No | 항목 | 기준 |
|----|------|------|
| AIRCR-1 | 리셋 경로 전수 검색 | 전체 파일 목록 출력, 순서 확인 |
| AIRCR-2 | DBGMCU 비트 정합 | WWDG_STOP=bit11, IWDG_STOP=bit12 (RM0090) |
| AIRCR-3 | DBGMCU 클리어 누락 | AIRCR 쓰기 후 클리어 없으면 FAIL |
| AIRCR-4 | MemManage_Handler 패턴 | Hardware_Init.cpp도 동일 패턴 적용 |

---

## 6. BUG 수정 이력 주석 제거 규칙

### 6-1. 제거 대상

```
[제거 1] 파일 상단 수정 이력 블록 전체
  // [양산 수정 — N건 결함 교정]
  // [양산 수정 이력 — 누적 N건]
  //  BUG-01 [CRIT] ...
  //    기존: ...
  //    수정: ...
  → 위 패턴으로 구성된 블록 전체 제거

[제거 2] 인라인 BUG 태그 주석
  // [BUG-NN] ...
  // [BUG-FIX ...] ...
  // [FIX-...] ...
  // [BUG-AIRCR-WDT] ...
  → 해당 줄 주석 제거 (코드는 유지)

[제거 3] PENDING 태그
  // [PENDING ...] ...
  → 해당 줄 주석 제거

[제거 4] 검수 세션 태그
  // ── 세션 N (BUG-NN ~ BUG-NN) ──
  → 해당 줄 제거
```

### 6-2. 유지 대상 (절대 제거 금지)

```
[유지 1] 파일 기본 헤더
  // ============================================================
  // HTS_xxx.cpp
  // Target: STM32F407 ...
  // ============================================================

[유지 2] 외주 업체 통합 가이드 섹션 전체

[유지 3] 함수·구조체 Doxygen 주석
  /// @brief / @param / @return / @note / @warning

[유지 4] 아키텍처 설명 주석 (알고리즘 동작 원리)
  // Phase 1: ... / Phase 2: ...
  // [보안 분석] / [설계 의도]

[유지 5] ⚠ 경고 주석 (외부 업체 가이드)
  // ⚠ [외부업체 필수 확인] ...
  // ⚠ [NVIC/HW 주의] ...
  // ⚠ [파트너사 필수 교체] ...

[유지 6] 불가피 사유 주석
  // [J-3 예외] / [항목⑨] 불가피 사유 주석
  // [항목⑨] % 불가피: Fisher-Yates 균등 분포 필수

[유지 7] constexpr 상수 설명 주석
  ///< AIRCR 리셋 명령 / ///< 디버거 활성화 등

[유지 8] static_assert 메시지 및 관련 주석
```

### 6-3. 제거 처리 순서

```
검사 항목 적용 완료
→ 자동 수정 완료
→ BUG 이력 주석 제거
→ 로그에 "BUG 이력 N줄 제거" 기록
→ 다음 파일 자동 시작
```

---

## 7. 판정 체계

| 판정 | 의미 |
|------|------|
| PASS | 기준 충족 |
| FAIL | 기준 위반 → 자동 수정 시도 |
| [요검토] | 자동 수정 불가 → 최종 보고서에 목록화 |
| N/A | PC 전용 / 해당 없음 |
| SKIP | 파일 전체 제외 (PC 전용 파일) |

---

## 8. 정오표 핵심 예외

| 예외 | 설명 |
|------|------|
| J-3 예외 | SWAR/CRC/LCG/비트마스크 알고리즘 표준상수 → 명명 없이 허용 |
| Secure Wipe 표준 | volatile 루프 + asm clobber "memory" + release fence 3중 필수 |
| std::atomic 전용 | volatile 동기화 목적 사용 금지 |
| constexpr 나눗셈 | 컴파일타임 상수 나눗셈 허용 |
| 32비트 UDIV | ARM Cortex-M4 하드웨어 UDIV 허용 |
| Fisher-Yates % | 가변 분모 균등 분포 필수 → 불가피 주석 명시로 허용 |
| HW 레지스터 주소 | constexpr 상수로 명명 필수 (매직넘버 금지) |

---

## 9. 로그 형식

```
파일명          | 항목      | 결과      | 처리
HTS_xxx.cpp    | ③힙      | FAIL      | 자동수정완료
HTS_xxx.h      | HDR-8    | FAIL      | [요검토]
HTS_xxx.cpp    | NVIC-2   | FAIL      | 자동수정완료(경고주석삽입)
HTS_xxx.cpp    | AIRCR-2  | FAIL      | 자동수정완료
HTS_xxx.cpp    | N-2      | N/A       | PC용 항목
HTS_xxx.cpp    | BUG이력  | 제거완료  | 47줄 삭제
```

---

## 10. 최종 보고서 형식

```
════════════════════════════════════════════
HTS B-CDMA 전수검사 최종 보고서 v5.0
════════════════════════════════════════════
총 처리 파일  : N개 (PC 전용 14개 제외)
총 자동 수정  : N건
총 [요검토]   : N건
BUG 이력 제거 : 총 N줄

[Layer별 결과]
Layer N | 파일 N | 수정 N | 요검토 N

[자동 수정 완료 목록]
파일명 | 항목 | 수정 내용 요약

⚠ [요검토 목록 — 사람 확인 필요] ⚠
파일명 | 항목 | 불확실 사유 | 권장 조치

⚠ [NVIC/IRQ 교체 필요 목록] ⚠
파일명 | 현재 플레이스홀더 | 교체 방법

⚠ [파이프라인 영향 주의] ⚠
수정으로 상위 계층 확인이 필요한 파일 목록
════════════════════════════════════════════
```

---

## 총 항목 수

| 분류 | 항목 수 |
|------|---------|
| 필수 17항 + 보충 A~D | 21 |
| A~G (동시성~빌드) | 16 |
| H (포인터/메모리) | 20 |
| I~K (제어흐름~Cortex-M4) | 11 |
| L~M (가독성~정적분석) | 23 |
| N (동시성) | 15 |
| O (입력검증/보안) | 15 |
| P (런타임/성능) | 15 |
| Q (프로젝트 구조) | 15 |
| R (보안부팅/펌웨어) | 30 |
| U (구조적 안전성) | 4 |
| V (모듈별 특수취약점) | 35 |
| W (수석 아키텍트 규약) | 4 |
| X (추가 정밀검사) | 20 |
| HDR (헤더 전용) | 8 |
| PIMPL (은닉화) | 6 |
| EXT (외부업체 가이드) | 7 |
| NVIC (인터럽트 경고) | 5 |
| AIRCR (리셋 패턴) | 4 |
| **합계** | **281** |