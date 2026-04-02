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

# HTS B-CDMA 전수검사 통합 기준서
**INNOViD CORE-X Pro HTS B-CDMA 보안통신 펌웨어**
**버전 5.1 — 초경량화 양산 전용 (OOM 방어 최적화)**

---

## 0. 자동 검수 실행 원칙 (AI 행동 지침)

1. **파일당 1-Pass 처리:** Layer 0부터 순차적으로 읽고, 수정 및 로그 기록 후 즉시 메모리를 비우고 다음 파일로 넘어갈 것. (동시 다중 파일 로드 금지)
2. **양산 무결성 집중:** 스타일(들여쓰기, 네이밍), 모던 C++ 문법 강제(auto, 범위 기반 for), 컴파일러 자동 최적화(RVO, 루프 이동) 지적을 엄격히 금지함.
3. **기능 훼손 절대 금지:** 알고리즘 본문, 수식, 상태 머신 전이 순서, 파이프라인 호출 순서를 단 1줄도 임의로 변경하지 말 것.
4. **자동 수정 3조건:** ① 기준서에 명시된 보안/포인터/동시성 위반 사항일 것, ② 함수 시그니처가 변하지 않을 것, ③ 100% 확신이 있을 것. 불충족 시 `[요검토]` 태그만 남기고 패스.

---

## 1. 제외 대상 (검수 생략 및 N/A 처리)

* **전체 SKIP (PC 전용 파일):** `HTS_3D_Tensor_FEC.h/.cpp`, `Layer 18 (모든 테스트 파일)`
* **코드 블록 SKIP:** `#else` (ARM 가드 반대편), `_HTS_CREATOR_MODE` 내부 코드
* **컴파일러 위임 (검사 금지):** 데드 코드 제거, 캐시 지역성, O(n²) 복잡도, RVO/NRVO.

---

## 2. 필수 검수 17항 + 보충 4항 (최우선 스캔)

* **① 배리어:** seq_cst 금지 → acquire/release/relaxed 다운그레이드 (단, Secure Wipe fence는 건드리지 말 것)
* **② std::abs:** ARM 경로에서 사용 금지 → fast_abs 전환
* **③ 힙 할당 금지:** ARM 경로 내 new/malloc/shared_ptr/std::vector/std::string 전면 금지 → 정적 버퍼 + placement new 전환
* **④ double/float:** ARM 내 double 금지 → Q16 정수 또는 static_cast<float> 전환
* **⑤ 예외 금지:** try-catch-throw 삭제 (-fno-exceptions)
* **⑥ 스택 보호:** 512B 초과 로컬 배열 → static/전역 전환, 재귀 호출 금지
* **⑦ 주석 일치:** BUG 수정 이력과 코드 정합성 유지
* **⑧ SRAM 검증:** Pimpl 구조체에 `static_assert(sizeof(Impl) <= IMPL_BUF_SIZE)` 필수
* **⑨ 나눗셈 제거:** 가변 분모 64비트 나눗셈 → 시프트/비트마스크 (32비트 UDIV 및 불가피 주석은 허용)
* **⑩ Zero-copy:** 64B 초과 구조체 값 전달 금지 → const& 전환
* **⑪ 엔디안:** 포인터 직접 캐스팅 직렬화 금지 → 비트 시프트
* **⑫ 캐스팅:** 암묵적 형변환, C스타일 캐스팅 금지 → static_cast 명시
* **⑬ CFI:** 상태 머신 전이 시 이전 상태 유효성 검증 로직 필수
* **⑭ PC 헤더:** `<iostream>`, `<thread>`, `<mutex>` 등 발견 시 `#ifndef HTS_PLATFORM_ARM` 가드 처리
* **⑮ 타임아웃:** HW 폴링 `while(flag)`에 타임아웃/상한 카운터 필수
* **⑯ 플래시 원자성:** Flash 쓰기 후 Read-Back 검증 확인
* **⑰ 데드라인/NVIC:** ISR 내 무제한 루프 금지, NVIC IRQ 번호는 플레이스홀더로 두고 `[파트너사 필수 교체]` 경고 주석 삽입
* **[A] sizeof 경고:** 1KB+ 멤버 포함 시 `@warning 전역/정적 배치 필수` 명시
* **[B] 래퍼 static_assert:** 1KB+ 클래스 sizeof ≤ SRAM 예산 산출 주석 포함
* **[C] CAS 가드:** 원자적 1회성 초기화는 `compare_exchange_strong` 사용
* **[D] 속성 가드:** raw `[[likely]]` 금지 → 프로젝트 매크로 처리

---

## 3. 핵심 아키텍처 및 보안 검수 항목 (초경량화)

**(※ 작동과 무관한 스타일/가독성 조항 전면 삭제 완료)**

### [A/B/C/D] 코어 무결성
* A-2. DMA/ISR 공유 영역 `atomic_thread_fence` + `volatile` 병행
* A-3. ISR 내 mutex/spinlock 배제 (Lock-free/CAS 링버퍼)
* B-2. alignas 누락에 의한 Unaligned Access 방어
* D-1. 암호 연산 Constant-time (if/switch 금지 → 비트마스크)
* **D-2. 보안 소거 3중 방어 (패턴 1자도 변경 금지):** `volatile 루프` + `__asm__ volatile("" ::: "memory");` + `release fence`
* **D-3. JTAG 감지 리셋 (순서 엄수):** `AIRCR 쓰기` → `DBGMCU 정지` → `dsb/isb` → `for(;;)`

### [H/I/J/K] 메모리 & 흐름 제어 (치명적 오류만)
* H-1~H-3, H-7~H-8. 널/댕글링 포인터, OOB, 이중 해제, 누수 원천 차단
* H-12~H-13. strcpy/sprintf 금지 → strncpy/snprintf 강제
* I-3. switch 문 default 케이스 명시
* J-1~J-2. 정수 축소 변환 시 유실, Unsigned 오버/언더플로우 방어
* J-3. HW 레지스터 매직넘버 금지 → constexpr 상수화
* K-1~K-3. MPU 리전 검사, ISR 진입 시 FPU 컨텍스트 보호

### [M/N/O] 정적 분석 & 동시성 (ARM 전용)
* M-4. 경고 유발 코드 수정 (-Werror 대비)
* M-8. reinterpret_cast 최소화 및 안전성 검증
* M-20. Pimpl 패턴의 placement new 규격 준수
* N-1, N-3, N-10. 데이터 레이스 방어, PRIMASK 크리티컬 섹션 락 범위 최소화
* O-1, O-4, O-13. 외부 입력/페이로드 인자 경계 및 버퍼 크기 철저 검증

### [R] 펌웨어 검증 (보안 부팅)
* R-17. WDT는 ISR 내부에서 킥 금지, 메인 루프 최상단에서만 허용
* R-19. HardFault 시 레지스터 로깅 후 즉각 리셋

---

## 4. 모듈 및 파트너사 연동 규약 (경계 방어)

### [PIMPL] 은닉화 표준
* Impl 정의는 무조건 `.cpp` 내부. 복사/이동은 `= delete`.
* 생성자: `Secure_Wipe(buf)` → `placement new` → `valid=true`
* 소멸자: `~Impl()` 호출 → `Secure_Wipe(buf)`

### [EXT] 파트너사/NVIC 특별 경고 (자동 삽입 템플릿)
* 코드에 임의의 NVIC 번호를 매핑하지 말 것. 발견 시 아래 주석 필수 삽입.
```cpp
// ⚠════════════════════════════════════════════════════════
// [외부업체 필수 확인] IRQ 번호 교체 필요 — 양산 사용 금지
// RM0090 벡터 테이블 참조 (ex: SPI1=35, DMA2_Stream0=56)
// ⚠════════════════════════════════════════════════════════

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