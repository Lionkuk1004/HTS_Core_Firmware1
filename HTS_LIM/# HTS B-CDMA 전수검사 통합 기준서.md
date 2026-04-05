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
| 전압 | 1.8~3.6V (PVD 감시) |`
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
| ISR 지연 | 12~16사이클 진입 | ISR 내 긴 로직 금지

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

[Layer 18 — HTS_TEST PC 검증 전용 (펌웨어 TU 제외)]
  HTS_TEST\KCMVP_암호_4종_종합_테스트.cpp      ← HTS_검증_KCMVP.vcxproj (ARIA/HMAC/LEA/LSH 단일 exe)
  HTS_TEST\종합재밍_종합_테스트.cpp            ← HTS_검증_종합재밍.vcxproj (Tensor+HARQ 시뮬)
  HTS_TEST\AMI_종합_통합_테스트.cpp            ← HTS_검증_AMI.vcxproj (AMI S1~S10)
  (구 레거시 개별 KAT·재밍·AMI 파일명은 제거됨 — HTS_Development.sln 동기화)
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
  util.c (ClCompile — C 런타임 유틸, §8-7)

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
    ※ ARIA/LEA/LSH256/HMAC/DRBG 벡터는 별도 *_KCMVP_KAT.cpp 가 아니라
      Crypto_KAT::KAT_ARIA / KAT_LEA / KAT_LSH256 / KAT_HMAC_SHA256 / KAT_DRBG 로
      단일 TU에 통합됨 (§8-5)
    ※ PC 독립 재검: HTS_TEST\KCMVP_암호_4종_종합_테스트.cpp + HTS_검증_KCMVP.vcxproj
  HTS_Conditional_SelfTest.h → .cpp

Layer 5  — 키 관리 / 보안 부팅
  HTS_Key_Provisioning.h → .cpp
  HTS_Key_Rotator.h → .cpp
  HTS_Dynamic_Key_Rotator.hpp → .cpp
  HTS_Secure_Boot_Verify.h → .cpp
  HTS_Anchor_Vault.hpp → host_aarch64\HTS_Anchor_Vault.cpp (A55/서버 TU — ARM-M4 단독 빌드 시 제외)
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
  HTS_AntiJam_Engine.h → .cpp
    ※ 3층 항재밍(AJC·Punch·Spatial Null). HTS_V400_Dispatcher.hpp 가 본 헤더를 include.
  AnchorEncoder.h → .cpp / AnchorDecoder.h → .cpp / AnchorManager.h → .cpp / TensorCodec.hpp → .cpp
    ※ 현재 HTS_LIM.vcxproj 에 단독 TU 없음 — BB1_Core_Engine / Holo·Sparse 등에 흡수된 것으로 검수 (§8-7)
  HTS_Orbital_Mapper.hpp → .cpp
  HTS_Sparse_Recovery.h → .cpp
  HTS_Quantum_Decoy_VDF.h → .cpp (CORE 헤더 / HTS_LIM 구현 TU)

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
    ※ 내부적으로 HTS_AntiJam_Engine.h 의존 (Layer 8 TU와 링크)

Layer 12 — 보안 파이프라인 / 세션
  HTS_AEAD_Integrity.hpp
  HTS_Security_Pipeline.h → .cpp
  HTS_Security_Session.h → .cpp
  HTS_Session_Gateway.hpp → .cpp
  HTS_Remote_Attestation.hpp → .cpp
  HTS_Role_Auth.h → .cpp

Layer 13 — 스토리지
  HTS_Storage_Interface.h → host_aarch64\HTS_Storage_Interface.cpp (호스트 TU — ARM-M4 단독 빌드 시 제외)
  HTS_Storage_Adapter.hpp

Layer 14 — 통신 프로토콜
  HTS_IPC_Protocol.h → .cpp
  HTS_IPC_Protocol_A55.h → host_aarch64\HTS_IPC_Protocol_A55.cpp (A55 IPC TU — 타깃별 제외 검토)
  HTS_Network_Bridge.h → .cpp
  HTS_KT_DSN_Adapter.h → .cpp
  HTS_CoAP_Engine.h → .cpp
  HTS_Voice_Codec_Bridge.h / HTS_Voice_Codec_Bridge_Defs.h → .cpp
    ※ 보코더·PLC·IPC_Error; HTS_API.h 기본 틱 주기 주석과 Defs 정합
  HTS_Mesh_Router.h → .cpp
  HTS_Mesh_Sync.h → .cpp
  HTS_Neighbor_Discovery.h → .cpp
  HTS_Universal_Adapter.h / .hpp → .cpp

Layer 15 — AMI / OTA
  HTS_AMI_Protocol.h / HTS_AMI_Protocol_Defs.h → .cpp
  HTS_OTA_AMI_Manager.h → .cpp
  HTS_OTA_Manager.h / HTS_OTA_Manager_Defs.h → .cpp
  HTS_Meter_Data_Manager.h → .cpp
  HTS_Modbus_Gateway.h / HTS_Modbus_Gateway_Defs.h → .cpp
  HTS_BLE_NFC_Gateway.h / HTS_BLE_NFC_Gateway_Defs.h → .cpp

Layer 16 — IoT / 센서 / 비상
  HTS_IoT_Codec.h / HTS_IoT_Codec_Defs.h → .cpp
  HTS_Sensor_Aggregator.h → .cpp
  HTS_Sensor_Fusion.h → .cpp
  HTS_Gyro_Engine.h → .cpp
  HTS_Location_Engine.h → .cpp
  HTS_Emergency_Beacon.h → .cpp
  HTS_CCTV_Security.h / HTS_CCTV_Security_Defs.h → .cpp

Layer 17 — 스케줄러 / 최상위 API
  HTS_Priority_Scheduler.h → .cpp
  HTS_Unified_Scheduler.hpp → .cpp
  HTS_Console_Manager.h / HTS_Console_Manager_Defs.h → .cpp
  HTS_Universal_API.h / .hpp → .cpp
    ※ `HTS_Universal_API.def` — vcxproj `None`(링커보내기), TU 아님
  HTS_API.h → .cpp

Layer 18 — 테스트 [전체 SKIP — PC 전용]
```

※ **섹션 3 ↔ §8 부록 동기화:** Layer 4(KAT 통합), Layer 5·13·14(호스트 TU), Layer 8·11(AntiJam), Layer 14(Voice Codec), Layer 0(`util.c`), **Layer 15~17(`*_Defs.h`·`Universal_API.def`)** 는 `HTS_LIM.vcxproj` `ClCompile`/`ClInclude`/`None` 과 정합. TU 목록 §8-7, Defs·필터 §8-2·§8-8. **M4 SRAM 합계·`.map`** 은 정적 라이브러리 단독 빌드로는 미완 — §8-11.

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


# HTS B-CDMA 전수검사 통합 기준서
**INNOViD CORE-X Pro HTS B-CDMA 보안통신 펌웨어**
**버전 5.1 — 초경량화 양산 전용 (OOM 방어 최적화)**

---

## 0. 자동 검수 실행 원칙 (AI 행동 지침)

1. **파일당 1-Pass 처리:** Layer 0부터 순차적으로 읽고, 수정 및 로그 기록 후 즉시 메모리를 비우고 다음 파일로 넘어갈 것. (동시 다중 파일 로드 금지)
2. **양산 무결성 집중:** 스타일(들여쓰기, 네이밍), 모던 C++ 문법 강제(auto, 범위 기반 for), 컴파일러 자동 최적화(RVO, 루프 이동) 지적을 엄격히  금지함.
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

# HTS B-CDMA 보안/최적화 필수 지침 및 양산 방어 기준서 (Bare-metal ARM Cortex-M4)

1. 하드웨어 메모리 보호 및 안티포렌식 (MPU & Anti-Forensics)
   - [동적 할당 금지] 런타임 동적 할당(new/malloc) 절대 금지. 힙(Heap) 할당 0회 유지.
   - [MPU 하드웨어 잠금] 보안 버퍼는 MPU(RBAR/RASR)를 제어하여 물리적 Read-Only(AP=110) 잠금 적용. 공유 뱅크 레지스터(RNR) 대신 RBAR Alias 기능을 활용하여 컨텍스트 스위칭 간 Data Race 차단.
   - [RAII 강제] 수동 Lock/Unlock API 노출 금지. RAII(스코프 가드) 패턴으로 설계하여 조기 return 시에도 MemManage Fault(데드락) 원천 차단.
   - [잔여 키 파쇄] 객체 소멸 전 또는 세션 강제 종료(Clean_State) 시, SRAM에 잔류하는 AES/ARIA 라운드 키 테이블 명시적 파쇄(secureWipe).
   - [컴파일러/버스 배리어] LTO/DCE 및 TBAA 최적화에 의한 파쇄 로직 증발을 막기 위해 `asm memory clobber` 및 버스 동기화용 `dsb sy` 배리어 필수 적용.
   - [패딩 바이트 유출 방어] Placement New(Pimpl 패턴 등) 사용 시, 생성 전 버퍼를 파쇄하여 패딩 데이터 누출 방지 및 std::launder 적용으로 수명 분석기 오작동 방어.
   - [정렬 주소 산술 오버플로우 방어] 포인터 정렬 시 단순 덧셈(addr + 3) 대신 비트 마스킹 ((4u - (addr & 3u)) & 3u) 연산으로 대체하여 O(1) 정렬 무결성 확보 및 메모리 래핑 하드폴트 방어.

2. 연산 및 버스 오버헤드 최적화 (O(1) 지향)
   - [UDIV 호출 차단] 하드웨어 나눗셈기 호출 차단을 위해 나눗셈(/) 및 모듈로(%) 연산 금지. 비트 연산(>>, &)과 매직 넘버(역수) 곱셈으로 대체.
   - [메모리 버스 최적화] 1바이트(STRB) 루프 금지. 시작 주소 정렬 확인 후 32비트(uint32_t) 워드 단위 고속 처리. 캐스팅 시 __may_alias__ 속성을 부여하여 TBAA 루프 증발 차단.
   - [레지스터 호이스팅] O(N) 루프 내부 메모리 복사 및 엔디안 변환 금지. 진입 전 64비트 레지스터 2개로 호이스팅하여 연산 후 종료 시 1회만 배열 복원.
   - [Single-pass 조립] 메모리 대역폭 낭비 및 CRC 위양성 방지를 위해 단일 패스(Single-pass) 파이프라인 유지.
   - [MISRA-C++ 음수 시프트 금지] 부호 있는 정수(Signed)의 비트 시프트(미정의 동작 유발) 절대 금지. 시프트 전 부호 없는 정수(Unsigned)로 반드시 캐스팅.
   - [64비트 원자성 에뮬레이션 차단] std::atomic<uint64_t> 사용 시 발생하는 libatomic 뮤텍스 강제 삽입(ISR 데드락) 방지. 32비트 변수에 상태를 비트 패킹하여 진정한 Lock-Free 구현.

3. 동시성 제어 및 안티 글리칭 (Concurrency & Anti-Glitching)
   - [Branchless 마스킹] 조건 분기(BNE/BEQ)를 유발하는 단축 평가(||, &&) 및 삼항 연산자 금지. static_cast<uint32_t>와 풀 비트 마스킹(0u - bits)을 활용해 제어 흐름 자체가 데이터를 변조하는 Branchless 코드 작성.
   - [산술 상태 머신] 카운터 리셋 시 if/else 금지. count = (count + 1) * is_same 형태의 순수 산술 연산으로 갱신. ISR에서 메인 루프 판정 변수 직접 갱신 금지.
   - [PRIMASK 글로벌 락 금지] agg_critical_enter로 모든 인터럽트를 막는 행위 금지. 하드웨어 버스 원자성과 std::atomic 기반 Lock-Free 데이터 파이프라인 구축.
   - [Lock-free 다중 스레드 CFI] 32비트 원자 변수에 '상태 + 활성 카운트'를 패킹하여 CAS(compare_exchange_weak) 루프로 다중 진입을 허용하는 제어 흐름 무결성(CFI) 구축.
   - [비동기 롤백 방어 및 스톨 금지] 스냅샷 역행 방지용 단조 증가(Monotonic) 검증 포함. 버려지는 레이트 리미터 슬롯은 생산자 풀로 즉각 반환(kAuditEmpty)하여 플래시 DMA 스톨 차단.

4. 런타임 보안 감시 및 물리적 방어망 (Runtime Security & Physical Defense)
   - [상시 하드웨어 퓨즈 폴링] 초기 1회 검사에 따른 TOCTOU 취약점 방어. 스트리밍 런타임 및 센서 데이터 주입 직전 JTAG/SWD(DHCSR) 및 RDP 레벨을 상시 폴링하여 훼손 시 즉각 자폭(Terminal Fault).
   - [지연 파기 시 즉각 파쇄] 타이밍 공격을 막기 위해 세션 파기를 백그라운드로 지연시키더라도, 핵심 세션 키 버퍼는 즉각 상수 시간에 파쇄(secureWipe)하여 오프라인 RAM 덤프 물리적 차단.
   - [Two-Time Pad 원천 분리] 송수신 채널에 동일 IV 주입 시 수신 카운터 MSB를 반전시키는 등, 하드웨어 레벨에서 수학적으로 도메인을 완벽히 분할하여 키스트림 중복 생성 원천 차단.

5. 양산 무결성 및 하드웨어 생애주기 관리 (Mass Production & Lifecycle)
   - [보안 프로비저닝 상태 분리] 런타임 퓨즈 폴링(4항)이 양산 공정의 초기 키 주입(Root Key Provisioning)을 차단하는 모순을 해결하기 위해, 펌웨어 부트 영역에 공정 초기 상태(Unprovisioned)와 양산 완료 상태(Sealed)를 하드웨어적으로 명확히 구분하는 상태 머신 추가.
   - [플래시 마모(Wear-out) 한계 방어] 비휘발성 메모리 손상 방지를 위한 A/B 뱅크 교차 기록 시 특정 섹터 집중 훼손을 막기 위해, EEPROM 에뮬레이션 물리 주소를 지속적으로 순환시키는 웨어 레벨링(Wear-leveling) 알고리즘 또는 쓰기 하드웨어 카운터 도입.
   - [독립 클럭 기반 와치독 적용] 전력/클럭 글리칭으로 메인 클럭(HSE/HSI)이 정지될 경우 소프트웨어 복구 불가. 메인 시스템과 완전히 분리된 내부 저속 클럭(LSI) 기반의 독립형 와치독(IWDG)을 가동하여 최악의 상황에서도 하드웨어 핀 리셋 보장.
수정은 검토후 인정이 될 경우에만 최소 침습 보강 패치 수정하며 기존의 문제없이 기능하는 코드는 건드리지 않으며 검사가 끝나면 바로 수정작업을 진행한다.

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

## 8. 부록 — `HTS_LIM.vcxproj` 연결·파이프라인 (2026 유지보수)

섹션 3 레이어 순서와 정적 라이브러리 빌드 단위(`ClCompile`)를 맞출 때 참고한다.
**헤더 전용(.hpp만)** / **C 소스** / **호스트 전용** 은 표에 별도 표기한다.

### 8-1. 빌드 매트릭스 예외 (`HTS_LIM.vcxproj` 주석과 동일)

| 항목 | Win32/x64 | ARM-M4 타깃 추가 시 |
|------|-----------|---------------------|
| `HTS_3D_Tensor_FEC.cpp` | 포함 가능 | **제외** (PC 시뮬 전용) |
| `host_aarch64\HTS_Anchor_Vault.cpp` | 포함 | **제외** (A55/서버) |
| `host_aarch64\HTS_Storage_Interface.cpp` | 포함 | **제외** (A55/서버) |
| `host_aarch64\HTS_IPC_Protocol_A55.cpp` | 포함 | 보드 정책에 따름 |

### 8-2. Layer 0~17 ↔ 주요 `ClCompile` (`.cpp`)

- **Layer 0**: `common.h` / `config.h` / `util.c` / `arm_arch.h` — C 유틸은 `util.c` 등으로 TU 연결.
- **Layer 1**: `HTS_Hardware_Init.cpp`, `HTS_Hardware_Bridge.cpp`, `HTS_Hardware_Auto_Scaler.cpp`, `HTS_Hardware_Shield.cpp`, `HTS_POST_Manager.cpp`, `HTS_Power_Manager.cpp`
- **Layer 2**: `HTS_Secure_Memory.cpp`, `HTS_ConstantTimeUtil.cpp`, `HTS_Crc32Util.cpp` — `HTS_Secure_Memory_Manager.hpp`는 헤더만.
- **Layer 3**: `aria050117.c`, `hmac.c`, `lea_*.c`, `lsh*.c`, `KISA_*.c`, `HTS_*_Bridge.cpp`, `HTS_CTR_DRBG.cpp`, `HTS_TRNG_Collector.cpp`, `HTS_Physical_Entropy_Engine.cpp`, `HTS_Entropy_Monitor.cpp` + `lsh256.h` 등 헤더
- **Layer 4**: `HTS_Crypto_KAT.cpp`, `HTS_Conditional_SelfTest.cpp` — 개별 `*_KCMVP_KAT.cpp`는 **§8-5**와 같이 `HTS_Crypto_KAT.cpp`에 함수로 통합됨. PC용 정적 KAT는 `HTS_TEST\KCMVP_암호_4종_종합_테스트.cpp`(별도 exe).
- **Layer 5**: `HTS_Key_Provisioning.cpp`, `HTS_Key_Rotator.cpp`, `HTS_Dynamic_Key_Rotator.cpp`, `HTS_Secure_Boot_Verify.cpp`, `HTS_Entropy_Arrow.cpp`, `host_aarch64\HTS_Anchor_Vault.cpp` (Anchor_Vault.hpp 구현 TU)
- **Layer 6**: `HTS_Anti_Debug.cpp`, `HTS_Anti_Glitch.cpp`, `HTS_Tamper_HAL.cpp`, `HTS_AntiAnalysis_Shield.cpp`, `HTS_Polymorphic_Shield.cpp`, `HTS_Pointer_Auth.cpp`, `HTS_Auto_Rollback_Manager.cpp`
- **Layer 7**: `HTS_Secure_Logger.cpp`, `HTS_Config.cpp`, `HTS_Dynamic_Config.cpp`, `HTS_Device_Profile.cpp`, `HTS_Device_Status_Reporter.cpp`, `HTS_Creator_Telemetry.cpp`
- **Layer 8**: `HTS_Gaussian_Pulse.cpp`, `HTS_Rx_Matched_Filter.cpp`, `HTS_Rx_Sync_Detector.cpp`, `HTS_Antipodal_Core.cpp`, `HTS_Adaptive_BPS_Controller.cpp`, `HTS_AntiJam_Engine.cpp`, `HTS_Orbital_Mapper.cpp`, `HTS_Sparse_Recovery.cpp`, `HTS_Quantum_Decoy_VDF.cpp` — Anchor/Tensor 단독 TU 없음 시 `BB1_Core_Engine.cpp` 등에 흡수 (섹션 3 Layer 8 주석).
- **Layer 9**: `HTS_Holo_Tensor_Engine.cpp`, `HTS_Holo_Tensor_4D.cpp`, `HTS_Dual_Tensor_16bit.cpp`, `HTS_3D_Tensor_FEC.cpp` (SKIP 정책 준수)
- **Layer 10**: `HTS_FEC_HARQ.cpp`, `HTS_Tx_Scheduler.cpp`, `BB1_Core_Engine.cpp`, `HTS64_Native_ECCM_Core.cpp`
- **Layer 11**: `HTS_Holo_Dispatcher.cpp`, `HTS_V400_Dispatcher.cpp` (헤더가 `HTS_AntiJam_Engine.h` 의존)
- **Layer 12**: `HTS_Security_Pipeline.cpp`, `HTS_Security_Session.cpp`, `HTS_Session_Gateway.cpp`, `HTS_Remote_Attestation.cpp`, `HTS_Role_Auth.cpp` — `HTS_AEAD_Integrity.hpp`는 헤더만.
- **Layer 13**: `host_aarch64\HTS_Storage_Interface.cpp` (호스트 TU), `HTS_Storage_Adapter.hpp` 헤더
- **Layer 14**: `HTS_IPC_Protocol.cpp`, `host_aarch64\HTS_IPC_Protocol_A55.cpp`, `HTS_Network_Bridge.cpp`, `HTS_KT_DSN_Adapter.cpp`, `HTS_CoAP_Engine.cpp`, `HTS_Voice_Codec_Bridge.cpp`, `HTS_Mesh_Router.cpp`, `HTS_Mesh_Sync.cpp`, `HTS_Neighbor_Discovery.cpp`, `HTS_Universal_Adapter.cpp`
- **Layer 15**: `HTS_AMI_Protocol.cpp` + `HTS_AMI_Protocol_Defs.h`, `HTS_OTA_AMI_Manager.cpp`, `HTS_OTA_Manager.cpp` + `HTS_OTA_Manager_Defs.h`, `HTS_Meter_Data_Manager.cpp`, `HTS_Modbus_Gateway.cpp` + `HTS_Modbus_Gateway_Defs.h`, `HTS_BLE_NFC_Gateway.cpp` + `HTS_BLE_NFC_Gateway_Defs.h`
- **Layer 16**: `HTS_IoT_Codec.cpp` + `HTS_IoT_Codec_Defs.h`, `HTS_Sensor_Aggregator.cpp`, `HTS_Sensor_Fusion.cpp`, `HTS_Gyro_Engine.cpp`, `HTS_Location_Engine.cpp`, `HTS_Emergency_Beacon.cpp`, `HTS_CCTV_Security.cpp` + `HTS_CCTV_Security_Defs.h`
- **Layer 17**: `HTS_Priority_Scheduler.cpp`, `HTS_Unified_Scheduler.cpp`, `HTS_Console_Manager.cpp` + `HTS_Console_Manager_Defs.h`, `HTS_Universal_API.cpp` + `HTS_Universal_API.h` / `.hpp` + `HTS_Universal_API.def`(`None`), `HTS_API.cpp`

### 8-3. 최상위 API 파이프라인 (`HTS_API.cpp` 요약)

1. `Initialize_Core` — `HTS_Secure_Boot_Is_Verified` → `POST_Manager::executePowerOnSelfTest` → `HTS_Tx_Scheduler::Initialize`
2. `Fetch_And_Heal_Rx_Payload` — HW FIFO → `Sparse_Recovery_Engine::Execute_L1_Reconstruction`
3. `Schedule_Unified_Tx_And_Queue` / `Service_Unified_Tx_*` — `Unified_Scheduler` → `Dual_Tensor_Pipeline` → `HTS_Tx_Scheduler::Push_Waveform_Chunk`

보드 부팅 시 `HTS_Hardware_Init`와의 호출 순서는 제품 펌웨어에서 명시할 것 (현재 `HTS_API.cpp`는 해당 심볼을 직접 호출하지 않음).

### 8-4. 동시성 검수 메모 (§2 ①)

- **Secure Wipe / KAT 소거** MSVC 분기의 `memory_order_seq_cst`는 **다운그레이드 금지** (본문 §2 ① 단서).
- 그 외 TRNG·세션·감사 플러시·MPU 배리어 등은 `release` / `acq_rel` 로 정합 가능 — 변경 시 회귀 빌드 권장.

### 8-5. Layer 4 KAT 통합 — 코드 확정 (펌웨어 TU + PC 독립 검증)

**펌웨어(HTS_LIM.lib):** `HTS_Crypto_KAT.cpp` 단일 TU에 다음이 **함수 단위로 통합**되어 있다. 아래 예시 파일명은 **레거시 명명**이며 소스 트리에는 없을 수 있다.

| 기준서 예시 파일 | 실제 구현 |
|------------------|-----------|
| `HTS_ARIA_KCMVP_KAT.cpp` | `Crypto_KAT::KAT_ARIA()` |
| `HTS_LEA_KCMVP_KAT.cpp` | `Crypto_KAT::KAT_LEA()` |
| `HTS_LSH256_KCMVP_KAT.cpp` | `Crypto_KAT::KAT_LSH256()` |
| `HTS_HMAC_KCMVP_KAT.cpp` | `Crypto_KAT::KAT_HMAC_SHA256()` |
| (DRBG) | `Crypto_KAT::KAT_DRBG()` |

**PC 전용(HTS_TEST):** `KCMVP_암호_4종_종합_테스트.cpp` + `HTS_검증_KCMVP.vcxproj` — 동일 알고리즘 **정적 KAT**를 단일 exe로 재검 (브릿지·KISA/NSR C 소스 링크).

`HTS_Conditional_SelfTest.cpp`는 별도 TU로 유지.

### 8-6. 섹션 3에 반영 완료 — 추가 TU 귀속 (코드 근거)

| 파일 | 확정 귀속 | 근거 |
|------|-----------|------|
| `HTS_AntiJam_Engine.cpp` | **Layer 8 (DSP/PHY)** | `HTS_V400_Dispatcher.hpp` 가 `HTS_AntiJam_Engine.h` include — 재밍은 PHY·디스패처 경계 |
| `HTS_Voice_Codec_Bridge.cpp` | **Layer 14 (통신)** | `IPC_Error`·패킷 싱크 API; `HTS_Secure_Memory.h` 의존(Layer 2). `HTS_API.h` 주기 주석과 Defs 연계 |
| `host_aarch64\HTS_IPC_Protocol_A55.cpp` | **Layer 14 (호스트 확장)** | 파일 경로·이름 규약. ARM-M4 단독 빌드 시 `vcxproj` 제외 |

### 8-7. `ClCompile` 전체 인벤토리 (`HTS_LIM.vcxproj` 동기화, 107 TU)

**검증:** `ClCompile` 항목 수 = **107**. TU 추가/삭제 시 아래로 목록을 덤프해 본 블록과 diff 한다.

```powershell
Select-String -Path "HTS_LIM\HTS_LIM.vcxproj" -Pattern 'ClCompile Include="([^"]+)"' |
  ForEach-Object { $_.Matches.Groups[1].Value } | Sort-Object
```

```text
aria050117.c
BB1_Core_Engine.cpp
hmac.c
host_aarch64\HTS_Anchor_Vault.cpp
host_aarch64\HTS_IPC_Protocol_A55.cpp
host_aarch64\HTS_Storage_Interface.cpp
HTS_3D_Tensor_FEC.cpp
HTS_Adaptive_BPS_Controller.cpp
HTS_AES_Bridge.cpp
HTS_AMI_Protocol.cpp
HTS_Anti_Debug.cpp
HTS_Anti_Glitch.cpp
HTS_AntiAnalysis_Shield.cpp
HTS_AntiJam_Engine.cpp
HTS_Antipodal_Core.cpp
HTS_API.cpp
HTS_ARIA_Bridge.cpp
HTS_Auto_Rollback_Manager.cpp
HTS_BLE_NFC_Gateway.cpp
HTS_CCTV_Security.cpp
HTS_CoAP_Engine.cpp
HTS_Conditional_SelfTest.cpp
HTS_Config.cpp
HTS_Console_Manager.cpp
HTS_ConstantTimeUtil.cpp
HTS_Crc32Util.cpp
HTS_Creator_Telemetry.cpp
HTS_Crypto_KAT.cpp
HTS_CTR_DRBG.cpp
HTS_Device_Profile.cpp
HTS_Device_Status_Reporter.cpp
HTS_Dual_Tensor_16bit.cpp
HTS_Dynamic_Config.cpp
HTS_Dynamic_Key_Rotator.cpp
HTS_Emergency_Beacon.cpp
HTS_Entropy_Arrow.cpp
HTS_Entropy_Monitor.cpp
HTS_FEC_HARQ.cpp
HTS_Gaussian_Pulse.cpp
HTS_Gyro_Engine.cpp
HTS_Hardware_Auto_Scaler.cpp
HTS_Hardware_Bridge.cpp
HTS_Hardware_Init.cpp
HTS_Hardware_Shield.cpp
HTS_HMAC_Bridge.cpp
HTS_Holo_Dispatcher.cpp
HTS_Holo_Tensor_4D.cpp
HTS_Holo_Tensor_Engine.cpp
HTS_IoT_Codec.cpp
HTS_IPC_Protocol.cpp
HTS_Key_Provisioning.cpp
HTS_Key_Rotator.cpp
HTS_KT_DSN_Adapter.cpp
HTS_LEA_Bridge.cpp
HTS_Location_Engine.cpp
HTS_LSH256_Bridge.cpp
HTS_Mesh_Router.cpp
HTS_Mesh_Sync.cpp
HTS_Meter_Data_Manager.cpp
HTS_Modbus_Gateway.cpp
HTS_Neighbor_Discovery.cpp
HTS_Network_Bridge.cpp
HTS_Orbital_Mapper.cpp
HTS_OTA_AMI_Manager.cpp
HTS_OTA_Manager.cpp
HTS_Physical_Entropy_Engine.cpp
HTS_Pointer_Auth.cpp
HTS_Polymorphic_Shield.cpp
HTS_POST_Manager.cpp
HTS_Power_Manager.cpp
HTS_Priority_Scheduler.cpp
HTS_Quantum_Decoy_VDF.cpp
HTS_Remote_Attestation.cpp
HTS_Role_Auth.cpp
HTS_Rx_Matched_Filter.cpp
HTS_Rx_Sync_Detector.cpp
HTS_Secure_Boot_Verify.cpp
HTS_Secure_Logger.cpp
HTS_Secure_Memory.cpp
HTS_Security_Pipeline.cpp
HTS_Security_Session.cpp
HTS_Sensor_Aggregator.cpp
HTS_Sensor_Fusion.cpp
HTS_Session_Gateway.cpp
HTS_SHA256_Bridge.cpp
HTS_Sparse_Recovery.cpp
HTS_Tamper_HAL.cpp
HTS_TRNG_Collector.cpp
HTS_Tx_Scheduler.cpp
HTS_Unified_Scheduler.cpp
HTS_Universal_Adapter.cpp
HTS_Universal_API.cpp
HTS_V400_Dispatcher.cpp
HTS_Voice_Codec_Bridge.cpp
HTS64_Native_ECCM_Core.cpp
KISA_HMAC.c
KISA_SHA256.c
lea_base.c
lea_core.c
lea_gcm_generic.c
lea_online.c
lea_t_fallback.c
lea_t_generic.c
lsh.c
lsh256.c
lsh512.c
util.c
```

### 8-8. `HTS_LIM.vcxproj.filters` (IDE)

Layer 15·16 모듈은 필터 `Layer 15 - AMI OTA`, `Layer 16 - IoT Sensor`에 묶여 있다. TU 추가 시 동일 필터 규칙을 따른다.

### 8-9. §2 최우선 스캔(17+4) × 레이어 검수 힌트

파일 1-Pass 시 아래 **우선 레이어**부터 해당 항목을 스캔하면 누락을 줄인다. (항목은 전 레이어에 적용될 수 있음 — 힌트는 **집중도**이다.)

| 항목 | 검수 집중 레이어 (힌트) |
|------|-------------------------|
| ① 배리어 | 전 레이어 — Secure Wipe·KAT 소거 MSVC `seq_cst` **유지** (§8-4) |
| ② std::abs | 8, 9, 10, 16 (PHY·텐서·FEC·센서 산술) |
| ③ 힙 | 전 `.cpp` — ARM 경로 `new`/`vector`/`string` 금지, **placement new**만 |
| ④ double | 3, 8, 9, 10, 16 |
| ⑤ 예외 | 전 `.cpp` |
| ⑥ 스택 | 전 `.cpp` — 512B+ 로컬 배열 |
| ⑦ 주석 | 전 파일 (§6 BUG 이력 규칙) |
| ⑧ Pimpl SRAM | 15~16 다수, 14 일부 — `static_assert(sizeof(Impl)≤…)` |
| ⑨ 나눗셈 | 8~11, 16 |
| ⑩ Zero-copy | 전 공개 API |
| ⑪ 엔디안 | 14, 15, 16 (프로토콜·페이로드) |
| ⑫ 캐스팅 | 전 `.cpp` |
| ⑬ CFI | 10, 11, 14, 15 (OTA·라우터·상태기) |
| ⑭ PC 헤더 | 7, 17 |
| ⑮ 타임아웃 | 1, 14, TRNG 등 HW 폴링 |
| ⑯ 플래시 | 5, 15 (부팅·OTA) |
| ⑰ NVIC/ISR | 1, 6, 14 |
| A sizeof | 대형 정적 버퍼 TU (텐서·버퍼 모듈) |
| B 래퍼 | 동일 |
| C CAS | 12 세션, **17** `HTS_API` 초기화 등 |
| D `[[likely]]` | 17 (`HTS_LIKELY` 매크로) |

### 8-10. Layer 15~17 대조 체크 (섹션 3 ≡ §8-2)

- [ ] Layer 15의 6개 `ClCompile`이 §8-7 목록에 모두 존재
- [ ] `HTS_OTA_AMI_Manager` 전용 `*_Defs.h` 없음 — 섹션 3에 Defs 미기재 **정상**
- [ ] Layer 16 `Sensor_*` / `Gyro` / `Location` / `Emergency` — Defs 없음 **정상**
- [ ] Layer 17 `HTS_Universal_API.def`가 프로젝트 `None`에 등록, `.cpp`와 쌍 검수

### 8-11. SRAM·Flash 산출 — `.map` / `size` (vcxproj와의 관계)

**전제:** `HTS_LIM.vcxproj`는 **정적 라이브러리(`StaticLibrary`)** 이다. `HTS_LIM_V3.lib`만 빌드하면 **링커가 최종 이미지를 만들지 않으므로** RAM 합계·`.map` 파일은 **기본적으로 생성되지 않는다.** Cortex-M4용 **실제 SRAM 사용량**은 `HTS_LIM` 오브젝트를 끌어다 쓰는 **보드 앱(펌웨어) 프로젝트의 최종 링크**에서 확정한다.

| 도구체인 | 산출물 | 명령 / 설정 (요지) |
|----------|--------|---------------------|
| **GNU Arm Embedded** (`arm-none-eabi-*`) | 링커 맵 | 최종 링크에 `-Wl,-Map=firmware.map` (경로는 툴체인 규약에 맞출 것) |
| ↑ 동일 | 섹션 크기 | `arm-none-eabi-size -A -d firmware.elf` — `.text` / `.data` / `.bss` 등 |
| **Keil µVision** | `.map` | Project → Options for Target → Listing → **Linker Listing** 에서 map 생성 |
| **IAR EWARM** | `.map` | Linker → List → **Generate map file** |
| **MSVC (호스트 Win32/x64)** | `.map` | **실행 파일(.exe)** 링크하는 프로젝트에서만 의미 있음. 링커 `/MAP` 또는 속성 **Linker → Debugging → Generate Map File** (버전에 따라 명칭 상이). **`HTS_LIM` 정적 라이브러리 단독 빌드에는 적용되지 않음.** |

**정적 추정:** 각 TU의 `IMPL_BUF_SIZE`·헤더 주석 `sizeof`·대형 `constexpr` ROM 테이블은 코드 검색으로 **상한**을 잡을 수 있다. §0-3 **메인 SRAM 112KB / CCM 64KB**와 대조할 때는 **동시에 상주하는 전역 인스턴스**와 **FEC `RxState64` 등 스택 배치 금지 대상**을 함께 검토한다. **FEC/HARQ RAM 절감 우선순위·트레이드오프**는 `HTS_FEC_HARQ.hpp` 상단 `[메모리 절감 대책]` 블록과 동기화한다.

**요약:** “전체 코드 RAM” 질문에 답하려면 **M4 앱 링크 한 번**에서 나온 **`.map` + `size`** 를 기준으로 삼는다 — `HTS_LIM.vcxproj`만으로는 수치가 완결되지 않으며, 본 절은 그 간극을 문서·프로젝트 주석과 맞춘 것이다.

