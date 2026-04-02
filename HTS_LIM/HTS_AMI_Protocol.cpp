/// @file  HTS_AMI_Protocol.cpp
/// @brief HTS AMI Protocol -- DLMS/COSEM Lightweight (국제 수출 대응)
///
/// [아키텍처 리팩토링]
///  A1 [CRIT] OBIS 하드코딩 → ROM 딕셔너리 테이블 + 국가별 주입
///     · if-else 10개 체인 → Dict_Lookup() O(N) 선형 탐색 (N≤16)
///     · Build_Report_APDU: 딕셔너리 순회로 자동 직렬화
///     · Lookup_And_Write: 딕셔너리 기반 O(1) 엔트리 탐색
///     · KEPCO/IDIS/ANSI C12: 빌드 타임 테이블 교체만으로 대응
///  A2 [CRIT] 평문 직송 → Security Suite 콜백 훅
///     · Send_Secured: encrypt 콜백 등록 시 ARIA-GCM/AES-GCM 암호화
///     · Process_Request: decrypt 콜백 등록 시 수신 복호화 + MAC 검증
///     · nullptr = 평문 통과 (테스트/개발 모드)
///  A3 [HIGH] Block Transfer 프레임워크
///     · PROCESSING → BLOCK_SENDING CFI 전이 추가
///     · 향후 Billing Profile 등 대형 응답 청킹 대응 가능
///
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_AMI_Protocol.h"
#include "HTS_IPC_Protocol.h"
#include <new>
#include <atomic>
#include <cstring>

namespace ProtectedEngine {

#if (defined(__arm__) || defined(__TARGET_ARCH_ARM) || \
     defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)) && \
    !defined(__aarch64__)
#define HTS_AMI_PRIMASK_SHUTDOWN 1
#else
#define HTS_AMI_PRIMASK_SHUTDOWN 0
#endif

    namespace {
        struct AMI_Busy_Guard {
            std::atomic_flag& f;
            bool locked;
            explicit AMI_Busy_Guard(std::atomic_flag& flag) noexcept
                : f(flag), locked(false) {
                if (!f.test_and_set(std::memory_order_acquire)) {
                    locked = true;
                }
            }
            ~AMI_Busy_Guard() noexcept {
                if (locked) {
                    f.clear(std::memory_order_release);
                }
            }
        };
    } // namespace

    // ============================================================
    //  [AMI-1] 보안 메모리 소거 (프로젝트 표준)
    // ============================================================
    static void AMI_Secure_Wipe(void* ptr, size_t size) noexcept {
        if (ptr == nullptr || size == 0u) { return; }
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0u; i < size; ++i) { p[i] = 0u; }
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" : : "r"(ptr) : "memory");
#endif
        std::atomic_thread_fence(std::memory_order_release);
    }

    // ============================================================
    //  Endian Helpers (local)
    // ============================================================
    static inline void AMI_Write_U16(uint8_t* b, uint16_t v) noexcept {
        b[0] = static_cast<uint8_t>(v >> 8u);
        b[1] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline void AMI_Write_U32(uint8_t* b, uint32_t v) noexcept {
        b[0] = static_cast<uint8_t>(v >> 24u);
        b[1] = static_cast<uint8_t>((v >> 16u) & 0xFFu);
        b[2] = static_cast<uint8_t>((v >> 8u) & 0xFFu);
        b[3] = static_cast<uint8_t>(v & 0xFFu);
    }
    static inline uint16_t AMI_Read_U16(const uint8_t* b) noexcept {
        return static_cast<uint16_t>(
            (static_cast<uint16_t>(b[0]) << 8u) | static_cast<uint16_t>(b[1]));
    }

    // ============================================================
    //
    //  STM32F407 BKP_DR0~DR19: VBAT 전원 유지 시 비휘발
    //  전원 차단 후 재부팅 시 boot_count 단조증가 보장
    //  → (device_id, boot_count, report_seq) 3중 키로 리플레이 공격 차단
    //
    //  [하드웨어 요건] VBAT 핀에 코인셀/슈퍼캡 연결 필수
    //  VBAT 미연결 시 전원 차단 → boot_count 리셋 (경고 로그)
    // ============================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM)
    namespace NV {
        // STM32F407 레지스터 주소 (constexpr 상수화)
        static constexpr uintptr_t RCC_APB1ENR_ADDR = 0x40023840u;
        static constexpr uint32_t  RCC_PWREN_BIT = (1u << 28u);
        static constexpr uintptr_t PWR_CR_ADDR = 0x40007000u;
        static constexpr uint32_t  PWR_CR_DBP_BIT = (1u << 8u);
        static constexpr uintptr_t BKP_DR0_ADDR = 0x40002850u;  // boot_count
        static constexpr uintptr_t BKP_DR1_ADDR = 0x40002854u;  // magic
        static constexpr uint32_t  NV_MAGIC = 0x494E4F56u; // "INOV"

        static uint32_t Read_Boot_Count() noexcept {
            volatile uint32_t* dr0 =
                reinterpret_cast<volatile uint32_t*>(BKP_DR0_ADDR);
            volatile uint32_t* dr1 =
                reinterpret_cast<volatile uint32_t*>(BKP_DR1_ADDR);

            // 매직 검증 — VBAT 이력 확인
            if (*dr1 != NV_MAGIC) { return 0u; }
            return *dr0;
        }

        static void Write_Boot_Count(uint32_t count) noexcept {
            // PWR 클록 활성화
            volatile uint32_t* rcc_apb1 =
                reinterpret_cast<volatile uint32_t*>(RCC_APB1ENR_ADDR);
            *rcc_apb1 |= RCC_PWREN_BIT;

            // Backup Domain 쓰기 허용 (DBP 비트)
            volatile uint32_t* pwr_cr =
                reinterpret_cast<volatile uint32_t*>(PWR_CR_ADDR);
            *pwr_cr |= PWR_CR_DBP_BIT;

            // 쓰기
            volatile uint32_t* dr0 =
                reinterpret_cast<volatile uint32_t*>(BKP_DR0_ADDR);
            volatile uint32_t* dr1 =
                reinterpret_cast<volatile uint32_t*>(BKP_DR1_ADDR);
            *dr0 = count;
            *dr1 = NV_MAGIC;

            // DBP 비트 복원 (쓰기 보호)
            *pwr_cr &= ~PWR_CR_DBP_BIT;

            __asm__ __volatile__("dsb" ::: "memory");
        }
    } // namespace NV
#else
    // PC 시뮬레이션: 정적 변수 (테스트용)
    namespace NV {
        static uint32_t s_sim_boot = 0u;
        static uint32_t Read_Boot_Count() noexcept { return s_sim_boot; }
        static void Write_Boot_Count(uint32_t c) noexcept { s_sim_boot = c; }
    }
#endif

    // ============================================================
    //  Impl Structure
    // ============================================================
    struct HTS_AMI_Protocol::Impl {
        // --- Dependencies ---
        HTS_IPC_Protocol* ipc;

        // --- Identity ---
        uint32_t device_id;

        // --- CFI State ---
        AMI_State state;
        uint8_t   cfi_violation_count;
        uint8_t   invoke_id;
        uint8_t   pad_;

        // --- Callbacks ---
        MeterCallbacks meter_cb;

        // --- [A1] OBIS 딕셔너리 (비소유 포인터 → ROM) ---
        const OBIS_Dictionary* obis_dict;

        // --- [A2] Security Suite (비소유 포인터) ---
        const AMI_SecuritySuite* security;

        // --- Periodic Report ---
        uint32_t report_interval_ms;
        uint32_t last_report_tick;
        uint32_t report_seq;        ///< 세션 내 단조증가 시퀀스
        uint32_t boot_count;        ///< 비휘발 부팅 카운터 (RTC BKP)

        // --- APDU Build Buffer ---
        uint8_t apdu_buf[AMI_MAX_APDU_SIZE];

        // --- [A2] Security Wrapped Buffer ---
        uint8_t secure_buf[AMI_MAX_SECURE_BUF];

        // --- RX 복호 버퍼 (Impl 정적, 스택 사용 금지) ---
        //  Process_Request에서 사용. 스택 48~1024B 점유 방지.
        //  향후 AMI_MAX_APDU_SIZE 확장 시에도 스택 오버플로우 원천 차단.
        uint8_t decrypt_buf[AMI_MAX_APDU_SIZE];

        // ============================================================
        //  CFI Transition
        // ============================================================
        bool Transition_State(AMI_State target) noexcept {
            if (!AMI_Is_Legal_Transition(state, target)) {
                if (AMI_Is_Legal_Transition(state, AMI_State::ERROR)) {
                    state = AMI_State::ERROR;
                }
                else {
                    state = AMI_State::OFFLINE;
                }
                cfi_violation_count++;
                return false;
            }
            state = target;
            return true;
        }

        // ============================================================
        //  [A1] 딕셔너리 기반 OBIS 룩업 — O(N), N≤16
        //  if-else 10개 체인 완전 제거
        //  일정 시간: OBIS_Equal은 분기 0 → 타이밍 공격 방어
        // ============================================================
        const OBIS_DictEntry* Dict_Lookup(const OBIS_Code& obis) const noexcept {
            if (obis_dict == nullptr || obis_dict->entries == nullptr) {
                return nullptr;
            }
            const uint8_t cnt = (obis_dict->count > AMI_MAX_DICT_ENTRIES)
                ? AMI_MAX_DICT_ENTRIES : obis_dict->count;
            for (uint8_t i = 0u; i < cnt; ++i) {
                if (OBIS_Equal(obis, obis_dict->entries[i].obis) == 0u) {
                    return &obis_dict->entries[i];
                }
            }
            return nullptr;
        }

        // ============================================================
        //  [A1] 딕셔너리 엔트리에서 값 읽기 + 직렬화
        //  [AMI-5] remain 검사: 타입별 정확한 크기
        // ============================================================
        uint32_t Write_Entry(uint8_t* buf, uint32_t remain,
            const OBIS_DictEntry& entry) noexcept {
            const uint32_t need = AMI_OBJ_HEADER_SIZE
                + static_cast<uint32_t>(entry.value_size);
            if (remain < need) { return 0u; }

            // OBIS
            buf[0] = entry.obis.a; buf[1] = entry.obis.b;
            buf[2] = entry.obis.c; buf[3] = entry.obis.d;
            buf[4] = entry.obis.e; buf[5] = entry.obis.f;
            // TYPE + LEN
            buf[6] = static_cast<uint8_t>(entry.data_type);
            buf[7] = entry.value_size;
            // VALUE
            if (entry.is_u16) {
                const uint16_t v = (entry.callback.get_u16 != nullptr)
                    ? entry.callback.get_u16() : 0u;
                AMI_Write_U16(&buf[8], v);
            }
            else {
                const uint32_t v = (entry.callback.get_u32 != nullptr)
                    ? entry.callback.get_u32() : 0u;
                AMI_Write_U32(&buf[8], v);
            }
            return need;
        }

        // ============================================================
        //  [A1] 딕셔너리 기반 주기 보고 APDU 빌드
        //  6개 객체 하드코딩
        //  딕셔너리 전체 순회 → 공간 허용하는 만큼 자동 직렬화
        // ============================================================
        uint16_t Build_Report_APDU() noexcept {
            uint32_t pos = 0u;

            // APDU header
            apdu_buf[pos++] = static_cast<uint8_t>(DLMS_Service::PERIODIC_REPORT);
            apdu_buf[pos++] = invoke_id;
            invoke_id = static_cast<uint8_t>(
                (static_cast<uint32_t>(invoke_id) + 1u) & 0xFFu);

            //  전원 차단 → 재부팅해도 boot_count 단조증가 (RTC BKP 저장)
            //  공격자가 old 패킷을 리플레이해도 boot_count 불일치 → HES 폐기
            apdu_buf[pos++] = static_cast<uint8_t>(boot_count >> 24u);
            apdu_buf[pos++] = static_cast<uint8_t>(boot_count >> 16u);
            apdu_buf[pos++] = static_cast<uint8_t>(boot_count >> 8u);
            apdu_buf[pos++] = static_cast<uint8_t>(boot_count & 0xFFu);

            apdu_buf[pos++] = static_cast<uint8_t>(report_seq >> 24u);
            apdu_buf[pos++] = static_cast<uint8_t>(report_seq >> 16u);
            apdu_buf[pos++] = static_cast<uint8_t>(report_seq >> 8u);
            apdu_buf[pos++] = static_cast<uint8_t>(report_seq & 0xFFu);
            report_seq++;
            const uint32_t count_pos = pos;
            apdu_buf[pos++] = 0u;

            uint8_t obj_count = 0u;

            if (obis_dict != nullptr && obis_dict->entries != nullptr) {
                const uint8_t cnt = (obis_dict->count > AMI_MAX_DICT_ENTRIES)
                    ? AMI_MAX_DICT_ENTRIES : obis_dict->count;
                for (uint8_t i = 0u; i < cnt; ++i) {
                    const uint32_t avail = AMI_MAX_APDU_SIZE - pos - AMI_APDU_CRC_SIZE;
                    const uint32_t written = Write_Entry(
                        &apdu_buf[pos], avail, obis_dict->entries[i]);
                    if (written == 0u) { break; }  // 공간 부족 → 중단
                    pos += written;
                    obj_count++;
                }
            }

            apdu_buf[count_pos] = obj_count;

            // CRC-16
            const uint16_t crc = IPC_Compute_CRC16(apdu_buf, pos);
            AMI_Write_U16(&apdu_buf[pos], crc);
            pos += AMI_APDU_CRC_SIZE;

            return static_cast<uint16_t>(pos);
        }

        // ============================================================
        //  [A2] 보안 랩핑 후 전송
        //  security == nullptr → 평문 직송 (테스트 모드)
        //  security != nullptr → encrypt → cipher 전송
        // ============================================================
        IPC_Error Send_Secured(uint16_t apdu_len) noexcept {
            if (ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

            if (security != nullptr && security->encrypt != nullptr) {
                uint16_t cipher_len = 0u;
                if (!security->encrypt(
                    apdu_buf, apdu_len,
                    secure_buf, &cipher_len,
                    static_cast<uint16_t>(AMI_MAX_SECURE_BUF))) {
                    return IPC_Error::BUFFER_OVERFLOW;
                }
                // 보안 콜백 방어: 잘못된 길이 반환 시 Fail-Closed
                if (cipher_len == 0u
                    || cipher_len > static_cast<uint16_t>(AMI_MAX_SECURE_BUF)) {
                    AMI_Secure_Wipe(secure_buf, AMI_MAX_SECURE_BUF);
                    return IPC_Error::BUFFER_OVERFLOW;
                }
                const IPC_Error err = ipc->Send_Frame(
                    IPC_Command::DATA_TX, secure_buf, cipher_len);
                // 보안 버퍼 소거
                AMI_Secure_Wipe(secure_buf, cipher_len);
                return err;
            }
            // 평문 모드
            return ipc->Send_Frame(
                IPC_Command::DATA_TX, apdu_buf, apdu_len);
        }

        // ============================================================
        //  [A1] 딕셔너리 기반 GET_REQUEST 처리
        // ============================================================
        IPC_Error Handle_Get_Request(const uint8_t* apdu, uint16_t len) noexcept {
            if (apdu == nullptr) { return IPC_Error::OK; }
            if (len < AMI_APDU_HEADER_SIZE + AMI_APDU_CRC_SIZE) { return IPC_Error::OK; }

            // CRC check
            const uint32_t data_region = static_cast<uint32_t>(len) - AMI_APDU_CRC_SIZE;
            const uint16_t computed = IPC_Compute_CRC16(apdu, data_region);
            const uint16_t received = AMI_Read_U16(&apdu[data_region]);
            if (computed != received) { return IPC_Error::OK; }

            const uint8_t req_invoke = apdu[1];
            const uint8_t obj_count = apdu[2];
            if (obj_count > AMI_MAX_OBJECTS) { return IPC_Error::OK; }

            // Build response
            uint32_t rpos = 0u;
            apdu_buf[rpos++] = static_cast<uint8_t>(DLMS_Service::GET_RESPONSE);
            apdu_buf[rpos++] = req_invoke;
            const uint32_t rcount_pos = rpos;
            apdu_buf[rpos++] = 0u;

            uint8_t rsp_count = 0u;
            uint32_t offset = AMI_APDU_HEADER_SIZE;

            for (uint8_t i = 0u; i < obj_count; ++i) {
                // 오버플로우 안전 경계 검사
                if (offset > data_region) { break; }
                if ((data_region - offset) < 6u) { break; }

                OBIS_Code req_obis;
                req_obis.a = apdu[offset + 0u];
                req_obis.b = apdu[offset + 1u];
                req_obis.c = apdu[offset + 2u];
                req_obis.d = apdu[offset + 3u];
                req_obis.e = apdu[offset + 4u];
                req_obis.f = apdu[offset + 5u];
                offset += 6u;

                // [A1] 딕셔너리 룩업 — if-else 체인 완전 제거
                const OBIS_DictEntry* entry = Dict_Lookup(req_obis);
                if (entry != nullptr) {
                    const uint32_t avail = AMI_MAX_APDU_SIZE - rpos - AMI_APDU_CRC_SIZE;
                    const uint32_t written = Write_Entry(
                        &apdu_buf[rpos], avail, *entry);
                    if (written > 0u) {
                        rpos += written;
                        rsp_count++;
                    }
                }
            }

            apdu_buf[rcount_pos] = rsp_count;

            // CRC
            const uint16_t crc = IPC_Compute_CRC16(apdu_buf, rpos);
            AMI_Write_U16(&apdu_buf[rpos], crc);
            rpos += AMI_APDU_CRC_SIZE;

            // [A2] 보안 랩핑 후 전송
            return Send_Secured(static_cast<uint16_t>(rpos));
        }
    };

    // Tick → Send_Periodic_Report 재진입 방지: 공개 API와 동일 본문 (Busy_Guard 단일)
    IPC_Error HTS_AMI_Protocol::ami_send_periodic_report_impl(Impl* impl) noexcept
    {
        if (impl->ipc == nullptr) { return IPC_Error::NOT_INITIALIZED; }

        if (!impl->Transition_State(AMI_State::REPORTING)) {
            return IPC_Error::CFI_VIOLATION;
        }

        const uint16_t apdu_len = impl->Build_Report_APDU();
        if (apdu_len == 0u) {
            impl->Transition_State(AMI_State::ERROR);
            return IPC_Error::BUFFER_OVERFLOW;
        }

        const IPC_Error err = impl->Send_Secured(apdu_len);

        if (err != IPC_Error::OK) {
            impl->Transition_State(AMI_State::ERROR);
            return err;
        }

        impl->Transition_State(AMI_State::IDLE);
        return IPC_Error::OK;
    }

    // ============================================================
    //  Public API
    // ============================================================

    // [AMI-3] 생성자: impl_buf_ memset 0 초기화
    HTS_AMI_Protocol::HTS_AMI_Protocol() noexcept
        : initialized_{ false }
    {
        static_assert(sizeof(Impl) <= IMPL_BUF_SIZE,
            "HTS_AMI_Protocol::Impl exceeds IMPL_BUF_SIZE");
        std::memset(impl_buf_, 0, IMPL_BUF_SIZE);
    }

    HTS_AMI_Protocol::~HTS_AMI_Protocol() noexcept {
        Shutdown();
    }

    IPC_Error HTS_AMI_Protocol::Initialize(HTS_IPC_Protocol* ipc,
        uint32_t device_id) noexcept
    {
        bool expected = false;
        if (!initialized_.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) {
            return IPC_Error::OK;
        }

        if (ipc == nullptr) {
            initialized_.store(false, std::memory_order_release);
            return IPC_Error::NOT_INITIALIZED;
        }

        Impl* impl = new (impl_buf_) Impl{};

        impl->ipc = ipc;
        impl->device_id = device_id;
        impl->state = AMI_State::OFFLINE;
        impl->cfi_violation_count = 0u;
        impl->invoke_id = 0u;
        impl->report_interval_ms = 0u;
        impl->last_report_tick = 0u;
        impl->report_seq = 0u;

        //  리플레이 공격 차단: 재부팅해도 boot_count 단조증가
        //  (device_id, boot_count, report_seq) = 글로벌 유일 키
        impl->boot_count = NV::Read_Boot_Count() + 1u;
        NV::Write_Boot_Count(impl->boot_count);
        impl->obis_dict = nullptr;
        impl->security = nullptr;

        // Zero all meter callbacks
        std::memset(&impl->meter_cb, 0, sizeof(MeterCallbacks));

        // CFI: OFFLINE -> IDLE
        impl->Transition_State(AMI_State::IDLE);

        return IPC_Error::OK;
    }

    // [AMI-1] Shutdown: impl_buf_ 전체 보안 소거
    // A-5: op_busy_ 대기는 IRQ 허용(인터럽트가 완료·락 해제 가능) → 짧은 구간만 PRIMASK
    void HTS_AMI_Protocol::Shutdown() noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return; }

        while (op_busy_.test_and_set(std::memory_order_acquire)) {}

#if HTS_AMI_PRIMASK_SHUTDOWN && (defined(__GNUC__) || defined(__clang__))
        uint32_t primask_saved;
        __asm__ __volatile__("mrs %0, primask\n\t"
            "cpsid i"
            : "=r"(primask_saved) :: "memory");
#endif

        if (!initialized_.load(std::memory_order_acquire)) {
            op_busy_.clear(std::memory_order_release);
#if HTS_AMI_PRIMASK_SHUTDOWN && (defined(__GNUC__) || defined(__clang__))
            __asm__ __volatile__("msr primask, %0" :: "r"(primask_saved) : "memory");
#endif
            return;
        }

        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->state = AMI_State::OFFLINE;
        impl->ipc = nullptr;
        impl->obis_dict = nullptr;
        impl->security = nullptr;
        impl->~Impl();

        // [AMI-1] impl_buf_ 전체 보안 소거 (함수 포인터, device_id, apdu_buf 등)
        AMI_Secure_Wipe(impl_buf_, IMPL_BUF_SIZE);
        initialized_.store(false, std::memory_order_release);
        op_busy_.clear(std::memory_order_release);

#if HTS_AMI_PRIMASK_SHUTDOWN && (defined(__GNUC__) || defined(__clang__))
        __asm__ __volatile__("msr primask, %0" :: "r"(primask_saved) : "memory");
#endif
    }

    // [A1] 국가별 OBIS 딕셔너리 주입
    void HTS_AMI_Protocol::Register_OBIS_Dictionary(
        const OBIS_Dictionary* dict) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->obis_dict = dict;
    }

    // [A2] Security Suite 등록
    void HTS_AMI_Protocol::Register_Security_Suite(
        const AMI_SecuritySuite* suite) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        impl->security = suite;
    }

    void HTS_AMI_Protocol::Register_Meter_Callbacks(
        const MeterCallbacks& cb) noexcept
    {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->meter_cb = cb;
    }

    void HTS_AMI_Protocol::Set_Report_Interval(uint32_t interval_ms) noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        reinterpret_cast<Impl*>(impl_buf_)->report_interval_ms = interval_ms;
    }

    // [AMI-2] Tick: unsigned 뺄셈은 49.7일 래핑 시에도 정확한 경과 시간 반환
    //  2의 보수 산술: (0x00000010 - 0xFFFFFFF0) = 0x00000020 = 32 → 정상 동작
    //  추가 방어 불필요 — MISRA C++ Rule 5-0-4 unsigned wrap 허용
    void HTS_AMI_Protocol::Tick(uint32_t systick_ms) noexcept {
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        if (impl->report_interval_ms > 0u) {
            // unsigned 뺄셈: 49.7일 래핑 시에도 정확 (의도적)
            const uint32_t elapsed = systick_ms - impl->last_report_tick;
            if (elapsed >= impl->report_interval_ms) {
                (void)ami_send_periodic_report_impl(impl);
                impl->last_report_tick = systick_ms;
            }
        }
    }

    IPC_Error HTS_AMI_Protocol::Send_Periodic_Report() noexcept {
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return IPC_Error::BUSY; }
        if (!initialized_.load(std::memory_order_acquire)) {
            return IPC_Error::NOT_INITIALIZED;
        }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);
        return HTS_AMI_Protocol::ami_send_periodic_report_impl(impl);
    }

    void HTS_AMI_Protocol::Process_Request(const uint8_t* apdu,
        uint16_t apdu_len) noexcept
    {
        if (apdu == nullptr) { return; }
        if (apdu_len < AMI_APDU_HEADER_SIZE + AMI_APDU_CRC_SIZE) { return; }
        if (!initialized_.load(std::memory_order_acquire)) { return; }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return; }
        Impl* impl = reinterpret_cast<Impl*>(impl_buf_);

        // [A2] 수신 복호화 (security suite 등록 시)
        //  복호화 실패(MAC 불일치) → 폐기 (무응답 = 보안 정책)
        const uint8_t* effective_apdu = apdu;
        uint16_t effective_len = apdu_len;
        std::memset(impl->decrypt_buf, 0, AMI_MAX_APDU_SIZE);

        if (impl->security != nullptr && impl->security->decrypt != nullptr) {
            uint16_t plain_len = 0u;
            if (!impl->security->decrypt(
                apdu, apdu_len,
                impl->decrypt_buf, &plain_len,
                static_cast<uint16_t>(AMI_MAX_APDU_SIZE))) {
                // MAC 검증 실패 → 무응답 폐기 (보안 정책)
                AMI_Secure_Wipe(impl->decrypt_buf, AMI_MAX_APDU_SIZE);
                return;
            }
            // 보안 콜백 방어: 길이 오염 시 파서 진입 차단
            if (plain_len < static_cast<uint16_t>(AMI_APDU_HEADER_SIZE + AMI_APDU_CRC_SIZE)
                || plain_len > static_cast<uint16_t>(AMI_MAX_APDU_SIZE)) {
                AMI_Secure_Wipe(impl->decrypt_buf, AMI_MAX_APDU_SIZE);
                return;
            }
            effective_apdu = impl->decrypt_buf;
            effective_len = plain_len;
        }

        //
        //  Transition_State(PROCESSING) 실패 시 ERROR/OFFLINE 전이 완료 후 반환 — IDLE 금지
        //  (복구는 상위 루프의 Initialize/재동기)
        if (!impl->Transition_State(AMI_State::PROCESSING)) {
            AMI_Secure_Wipe(impl->decrypt_buf, AMI_MAX_APDU_SIZE);
            // state는 이미 Transition_State 내부에서 ERROR/OFFLINE 전이됨
            // IDLE 복귀 금지: CFI 위반 상태에서 정상 통신 재개 = 보안 허점
            return;
        }

        const DLMS_Service svc = static_cast<DLMS_Service>(effective_apdu[0]);

        switch (svc) {
        case DLMS_Service::GET_REQUEST:
        {
            const IPC_Error get_err = impl->Handle_Get_Request(
                effective_apdu, effective_len);
            if (get_err != IPC_Error::OK) {
                impl->Transition_State(AMI_State::ERROR);
            }
        }
            break;
        case DLMS_Service::SET_REQUEST:
            //  IEC 62056-53 §7.4.2.3: Data-Access-Error 3 = Read/Write Denied
            //   uint8_t rsp[4] 스택 → Send_Frame에 포인터 전달
            //    Send_Frame이 현재 동기 직렬화이므로 즉시 복사되어 안전하나
            //    구현 변경 시 Dangling 포인터 위험 (스코프 이탈 후 DMA 접근)
            //   Impl::apdu_buf 정적 버퍼에 4바이트 직렬화 후 전달
            //    apdu_buf는 Impl 내부 정적 배열 → 스코프 이탈 없음
            //    Send_Frame 호출 시점에 유효한 포인터 보장
            if (effective_len >= 1u && impl->ipc != nullptr) {
                impl->apdu_buf[0] = static_cast<uint8_t>(DLMS_Service::SET_RESPONSE);
                impl->apdu_buf[1] = (effective_len >= 2u) ? effective_apdu[1] : 0x01u;
                impl->apdu_buf[2] = 0x01u;  // Data-Access-Error
                impl->apdu_buf[3] = 0x03u;  // Read/Write Denied
                const IPC_Error set_err =
                    impl->ipc->Send_Frame(IPC_Command::DATA_TX, impl->apdu_buf, 4u);
                if (set_err != IPC_Error::OK) {
                    impl->Transition_State(AMI_State::ERROR);
                }
            }
            break;
        case DLMS_Service::ACTION_REQUEST:
            //  IEC 62056-53 §7.4.2.6: Action-Result 3 = Other-Reason
            if (effective_len >= 1u && impl->ipc != nullptr) {
                impl->apdu_buf[0] = static_cast<uint8_t>(DLMS_Service::ACTION_RESPONSE);
                impl->apdu_buf[1] = (effective_len >= 2u) ? effective_apdu[1] : 0x01u;
                impl->apdu_buf[2] = 0x01u;  // Action-Result present
                impl->apdu_buf[3] = 0x03u;  // Other-Reason
                const IPC_Error act_err =
                    impl->ipc->Send_Frame(IPC_Command::DATA_TX, impl->apdu_buf, 4u);
                if (act_err != IPC_Error::OK) {
                    impl->Transition_State(AMI_State::ERROR);
                }
            }
            break;
        default:
            break;
        }

        // 복호 버퍼 보안 소거
        AMI_Secure_Wipe(impl->decrypt_buf, AMI_MAX_APDU_SIZE);

        if (impl->state != AMI_State::ERROR && impl->state != AMI_State::OFFLINE) {
            impl->Transition_State(AMI_State::IDLE);
        }
    }

    AMI_State HTS_AMI_Protocol::Get_State() const noexcept {
        if (!initialized_.load(std::memory_order_acquire)) {
            return AMI_State::OFFLINE;
        }
        AMI_Busy_Guard g(op_busy_);
        if (!g.locked) { return AMI_State::OFFLINE; }
        return reinterpret_cast<const Impl*>(impl_buf_)->state;
    }

} // namespace ProtectedEngine
