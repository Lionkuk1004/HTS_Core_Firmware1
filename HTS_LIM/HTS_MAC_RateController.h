// =========================================================================
// HTS_MAC_RateController.h
// MAC 계층 포트 자동 감지 및 확산 코드 기어 변속 컨트롤러
// Target: STM32F407 (Cortex-M4, 168MHz)
//
// -------------------------------------------------------------------------
//  외주 업체 통합 가이드
// -------------------------------------------------------------------------
//
//  [목적]
//  마이크(I2S) / 센서(UART) 입력 포트를 자동 감지하여
//  보코더 전송 속도 + 확산 코드 길이(SF)를 자동 전환합니다.
//
//  [사용법]
//   MAC_RateController mac;
//   mac.Set_Dial_Speed(VocoderRate::RATE_2400_BPS);
//   mac.Auto_Detect_And_Route(InputPort::I2S_MIC_VOCODER);
//   uint32_t sf = mac.Calculate_Spreading_Factor();
//
//  [양산 수정 이력 — 6건]
//   BUG-01 [CRIT] <iostream> + std::cout 제거 (ARM/A55 빌드 불가)
//   BUG-02 [CRIT] double + std::log10 제거 (④ float/double 금지)
//   BUG-03 [CRIT] std::cout 6곳 → SecureLogger 또는 제거
//   BUG-04 [HIGH] noexcept 전체 추가
//   BUG-05 [MED]  런타임 나눗셈 → 룩업 테이블 (⑨ ALU 최적화)
//   BUG-06 [LOW]  Target 주석 추가
//
// =========================================================================
#pragma once
#include <cstdint>
#include <cstddef>

namespace ProtectedEngine {

    // [하드웨어 포트 정의] 데이터 입력 소스
    enum class InputPort : uint8_t {
        I2S_MIC_VOCODER = 0u,   ///< 마이크/음성 칩
        UART_SENSOR_AMI = 1u    ///< 센서/전력량계
    };

    // 보코더(음성) 전송 속도 단계
    enum class VocoderRate : uint32_t {
        RATE_100_BPS = 100u,  ///< 초저속 센서 텍스트 (50dB 극한 방어)
        RATE_1200_BPS = 1200u,  ///< 최장거리 생존 모드 (극한 방어)
        RATE_2400_BPS = 2400u,  ///< 전술 표준 모드 (36dB 기준)
        RATE_4800_BPS = 4800u,  ///< 고음질 모드
        RATE_9600_BPS = 9600u   ///< 최고음질 모드 (방어 최소)
    };

    class MAC_RateController {
    public:
        MAC_RateController() noexcept
            : current_rate_(VocoderRate::RATE_2400_BPS)
            , user_dial_setting_(VocoderRate::RATE_2400_BPS)
            , sensor_base_rate_(VocoderRate::RATE_100_BPS) {
        }

        // 복사/이동 허용 — 순수 값 타입 (키 소재 없음)

        /// @brief 관리자용 센서 기본 속도 설정 (단말기 설치 시 1회)
        void Set_Sensor_Base_Rate(VocoderRate target_rate) noexcept {
            sensor_base_rate_ = Normalize_Rate(target_rate);
        }

        /// @brief 사용자 다이얼 속도 변경 (음성 기준)
        void Set_Dial_Speed(VocoderRate new_rate) noexcept {
            const VocoderRate safe_rate = Normalize_Rate(new_rate);
            user_dial_setting_ = safe_rate;
            current_rate_ = safe_rate;
        }

        // =================================================================
        //  포트 자동 감지 및 기어 변속 (Auto-Routing)
        //
        //  I2S_MIC → 사용자 다이얼 속도
        //  UART_SENSOR → 관리자 설정 센서 속도
        // =================================================================
        void Auto_Detect_And_Route(InputPort source_port) noexcept {
            switch (source_port) {
            case InputPort::I2S_MIC_VOCODER:
                current_rate_ = user_dial_setting_;
                break;
            case InputPort::UART_SENSOR_AMI:
                current_rate_ = sensor_base_rate_;
                break;
            default:
                // 비정상 enum 주입(static_cast) 방어: 안전 저속 모드로 fail-closed
                current_rate_ = VocoderRate::RATE_100_BPS;
                break;
            }
        }

        [[nodiscard]]
        VocoderRate Get_Current_Rate() const noexcept {
            return current_rate_;
        }

        // =================================================================
        //  확산 코드 길이 계산
        //
        //  FIXED_CHIP_RATE(9830400) / rate = 고정 5가지 → 컴파일 타임 확정
        //  미정의 rate → 기본값 4096 (2400bps 기준) 폴백
        // =================================================================
        [[nodiscard]]
        uint32_t Calculate_Spreading_Factor() const noexcept {
            switch (current_rate_) {
            case VocoderRate::RATE_100_BPS:  return 98304u;  // 9830400/100
            case VocoderRate::RATE_1200_BPS: return  8192u;  // 9830400/1200
            case VocoderRate::RATE_2400_BPS: return  4096u;  // 9830400/2400
            case VocoderRate::RATE_4800_BPS: return  2048u;  // 9830400/4800
            case VocoderRate::RATE_9600_BPS: return  1024u;  // 9830400/9600
            default:                         return  4096u;  // 안전 폴백
            }
        }

        // =================================================================
        //  처리 이득 (Processing Gain) — 정수 dB 근사
        //
        //  PG_dB ≈ 10 × log2(SF) × 0.301 ≈ 3 × log2(SF)
        //  log2(SF) = 31 - CLZ(SF) (SF는 항상 2의 거듭제곱)
        //
        //  SF=98304 → 근사 50dB (실제 49.9)
        //  SF=4096  → 정확 36dB
        //  SF=1024  → 정확 30dB
        // =================================================================
        [[nodiscard]]
        uint32_t Get_Processing_Gain_dB_Approx() const noexcept {
            const uint32_t sf = Calculate_Spreading_Factor();
            if (sf == 0u) return 0u;
            // 룩업 (5가지 고정값이므로 정확한 값 반환)
            switch (sf) {
            case 98304u: return 50u;
            case  8192u: return 39u;
            case  4096u: return 36u;
            case  2048u: return 33u;
            case  1024u: return 30u;
            default:     return 36u;  // 폴백
            }
        }

    private:
        static constexpr VocoderRate Normalize_Rate(VocoderRate rate) noexcept {
            switch (rate) {
            case VocoderRate::RATE_100_BPS:
            case VocoderRate::RATE_1200_BPS:
            case VocoderRate::RATE_2400_BPS:
            case VocoderRate::RATE_4800_BPS:
            case VocoderRate::RATE_9600_BPS:
                return rate;
            default:
                // 비정상 enum 값(static_cast 주입) 방어
                return VocoderRate::RATE_2400_BPS;
            }
        }

        static constexpr uint32_t FIXED_CHIP_RATE = 9830400u;

        VocoderRate current_rate_;
        VocoderRate user_dial_setting_;
        VocoderRate sensor_base_rate_;
    };

} // namespace ProtectedEngine
