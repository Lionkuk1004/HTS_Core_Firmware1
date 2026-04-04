// =========================================================================
// HTS_TimeSpace_Guard.h
// 시공간 기만(크로노스 스푸핑) · 슬라이딩 리플레이 윈도우 — 세션/IPC 경계용 경량 가드
// Target: STM32F407 (Cortex-M4) / 호스트 검증
//
// @note Session_Gateway·IPC·CoAP 등 상위 바인딩에서 인스턴스를 두고,
//       수신 시퀀스·RTC/동기 시각을 Feed 한다. 힙 0, 가상 함수 0.
// =========================================================================
#pragma once

#include <cstdint>

namespace ProtectedEngine {

    /// @brief uint32_t 시퀀스 슬라이딩 윈도우(폭 64) — 중복·낡은 SEQ O(1) 기각
    class AntiReplayWindow64 final {
    public:
        /// @brief 상태 초기화(세션 리셋·크로노스 이상 시 호출)
        void Reset() noexcept
        {
            largest_ = 0u;
            bitmap_ = 0u;
            initialized_ = false;
        }

        /// @brief SEQ 수락 시 true, 리플레이/윈도우 밖이면 false (상태 불변)
        [[nodiscard]] bool AcceptSeq(uint32_t seq) noexcept
        {
            if (!initialized_) {
                largest_ = seq;
                bitmap_ = 1ull;
                initialized_ = true; 
                return true;
            }
            if (seq > largest_) {
                const uint32_t delta = seq - largest_;
                if (delta >= 64u) {
                    largest_ = seq;
                    bitmap_ = 1ull;
                    return true;
                }
                bitmap_ <<= delta;
                largest_ = seq;
                bitmap_ |= 1ull;
                return true;
            }
            const uint32_t diff = largest_ - seq;
            if (diff >= 64u) {
                return false;
            }
            const uint64_t bit = 1ull << static_cast<uint32_t>(diff);
            if ((bitmap_ & bit) != 0ull) {
                return false;
            }
            bitmap_ |= bit;
            return true;
        }

    private:
        uint32_t largest_ = 0u;
        uint64_t bitmap_ = 0u;
        bool     initialized_ = false;
    };

    /// @brief uint64_t 단조 벽시계(ms) — 비정상 역행·미래 널뛰기 감지 시 false
    class ChronosAnomalyGuardU64 final {
    public:
        /// 역행이 이 값(ms) 초과면 이상(기본: 약 4년)
        static constexpr uint64_t kMaxBackwardJumpMs =
            86400000ULL * 365ULL * 4ULL;
        /// 순행이 이 값(ms) 초과면 이상(기본: 약 15년)
        static constexpr uint64_t kMaxForwardJumpMs =
            86400000ULL * 365ULL * 15ULL;

        void Reset() noexcept
        {
            last_ms_ = 0u;
            have_last_ = false;
        }

        /// @return false 이면 호출측에서 세션·리플레이 윈도우 소거 권장
        [[nodiscard]] bool FeedMonotonicWallMs(uint64_t wall_ms) noexcept
        {
            if (!have_last_) {
                last_ms_ = wall_ms;
                have_last_ = true;
                return true;
            }
            if (wall_ms >= last_ms_) {
                const uint64_t fwd = wall_ms - last_ms_;
                if (fwd > kMaxForwardJumpMs) {
                    have_last_ = false;
                    return false;
                }
            }
            else {
                const uint64_t back = last_ms_ - wall_ms;
                if (back > kMaxBackwardJumpMs) {
                    have_last_ = false;
                    return false;
                }
            }
            last_ms_ = wall_ms;
            return true;
        }

    private:
        uint64_t last_ms_ = 0u;
        bool     have_last_ = false;
    };

} // namespace ProtectedEngine
