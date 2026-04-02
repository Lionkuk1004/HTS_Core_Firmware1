/// @file  HTS_IoT_Codec.cpp
/// @brief HTS IoT Codec -- Implementation
/// @note  ARM only. Pure ASCII. No PC/server code.
/// @author Lim Young-jun
/// @copyright INNOViD 2026. All rights reserved.

#include "HTS_IoT_Codec.h"
#include "HTS_Secure_Memory.h"

namespace ProtectedEngine {
    namespace {
        struct IoT_Codec_Busy_Guard final {
            std::atomic_flag* flag;
            uint32_t locked;
            explicit IoT_Codec_Busy_Guard(std::atomic_flag& f) noexcept
                : flag(&f), locked(HTS_IoT_Codec::SECURE_FALSE) {
                locked = (!flag->test_and_set(std::memory_order_acq_rel))
                    ? HTS_IoT_Codec::SECURE_TRUE
                    : HTS_IoT_Codec::SECURE_FALSE;
            }
            ~IoT_Codec_Busy_Guard() noexcept {
                if (locked == HTS_IoT_Codec::SECURE_TRUE) {
                    flag->clear(std::memory_order_release);
                }
            }
            IoT_Codec_Busy_Guard(const IoT_Codec_Busy_Guard&) = delete;
            IoT_Codec_Busy_Guard& operator=(const IoT_Codec_Busy_Guard&) = delete;
        };
    }

    // ============================================================
    //  Constructor
    // ============================================================

    HTS_IoT_Codec::HTS_IoT_Codec() noexcept
        : build_pos_(0u)
        , tlv_count_(0u)
        , frame_active_(false)
        , session_token_(0u)
    {
        for (uint32_t i = 0u; i < IOT_MAX_FRAME_SIZE; ++i) {
            build_buf_[i] = 0u;
        }
    }

    // ============================================================
    //  Begin_Frame
    // ============================================================

    uint32_t HTS_IoT_Codec::Begin_Frame(IoT_MsgType type, uint32_t device_id,
        uint32_t timestamp, uint32_t& out_session_token) noexcept
    {
        IoT_Codec_Busy_Guard guard(op_busy_);
        if (guard.locked != HTS_IoT_Codec::SECURE_TRUE) {
            out_session_token = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        }
        if (frame_active_) {
            out_session_token = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        }

        build_pos_ = 0u;
        tlv_count_ = 0u;

        if (IOT_FRAME_HEADER_SIZE > IOT_MAX_FRAME_SIZE) {
            out_session_token = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        }

        build_buf_[0] = static_cast<uint8_t>(type);
        Write_U32(&build_buf_[1], device_id);
        Write_U32(&build_buf_[5], timestamp);
        build_buf_[9] = 0u;

        build_pos_ = static_cast<uint16_t>(IOT_FRAME_HEADER_SIZE);
        frame_active_ = true;
        session_token_ = session_token_ * 0x9E3779B9u + 1u;
        if (session_token_ == 0u) {
            session_token_ = 1u;
        }
        out_session_token = session_token_;
        return HTS_IoT_Codec::SECURE_TRUE;
    }

    // ============================================================
    //  Add TLV Items
    // ============================================================

    uint32_t HTS_IoT_Codec::Add_U8(uint32_t session_token, SensorType sensor,
        uint8_t value) noexcept
    {
        return Add_Raw(session_token, sensor, &value, 1u);
    }

    uint32_t HTS_IoT_Codec::Add_U16(uint32_t session_token, SensorType sensor,
        uint16_t value) noexcept
    {
        uint8_t buf[2];
        Write_U16(buf, value);
        return Add_Raw(session_token, sensor, buf, 2u);
    }

    uint32_t HTS_IoT_Codec::Add_U32(uint32_t session_token, SensorType sensor,
        uint32_t value) noexcept
    {
        uint8_t buf[4];
        Write_U32(buf, value);
        return Add_Raw(session_token, sensor, buf, 4u);
    }

    uint32_t HTS_IoT_Codec::Add_Raw(uint32_t session_token, SensorType sensor,
        const uint8_t* data, uint8_t data_len) noexcept
    {
        IoT_Codec_Busy_Guard guard(op_busy_);
        if (guard.locked != HTS_IoT_Codec::SECURE_TRUE) {
            return HTS_IoT_Codec::SECURE_FALSE;
        }
        if (session_token != session_token_) {
            return HTS_IoT_Codec::SECURE_FALSE;
        }
        if (!frame_active_) { return HTS_IoT_Codec::SECURE_FALSE; }
        if (data == nullptr && data_len > 0u) { return HTS_IoT_Codec::SECURE_FALSE; }
        if (data_len > IOT_TLV_MAX_VALUE_SIZE) { return HTS_IoT_Codec::SECURE_FALSE; }
        if (tlv_count_ >= IOT_MAX_TLV_COUNT) { return HTS_IoT_Codec::SECURE_FALSE; }

        const uint32_t needed = IOT_TLV_HEADER_SIZE + static_cast<uint32_t>(data_len);
        const uint32_t remaining = IOT_MAX_FRAME_SIZE - static_cast<uint32_t>(build_pos_);
        if (needed + IOT_FRAME_CRC_SIZE > remaining) {
            return HTS_IoT_Codec::SECURE_FALSE;
        }

        const size_t base = static_cast<size_t>(build_pos_);
        const size_t hdr = static_cast<size_t>(IOT_TLV_HEADER_SIZE);
        build_buf_[base] = static_cast<uint8_t>(sensor);
        build_buf_[base + static_cast<size_t>(1u)] = data_len;
        for (uint8_t i = 0u; i < data_len; ++i) {
            build_buf_[base + hdr + static_cast<size_t>(i)] =
                data[static_cast<size_t>(i)];
        }

        build_pos_ = static_cast<uint16_t>(
            static_cast<uint32_t>(build_pos_) + needed);
        tlv_count_++;
        return HTS_IoT_Codec::SECURE_TRUE;
    }

    // ============================================================
    //  Finalize
    // ============================================================

    uint32_t HTS_IoT_Codec::Finalize(uint32_t session_token, uint8_t* out_buf,
        uint16_t out_buf_size, uint16_t& out_len) noexcept
    {
        IoT_Codec_Busy_Guard guard(op_busy_);
        if (guard.locked != HTS_IoT_Codec::SECURE_TRUE) {
            out_len = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        }

        out_len = 0u;
        if (session_token != session_token_) {
            return HTS_IoT_Codec::SECURE_FALSE;
        }
        if (!frame_active_) { return HTS_IoT_Codec::SECURE_FALSE; }
        if (out_buf == nullptr) {
            SecureMemory::secureWipe(static_cast<void*>(build_buf_), sizeof(build_buf_));
            build_pos_ = 0u;
            tlv_count_ = 0u;
            frame_active_ = false;
            session_token_ = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        }

        build_buf_[9] = tlv_count_;

        const uint32_t data_region = static_cast<uint32_t>(build_pos_);
        if (data_region + IOT_FRAME_CRC_SIZE > IOT_MAX_FRAME_SIZE) {
            frame_active_ = false;
            SecureMemory::secureWipe(static_cast<void*>(build_buf_), sizeof(build_buf_));
            build_pos_ = 0u;
            tlv_count_ = 0u;
            session_token_ = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        }

        const uint16_t crc = IPC_Compute_CRC16(build_buf_, data_region);
        Write_U16(&build_buf_[data_region], crc);

        const uint16_t total = static_cast<uint16_t>(data_region + IOT_FRAME_CRC_SIZE);
        if (total > out_buf_size) { return HTS_IoT_Codec::SECURE_FALSE; }

        for (uint16_t i = 0u; i < total; ++i) {
            const size_t idx = static_cast<size_t>(i);
            out_buf[idx] = build_buf_[idx];
        }
        out_len = total;

        SecureMemory::secureWipe(static_cast<void*>(build_buf_), sizeof(build_buf_));
        build_pos_ = 0u;
        tlv_count_ = 0u;
        frame_active_ = false;
        session_token_ = 0u;
        return HTS_IoT_Codec::SECURE_TRUE;
    }

    // ============================================================
    //  Parse
    // ============================================================

    uint32_t HTS_IoT_Codec::Parse(const uint8_t* wire_buf, uint16_t wire_len,
        IoT_Frame_Header& out_header,
        IoT_TLV_Item* out_items, uint8_t max_items,
        uint8_t& out_item_count) const noexcept
    {
        out_item_count = 0u;
        bool entered_loop = false;
        uint8_t parsed = 0u;

        const auto parse_fail_fn =
            [out_items, max_items, &out_item_count](bool wipe_items) noexcept
            -> uint32_t {
            if (wipe_items && out_items != nullptr && max_items > 0u) {
                const size_t wipe_bytes =
                    static_cast<size_t>(sizeof(IoT_TLV_Item)) *
                    static_cast<size_t>(max_items);
                SecureMemory::secureWipe(static_cast<void*>(out_items), wipe_bytes);
            }
            out_item_count = 0u;
            return HTS_IoT_Codec::SECURE_FALSE;
        };

        if (wire_buf == nullptr) { return parse_fail_fn(false); }
        if (wire_len < IOT_FRAME_HEADER_SIZE + IOT_FRAME_CRC_SIZE) {
            return parse_fail_fn(false);
        }

        const uint32_t data_region = static_cast<uint32_t>(wire_len) - IOT_FRAME_CRC_SIZE;
        const uint16_t computed_crc = IPC_Compute_CRC16(wire_buf, data_region);
        const uint16_t received_crc =
            Read_U16(&wire_buf[static_cast<size_t>(data_region)]);
        if (computed_crc != received_crc) { return parse_fail_fn(false); }

        out_header.msg_type = static_cast<IoT_MsgType>(wire_buf[0]);
        out_header.reserved = 0u;
        out_header.device_id = Read_U32(&wire_buf[1]);
        out_header.timestamp_sec = Read_U32(&wire_buf[5]);
        out_header.tlv_count = wire_buf[9];
        out_header.pad_ = 0u;

        if (out_header.tlv_count > IOT_MAX_TLV_COUNT) { return parse_fail_fn(false); }
        if (out_header.tlv_count > max_items) { return parse_fail_fn(false); }
        if (out_header.tlv_count > 0u && out_items == nullptr) {
            return parse_fail_fn(false);
        }

        const size_t data_region_sz = static_cast<size_t>(data_region);
        size_t offset = static_cast<size_t>(IOT_FRAME_HEADER_SIZE);

        while ((parsed < out_header.tlv_count) &&
            (offset <= data_region_sz) &&
            ((data_region_sz - offset) >= static_cast<size_t>(IOT_TLV_HEADER_SIZE)))
        {
            entered_loop = true;
            const SensorType stype = static_cast<SensorType>(wire_buf[offset]);
            const uint8_t vlen = wire_buf[offset + static_cast<size_t>(1u)];

            if (vlen > IOT_TLV_MAX_VALUE_SIZE) {
                return parse_fail_fn(entered_loop || parsed > 0u);
            }
            const size_t needed_sz =
                static_cast<size_t>(IOT_TLV_HEADER_SIZE) + static_cast<size_t>(vlen);
            if ((data_region_sz - offset) < needed_sz) {
                return parse_fail_fn(entered_loop || parsed > 0u);
            }

            const uint8_t expected_size = IoT_Sensor_Value_Size(stype);
            if (expected_size != 0u && vlen != expected_size) {
                return parse_fail_fn(entered_loop || parsed > 0u);
            }

            if (parsed < max_items && out_items != nullptr) {
                const size_t pi = static_cast<size_t>(parsed);
                out_items[pi].sensor_type = stype;
                out_items[pi].value_len = vlen;
                for (uint8_t j = 0u; j < vlen; ++j) {
                    const size_t src_idx =
                        offset + static_cast<size_t>(IOT_TLV_HEADER_SIZE) +
                        static_cast<size_t>(j);
                    out_items[pi].value[j] = wire_buf[src_idx];
                }
                for (uint8_t j = vlen; j < IOT_TLV_MAX_VALUE_SIZE; ++j) {
                    out_items[pi].value[j] = 0u;
                }
                out_items[pi].padding[0] = 0u;
                out_items[pi].padding[1] = 0u;
            }

            offset += needed_sz;
            parsed++;
        }

        if (parsed != out_header.tlv_count) {
            return parse_fail_fn(entered_loop || parsed > 0u);
        }

        out_item_count = parsed;
        return HTS_IoT_Codec::SECURE_TRUE;
    }

    // ============================================================
    //  Accessors
    // ============================================================

    uint8_t HTS_IoT_Codec::Get_TLV_Count() const noexcept
    {
        IoT_Codec_Busy_Guard guard(op_busy_);
        if (guard.locked != HTS_IoT_Codec::SECURE_TRUE) { return 0u; }
        return tlv_count_;
    }

    uint16_t HTS_IoT_Codec::Get_Used_Bytes() const noexcept
    {
        IoT_Codec_Busy_Guard guard(op_busy_);
        if (guard.locked != HTS_IoT_Codec::SECURE_TRUE) { return 0u; }
        return build_pos_;
    }

} // namespace ProtectedEngine
