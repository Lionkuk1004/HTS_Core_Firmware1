// =========================================================================
// HTS_Data_Loader.cpp
// 대용량 파일 I/O 및 텐서 변환 구현부 (A55 Linux / PC 전용)
// Target: 통합콘솔 (A55 Linux) / PC (STM32 베어메탈 제외)
//
// [양산 수정 — 세션 1 (5건) + 세션 5 (8건) = 총 13건]
//
//  ── 세션 1 (BUG-01 ~ BUG-05) ──
//  BUG-01 [HIGH]   Save_Tensor_As_File original_size OOB 방어
//  BUG-02 [MEDIUM] Get_File_Size filesystem → ifstream 폴백
//  BUG-03 [MEDIUM] Process_Big_Data 청크 꼬리 소거
//  BUG-04 [LOW]    Load_File_As_Tensor size_t 오버플로 방어
//  BUG-05 [LOW]    생성자 cerr 로깅 일관성
//
//  ── 세션 5 (BUG-06 ~ BUG-13) ──
//  BUG-06 [CRITICAL] 소멸자 없음 → memory_pool(64MB) 파일 평문 잔존
//    수정: ~Data_Loader() volatile 소거 + fence
//
//  BUG-07 [HIGH]     Process_Big_Data memset → DCE 안전 volatile 소거
//    기존: std::memset → GCC -O2에서 "이후 미참조" 판정 시 DCE 가능
//    수정: Secure_Wipe_Loader (volatile + O0 + fence)
//
//  BUG-08 [MEDIUM]   복사/이동 미차단 → = delete (64MB pool 복제 방지)
//
//  BUG-09 [MEDIUM]   생성자 abort → 조용한 실패
//    기존: OOM → std::abort() → 프로세스 강제 종료
//    수정: memory_pool 비어있음 → 모든 함수 false 반환
//
//  BUG-10 [LOW]      Self-Contained <cstddef> 추가
//  BUG-11 [LOW]      [[nodiscard]] 적용
//  BUG-12 [LOW]      Doxygen @param/@return 추가
//  BUG-13 [LOW]      하위 호환 래퍼 [[nodiscard]] 적용
// =========================================================================
#if defined(__arm__) || defined(__TARGET_ARCH_ARM) || defined(__TARGET_ARCH_THUMB) || defined(__ARM_ARCH)
#error "[HTS_FATAL] HTS_Data_Loader.cpp는 A55 Linux/PC 전용입니다."
#endif

#include "HTS_Data_Loader.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>

// ── std::filesystem 가용성 판별 ──────────────────────────────────────
#if __cplusplus >= 201703L || (defined(_MSVC_LANG) && _MSVC_LANG >= 201703L)
#define HTS_HAS_FILESYSTEM 1
#include <filesystem>
#else
#define HTS_HAS_FILESYSTEM 0
#endif

namespace ProtectedEngine {

    // =====================================================================
    //  [BUG-06/07] 보안 메모리 소거 (DCE 안전)
    // =====================================================================
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC push_options
#pragma GCC optimize("O0")
#elif defined(_MSC_VER)
#pragma optimize("", off)
#endif

    static void Secure_Wipe_Loader(void* ptr, size_t size) noexcept {
        if (!ptr || size == 0) return;
        volatile unsigned char* p =
            static_cast<volatile unsigned char*>(ptr);
        for (size_t i = 0; i < size; ++i) p[i] = 0;
        // [BUG-17] seq_cst → release (소거 배리어 정책 통일)
        std::atomic_thread_fence(std::memory_order_release);
    }

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC pop_options
#elif defined(_MSC_VER)
#pragma optimize("", on)
#endif

    // =====================================================================
    //  생성자 — 64MB 메모리 풀 1회 할당
    //  [BUG-09] abort → 조용한 실패 (pool 비어있음 → 모든 함수 false)
    // =====================================================================
    Data_Loader::Data_Loader() noexcept {
        try {
            memory_pool.resize(CHUNK_SIZE, 0);
        }
        catch (...) {
            // [BUG-09] OOM → pool 비어있음 → Process_Big_Data 등이 false 반환
            std::cerr << "[WARNING] Data_Loader: 64MB pool OOM — "
                "기능 비활성\n";
        }
    }

    // =====================================================================
    //  [BUG-06] 소멸자 — memory_pool 64MB 보안 소거
    //  파일 평문이 힙에 잔존하는 것을 방지
    //  PC 서버: 코어 덤프 / 스왑 파일에서 평문 노출 차단
    // =====================================================================
    Data_Loader::~Data_Loader() noexcept {
        if (!memory_pool.empty()) {
            Secure_Wipe_Loader(memory_pool.data(),
                memory_pool.size() * sizeof(uint32_t));
        }
    }

    // =====================================================================
    //  Initialize
    // =====================================================================
    void Data_Loader::Initialize(
        const std::vector<uint8_t>& pqc_key) noexcept {
        try {
            storage_io.Initialize_Storage(pqc_key);
        }
        catch (...) {}
    }

    // =====================================================================
    //  Load_File_As_Tensor (다이렉트 로드 — 권장 API)
    // =====================================================================
    bool Data_Loader::Load_File_As_Tensor(
        const std::string& path,
        std::vector<uint32_t>& out_tensor) noexcept {

        try {
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file.is_open()) {
                out_tensor.clear();
                return false;
            }

            std::streamsize file_size = file.tellg();
            if (file_size <= 0) {
                out_tensor.clear();
                return false;
            }

            // [BUG-04] size_t 오버플로 방어
            size_t byte_count = static_cast<size_t>(file_size);
            if (byte_count > std::numeric_limits<size_t>::max() - 3u) {
                out_tensor.clear();
                return false;
            }

            size_t required_elements = (byte_count + 3u) / 4u;

            file.seekg(0, std::ios::beg);

            if (out_tensor.capacity() < required_elements) {
                out_tensor.reserve(required_elements + 1024u);
            }
            out_tensor.resize(required_elements);

            // 마지막 워드 잔여 바이트 사전 제로화
            if (byte_count % 4u != 0u) {
                out_tensor.back() = 0;
            }

            file.read(reinterpret_cast<char*>(out_tensor.data()),
                file_size);
            return file.good();
        }
        catch (...) {
            return false;
        }
    }

    // =====================================================================
    //  Load_File_As_Tensor (하위 호환 래퍼)
    // =====================================================================
    std::vector<uint32_t> Data_Loader::Load_File_As_Tensor(
        const std::string& path) noexcept {

        std::vector<uint32_t> tensor;
        (void)Load_File_As_Tensor(path, tensor);
        return tensor;
    }

    // =====================================================================
    //  Save_Tensor_As_File — [BUG-01] original_size OOB 방어
    // =====================================================================
    bool Data_Loader::Save_Tensor_As_File(
        const std::string& path,
        const std::vector<uint32_t>& tensor,
        size_t original_size) noexcept {

        try {
            if (tensor.empty() || original_size == 0) return false;

            const size_t tensor_bytes = tensor.size() * sizeof(uint32_t);
            if (original_size > tensor_bytes) {
                std::cerr << "[ERROR] Save_Tensor_As_File: original_size("
                    << original_size << ") > capacity("
                    << tensor_bytes << ")\n";
                return false;
            }

            std::ofstream file(path, std::ios::binary);
            if (!file.is_open()) return false;

            file.write(reinterpret_cast<const char*>(tensor.data()),
                static_cast<std::streamsize>(original_size));
            return file.good();
        }
        catch (...) {
            return false;
        }
    }

    // =====================================================================
    //  Process_Big_Data — [BUG-07] volatile 소거 (DCE 안전)
    // =====================================================================
    bool Data_Loader::Process_Big_Data(
        const std::string& input_path,
        const std::string& output_path) noexcept {

        if (memory_pool.empty()) return false;  // [BUG-09] pool 미할당

        try {
            std::ifstream fin(input_path, std::ios::binary);
            std::ofstream fout(output_path, std::ios::binary);
            if (!fin || !fout) return false;

            const std::streamsize pool_bytes =
                static_cast<std::streamsize>(CHUNK_SIZE * sizeof(uint32_t));

            // [BUG-16] 청크 오프셋 누적 — Many-Time Pad 차단
            // 각 청크에 파일 내 절대 바이트 위치를 전달하여
            // Protect_File_Partial이 청크마다 고유 키스트림 생성
            uint64_t chunk_byte_offset = 0;

            while (true) {
                fin.read(reinterpret_cast<char*>(memory_pool.data()),
                    pool_bytes);
                std::streamsize bytes_read = fin.gcount();
                if (bytes_read <= 0) break;

                size_t elements_to_process =
                    (static_cast<size_t>(bytes_read) + 3u) / 4u;

                // [BUG-16] chunk_byte_offset 전달 → 청크별 고유 시드
                storage_io.Protect_File_Partial(
                    memory_pool, elements_to_process, chunk_byte_offset);

                fout.write(reinterpret_cast<char*>(memory_pool.data()),
                    bytes_read);

                // [BUG-16] 오프셋 누적 (다음 청크 위치)
                chunk_byte_offset += static_cast<uint64_t>(bytes_read);

                // [BUG-07 개선] 전체 풀 소거 (조건 분기 없음 — 단순+확실)
                Secure_Wipe_Loader(memory_pool.data(),
                    CHUNK_SIZE * sizeof(uint32_t));
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }

    // =====================================================================
    //  Get_File_Size — [BUG-02] C++17/14 폴백
    // =====================================================================
    size_t Data_Loader::Get_File_Size(const std::string& path) noexcept {
        try {
#if HTS_HAS_FILESYSTEM
            if (!std::filesystem::exists(path)) return 0;
            auto fsize = std::filesystem::file_size(path);
            return static_cast<size_t>(fsize);
#else
            std::ifstream file(path, std::ios::binary | std::ios::ate);
            if (!file.is_open()) return 0;
            std::streamsize size = file.tellg();
            if (size <= 0) return 0;
            return static_cast<size_t>(size);
#endif
        }
        catch (...) {
            return 0;
        }
    }

} // namespace ProtectedEngine