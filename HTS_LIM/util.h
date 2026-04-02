#pragma once
// ─────────────────────────────────────────────────────────
//  외주 업체 통합 가이드
// ─────────────────────────────────────────────────────────
//  [사용법] 기본 사용 예시를 여기에 기재하세요.
//  [메모리] sizeof(클래스명) 확인 후 전역/정적 배치 필수.
//  [보안]   복사/이동 연산자 = delete (키 소재 복제 차단).
//
//  ⚠ [파트너사 필수 확인]
//    HW 레지스터 주소(UART/WDT 등)는 보드 설계에 맞게 교체.
//    IRQ 번호는 STM32F407 RM0090 벡터 테이블 기준으로 교체.
// ─────────────────────────────────────────────────────────

#ifdef  __cplusplus
extern "C" {
#endif

	int asc2hex(unsigned char* dst, const char* src);
	void print_title(const char* title);
	void print_hex(const char* valName, const unsigned char* data, const int dataLen);
	void print_result(const char* func, int ret);
	void word2byte(unsigned char* dst, const unsigned int src, const int srcLen);

#ifdef  __cplusplus
}
#endif

// EOF


