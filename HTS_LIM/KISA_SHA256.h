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

/**
@file KISA_SHA256.h
@brief SHA256 암호 알고리즘 (KISA 참조 구현)
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/

#ifndef _KISA_SHA256_H
#define _KISA_SHA256_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef OUT
#define OUT
#endif

#ifndef IN
	#define IN
#endif

#ifndef INOUT
	#define INOUT
#endif

#define USER_LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
	#define USING_BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
	#define USING_LITTLE_ENDIAN
#else
	#if 0
		#define USING_BIG_ENDIAN
	#elif defined(_MSC_VER)
		#define USING_LITTLE_ENDIAN
	#else
		#error
	#endif
#endif

	//typedef unsigned long ULONG;
	//typedef ULONG* ULONG_PTR;
	
	typedef unsigned int ULONG;
	typedef ULONG* ULONG_PTR;

	typedef unsigned int UINT;
	typedef UINT* UINT_PTR;

	typedef signed int SINT;
	typedef SINT* SINT_PTR;

	typedef unsigned char UCHAR;
	typedef UCHAR* UCHAR_PTR;

	typedef unsigned char BYTE;

#define SHA256_DIGEST_BLOCKLEN	64
#define SHA256_DIGEST_VALUELEN	32

	typedef struct {
		UINT uChainVar[SHA256_DIGEST_VALUELEN / 4];
		UINT uHighLength;
		UINT uLowLength;
		BYTE szBuffer[SHA256_DIGEST_BLOCKLEN];
	} SHA256_INFO;

	/**
	@brief ���⺯���� ���̺����� �ʱ�ȭ�ϴ� �Լ�
	@param Info : SHA256_Process ȣ�� �� ���Ǵ� ����ü
	*/
	void SHA256_Init(OUT SHA256_INFO* Info);

	/**
	@brief ���⺯���� ���̺����� �ʱ�ȭ�ϴ� �Լ�
	@param Info : SHA256_Init ȣ���Ͽ� �ʱ�ȭ�� ����ü(���������� ���ȴ�.)
	@param pszMessage : ����� �Է� ��
	@param inLen : ����� �Է� �� ����
	*/
	void SHA256_Process(OUT SHA256_INFO* Info, IN const BYTE* pszMessage, IN UINT uDataLen);

	/**
	@brief �޽��� �����̱�� ���� �����̱⸦ ������ �� ������ �޽��� ����� ������ �����Լ��� ȣ���ϴ� �Լ�
	@param Info : SHA256_Init ȣ���Ͽ� �ʱ�ȭ�� ����ü(���������� ���ȴ�.)
	@param pszDigest : ��ȣ��
	*/
	void SHA256_Close(OUT SHA256_INFO* Info, IN BYTE* pszDigest);

	/**
	@brief ����� �Է� ���� �ѹ��� ó��
	@param pszMessage : ����� �Է� ��
	@param pszDigest : ��ȣ��
	@remarks ���������� SHA256_Init, SHA256_Process, SHA256_Close�� ȣ���Ѵ�.
	*/
	void SHA256_Encrpyt(IN const BYTE* pszMessage, IN UINT uPlainTextLen, OUT BYTE* pszDigest);

#ifdef  __cplusplus
}
#endif

#endif