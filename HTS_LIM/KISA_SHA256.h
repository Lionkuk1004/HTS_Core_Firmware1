/**
@file KISA_SHA_256.h
@brief SHA256 ��ȣ �˰����
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