#pragma once

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
