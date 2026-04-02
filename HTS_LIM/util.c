#include <stdio.h>
#include <stdlib.h> 
#include "util.h"

int asc2hex(unsigned char* dst, const char* src)
{
	unsigned char temp = 0x00;
	int i = 0;

	while (src[i] != 0x00)
	{
		temp = 0x00;

		if ((src[i] >= 0x30) && (src[i] <= 0x39))
			temp = src[i] - '0';
		else if ((src[i] >= 0x41) && (src[i] <= 0x5A))
			temp = src[i] - 'A' + 10;
		else if ((src[i] >= 0x61) && (src[i] <= 0x7A))
			temp = src[i] - 'a' + 10;
		else
			temp = 0x00;

		(i & 1) ? (dst[i >> 1] ^= temp & 0x0F) : (dst[i >> 1] = 0, dst[i >> 1] = temp << 4);

		i++;
	}

	return ((i + 1) / 2);
}

void print_title(const char* title)
{
	printf("================================================\n");
	printf("  %s\n", title);
	printf("================================================\n");
}

void print_hex(const char* valName, const unsigned char* data, const int dataLen)
{
	int i = 0;

	printf("%s [%dbyte] :", valName, dataLen);
	for (i = 0; i < dataLen; i++)
	{
		if (!(i & 0x0F))
			printf("\n");
		printf(" %02X", data[i]);
	}
	printf("\n");
}

void print_result(const char* func, int ret)
{
	if (ret)
	{
		printf("================================================\n");
		printf("  %s Failure!\n", func);
		printf("================================================\n");

		exit(0);
	}
	else
	{
		printf("================================================\n");
		printf("  %s Success!\n", func);
		printf("================================================\n");
	}
}


void word2byte(unsigned char* dst, const unsigned int src, const int srcLen)
{
	int i = 0, shift = 0;
	for (i = 0; i < srcLen; i++)
	{
		shift = (srcLen - (i + 1)) * 8;
		dst[i] = (unsigned char)((src >> shift) & 0xff);
	}
}
// EOF


