#pragma warning( disable : 4996)
#include <iostream>
#include "syclover.h"
#include <windows.h>
#include "S.h"
using namespace std;

char flag[] = ">pvfqYc,4tTc2UxRmlJ,sB{Fh4Ck2:CFOb4ErhtIcoLo";

#pragma code_seg(".SCTF")
void Fun()
{
	int i;
	char tmp;

	for (i = 0; i < strlen(flag); i++)
	{
		flag[i] -= 1;
	}
	for (i = 0; i < strlen(flag) / 2; i++)
	{
		tmp = flag[strlen(flag) - 1 - i];
		flag[strlen(flag) - 1 - i] = flag[i];
		flag[i] = tmp;
	}
}
#pragma code_seg()
#pragma comment(linker, "/SECTION:.SCTF,ERW")

void xorPlus(char *soure, int dLen, char *Key, int Klen);

const char g_key[17] = "sycloversyclover";
const char g_iv[17] = "sctfsctfsctfsctf";

string EncryptionAES(const string& strSrc) //AES加密
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());

	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char *szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}

bool checkDebugged()
{
	bool bDebugged = false;
	int nNtFlag = 0;
	_asm {
		MOV EAX, DWORD PTR FS : [0x30]
		MOV AL, BYTE PTR DS : [EAX + 2]
		MOV bDebugged, AL
		MOV EAX, DWORD PTR FS : [0x30]
		MOV EAX, DWORD PTR DS : [EAX + 0x68]
		MOV nNtFlag, EAX
	}
	return bDebugged || (nNtFlag == 0x70);
}

void SMC(char *pBuf, char *key)
{
	const char *szSecName = ".SCTF";
	short nSec;
	BOOL isdebug;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pSec;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuf;
	pNtHeader = (PIMAGE_NT_HEADERS)&pBuf[pDosHeader->e_lfanew];
	nSec = pNtHeader->FileHeader.NumberOfSections;
	pSec = (PIMAGE_SECTION_HEADER)&pBuf[sizeof(IMAGE_NT_HEADERS) + pDosHeader->e_lfanew];
	for (int i = 0; i < nSec; i++)
	{
		if (strcmp((char *)&pSec->Name, szSecName) == 0)
		{
			int pack_size;
			char *packStart;
			_try {
				DebugBreak();
			}
			_except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
				EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
			{
				CheckRemoteDebuggerPresent(GetCurrentProcess(), &isdebug);
				if (IsDebuggerPresent()|| isdebug)
				{
					return;
				}
				pack_size = pSec->SizeOfRawData;
				packStart = &pBuf[pSec->VirtualAddress];
				xorPlus(packStart, pack_size, key, strlen(key));
			}
			return;
		}
		pSec++;
	}
}

void xorPlus(char *soure, int dLen, char *Key, int Klen)
{
	for (int i = 0; i < dLen;)
	{
		for (int j = 0; (j < Klen) && (i < dLen); j++, i++)
		{
			soure[i] = soure[i] ^ Key[j];
			soure[i] = ~soure[i];
		}
	}
}

void fun()
{
	if (checkDebugged())
	{
		exit(-5);
	}
	_try
	{
		Fun();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		;
	}
}

int main(int argc, char **argv)
{
	char ticket[45];

	SMC((char *)GetModuleHandle(0), (char *)g_key);
	fun();
	cout << "welcome to 2019 sctf" << endl;
	cout << "please input your ticket:";
	cin >> ticket;
	if (!EncryptionAES(ticket).compare(flag))
	{
		cout << "Have fun!" << endl;
	}
	else
	{
		cout << "A forged ticket!!" << endl;
	}
	system("pause");
	return 0;
}