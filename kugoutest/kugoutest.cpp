#include <iostream>
#include <Windows.h>
#include <iomanip> 
#include <string>
#include "MD5.h"

#define UCHAR unsigned char
#define READ_SIZE 0x1000

using namespace std;

//酷狗 .kgma/.kgtemp 文件头
typedef struct KGFileHead {
	DWORD dwMagic[4];        //文件标志
	DWORD dwOffset;       //加密内容偏移
	DWORD dwFileType;	//文件类型
	DWORD dwKeyType;     //密钥类型（内置密钥）
	UCHAR KeyTest[16];  //密钥测试值
	UCHAR FileKey[16]; //文件随机密钥
}KGFileHead;

//函数定义
void Decrypt(UCHAR* buffer, DWORD size, uint64_t offset, UCHAR* FileKey, UCHAR* FixedKey);
UCHAR* Md5_Complex(UCHAR* key, DWORD size);


//各种常量定义
UCHAR KEY_MAGIC_M1[4] = { 0x6C, 0x2C, 0x2F, 0x27 };
UCHAR KEY_MAGIC_M1_KEY[16] = { 0x14, 0xE3, 0x10, 0xB1, 0x0D, 0x3B,
0x6F, 0x41, 0x85, 0x6B, 0x79, 0x27, 0x8B, 0xFD, 0x61, 0x85 };
WORD OFFSET_TABLE[16]  = { 14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1 };
DWORD MAGIC_M1[4] = { 0xEB32D57C,0x4B7F0286,0x8EA6AFA8,0x1499FF0F };
UCHAR MAGIC_KEY_TEST[16] = {0x38, 0x85, 0xED, 0x92, 0x79, 0x5F, 0xF8, 0x4C, 
0xB3, 0x3, 0x61, 0x41, 0x16, 0xA0, 0x1D, 0x47};

//文件格式
UCHAR FLAC_MAGIC[] = { 0x66, 0x4C, 0x61, 0x43 };
UCHAR MP3_ID3_MAGIC[] = { 0x49, 0x44, 0x33 };
UCHAR MP3_FRAME_MAGIC[] = { 0xFF, 0xFB };

int main(int argc, char* argv[]){
	string path = "";
	string new_path = "";
	HANDLE hInputFile = NULL;
	HANDLE hOutputFile = NULL;
	UCHAR* pFileKey = NULL;
	UCHAR content[READ_SIZE];
	KGFileHead kgFileHead;
	uint64_t file_size = 0;
	uint64_t file_pos = 0;
	DWORD dwRead = 0;
	size_t dotPos = 0;


	//检查参数 kgtest <inputfile> 
	if (argc != 2) {
		cout << "Usage: filename <inputfile>" << endl;
		cout << "Example(例如)：xxx.exe ./input.kgma" << endl;
		return 1;
	}
	path.append(argv[1]);
	cout << path << endl;
	/*** 读取文件/校验密钥 ***/
	//打开文件
	hInputFile = CreateFileA(path.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hInputFile == INVALID_HANDLE_VALUE) {
		cout << "文件打开失败！(文件不存在/文件名无法识别)" <<  GetLastError() << endl;
		goto Exit;
	}
	//读取文件头
	if (!ReadFile(hInputFile, &kgFileHead, sizeof(KGFileHead), NULL, NULL)) {
		cout << "文件读取失败！" << GetLastError() << endl;
		goto Exit;
	}
	//检查文件头
	if (memcmp(kgFileHead.dwMagic, MAGIC_M1, sizeof(MAGIC_M1)) != 0) {
		cout << "文件不是酷狗加密文件！" << endl;
		goto Exit;
	}
	//对比文件类型和密钥类型/（这里密钥写死的）
	if (kgFileHead.dwFileType != 3 || kgFileHead.dwKeyType != 1) {
		cout << "文件不是酷狗加密文件！" << endl;
	}
	//获取文件密钥
	pFileKey = Md5_Complex(kgFileHead.FileKey, sizeof(kgFileHead.FileKey));
	//检查密钥测试值
	Decrypt(kgFileHead.KeyTest, sizeof(kgFileHead.KeyTest), 0, pFileKey, KEY_MAGIC_M1_KEY);
	if (memcmp(kgFileHead.KeyTest, MAGIC_KEY_TEST, sizeof(MAGIC_KEY_TEST)) != 0) {
		cout << "文件密钥测试值不匹配！" << endl;
		goto Exit;
	}
	
	cout << "密钥匹配!" << endl;
	/*** 解密文件 ***/
	//去后缀
	dotPos = path.rfind('.');
	if (dotPos != std::string::npos) {
		path = path.substr(0, dotPos);
	}
	//检查文件格式
	hOutputFile = CreateFileA(path.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutputFile == INVALID_HANDLE_VALUE) {
		cout << "创建文件失败！" << GetLastError() << endl;
		goto Exit;
	}
	//设置文件指针到加密内容偏移位置
	if (SetFilePointer(hInputFile, kgFileHead.dwOffset, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
		cout << "设置文件指针失败！" << GetLastError() << endl;
		goto Exit;
	}
	file_size = GetFileSize(hInputFile, NULL);
	//读取加密内容并解密
	while (ReadFile(hInputFile, content, READ_SIZE, &dwRead, NULL) && dwRead > 0) {
		// 解密读取的内容
		Decrypt(content, READ_SIZE, file_pos, pFileKey, KEY_MAGIC_M1_KEY);
		//判断文件类型
		if (file_pos == 0) {
			if (!memcmp(content, FLAC_MAGIC, 4)) {
				new_path = path + ".flac";
			}
			else if (!memcmp(content, MP3_ID3_MAGIC, 3) || memcmp(content, MP3_FRAME_MAGIC,2)) {
				new_path = path + ".mp3";
			}
		}
		file_pos += READ_SIZE;
		// 写入解密后内容
		DWORD dwWritten = 0;
		if (!WriteFile(hOutputFile, content, dwRead, &dwWritten, NULL) || dwWritten != dwRead) {
			cout << "写入文件失败！" << GetLastError() << endl;
			goto Exit;
		}
		float progress = (float)file_pos / file_size * 100.0f;
		std::cout << "\r解密进度: " << std::fixed << std::setprecision(2)
			<< std::setw(6) << progress << "%" << std::flush;
	}
	//解除占用
	CloseHandle(hOutputFile);
	hOutputFile = NULL;
	//添加后缀
	cout << endl;
	if (!MoveFileA(path.c_str(), new_path.c_str())) {
		cout << "文件名重复，请删除【" << new_path << "】后试！！！" << endl;
		remove(path.c_str());
		goto Exit;
	}
	else {
		cout <<  "解密成功：" << new_path << endl;
	}
	
	

Exit:
	//退出清除数据
	if (hInputFile != NULL && hInputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hInputFile);
		hInputFile = NULL;
	}
	if (hOutputFile != NULL && hOutputFile != INVALID_HANDLE_VALUE) {
		CloseHandle(hOutputFile);
		hOutputFile = NULL;
	}
	if (pFileKey != NULL) {
		delete[] pFileKey;
	}
	return 0;
}

UCHAR* Md5_Complex(UCHAR* FileKey, DWORD size) {
	UCHAR md5[16] = { 0 };
	MD5_CTX md5_ctx;
	//进行md5
	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, FileKey, size);
	MD5Final(md5, &md5_ctx);

	//奇偶排序
	UCHAR* output = new UCHAR[17];
	for (int i = 0; i < 16; i++) {
		output[OFFSET_TABLE[i]] = md5[i];
	}
	output[16] = 0x6b;
	return output;
}

void Decrypt(UCHAR* buffer, DWORD size, uint64_t offset, UCHAR* FileKey, UCHAR* FixedKey) {
	WORD FileKeySize = 0x11; 
	WORD FixedKeySize = 0x10; 

	for (DWORD i = 0; i < size; ++i) {
		uint64_t absOffset = offset + i;

		UCHAR t1 = FileKey[absOffset % FileKeySize];
		UCHAR t2 = FixedKey[absOffset % FixedKeySize];

		UCHAR v1 = buffer[i] ^ t1 ^ ((buffer[i] ^ t1) << 4);
		UCHAR v2 = ((absOffset >> 0x18) & 0xFF) ^ ((absOffset >> 0x10) & 0xFF) ^ ((absOffset >> 0x8) & 0xFF) ^ (absOffset & 0xff) ^ t2;

		buffer[i] = v1 ^ v2;
	}
}

