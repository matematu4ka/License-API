#define _CRT_SECURE_NO_WARNINGS_
#include <iostream>
#include <Winsock2.h>
#include <ws2tcpip.h>
#include <fstream>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <regex>

#pragma comment(lib, "ws2_32.lib")
#include <string>
#include <vector>
#include "Utils.h"

#include <chrono>
#include <time.h>
#include <filesystem>

namespace fs = std::filesystem;

using namespace std;

class CryptLicense {
public:
	std::string Code;
	fs::path parentDir = currentDir.parent_path();
	fs::path currentDir = fs::current_path();
	CryptLicense();
	~CryptLicense();
	time_t getCurrentUnixTimestamp();
	bool fileExists(const std::wstring& filePath);
	bool CheckLicense();
	void GetCode();
	bool GetLicense(const std::string& ip, int port);
	std::string extractValue(std::string& str);
	void Get2HardValue();
	std::string HardValue;
	bool isFileEmpty(const std::wstring& filename);
	bool checkFilesForEmptiness();
	void start(int port, std::string ip);
};