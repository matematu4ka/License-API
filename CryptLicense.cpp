#include "CryptLicense.h"
#include "Utils.h"

CryptLicense::CryptLicense() {};
CryptLicense::~CryptLicense() {};

time_t CryptLicense::getCurrentUnixTimestamp() {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();

    return std::chrono::system_clock::to_time_t(now);
}

bool CryptLicense::fileExists(const std::wstring& filePath) {
    return fs::exists(filePath);
}

bool CryptLicense::CheckLicense() {
    GetCode();
    std::string publicKey;
    std::vector<char> vecPublic;
    std::vector<char> vec;

    const std::wstring fileNamePublicKey = parentDir / L"public.bin";
    utils::LoadFileToVector(fileNamePublicKey, vecPublic);

    if (vecPublic.empty())
    {
        return false;
    }
    publicKey.assign(vecPublic.begin(), vecPublic.end());

    try
    {
        const std::wstring fileName = currentDir / L"License.dat";
        utils::LoadFileToVector(fileName, vec);

        std::cout << publicKey << std::endl;

        if (utils::RsaVerifyVector(publicKey, Code, vec))
        {
            return true;
        }
        else
        {
            return false;
        }

    }
    catch (const std::logic_error& ex)
    {
        std::cout << "You do not have License.dat file installed. Please put it in program dir." << std::endl;
    }
    return true;
}

void CryptLicense::GetCode() {
    std::time_t timestamp = getCurrentUnixTimestamp();
    Code = std::to_string(timestamp);
}

bool CryptLicense::GetLicense(const std::string& ip, int port) {
    GetCode();
    Get2HardValue();
    // ������������� ���������� Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "������ ��� ������������� Winsock." << std::endl;
        return false;
    }

    // �������� ������
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        std::cerr << "������ ��� �������� ������." << std::endl;
        WSACleanup();
        return false;
    }

    // ���������� ��������� � ������� �������
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);

    // ����������� � �������
    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "������ ��� ����������� � �������." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    Sleep(2000);

    // �������� ��������� �� ������
    if (send(clientSocket, Code.c_str(), Code.size(), 0) == SOCKET_ERROR) {
        std::cerr << "������ ��� �������� ��������� �� ������." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    std::cout << "��������� \"" << Code << "\" ������� ���������� �� ������." << std::endl;

    if (send(clientSocket, HardValue.c_str(), HardValue.size(), 0) == SOCKET_ERROR) {
        std::cerr << "������ ��� �������� ��������� �� ������." << std::endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    std::cout << "��������� \"" << HardValue << "\" ������� ���������� �� ������." << std::endl;

    char buffer[1024];
    std::string message1;
    std::string message2;

    // ��������� ������ ��������� �� �������
    int bytesReceived1 = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived1 == SOCKET_ERROR || bytesReceived1 == 0) {
        if (bytesReceived1 == SOCKET_ERROR) {
            std::cerr << "������ ��� ������ ������� ���������." << std::endl;
        }
        else {
            std::cerr << "������ ������ ���������� ��� �������� ������." << std::endl;
        }
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }
    message1.assign(buffer, bytesReceived1);
    std::cout << "�������� ������ ���������: " << message1 << std::endl;

    // ��������� ������ ��������� �� �������
    int bytesReceived2 = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived2 == SOCKET_ERROR || bytesReceived2 == 0) {
        if (bytesReceived2 == SOCKET_ERROR) {
            std::cerr << "������ ��� ������ ������� ���������." << std::endl;
        }
        else {
            std::cerr << "������ ������ ���������� ��� �������� ������." << std::endl;
        }
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }
    message2.assign(buffer, bytesReceived2);
    std::cout << "�������� ������ ���������: " << message2 << std::endl;

    //������ � �����
    std::vector<char> messageToVec1(message1.begin(), message1.end());
    std::vector<char> messageToVec2(message2.begin(), message2.end());
    utils::SaveVectorToFile(parentDir / L"public.bin", messageToVec1);
    utils::SaveVectorToFile(currentDir / L"License.dat", messageToVec2);

    // �������� ������ � ������� Winsock
    closesocket(clientSocket);
    WSACleanup();

    return true;
}

std::string CryptLicense::extractValue(std::string& str) {
    std::string value;
    size_t colonPos = str.find(':');
    if (colonPos != std::string::npos) {
        // ���������� �������� ����� ������� ':'
        value = str.substr(colonPos + 2); // +2 ����� ���������� ':' � ������ ����� ����
        // �������� '\\'
        if (!value.empty() && value.back() == '\\')
            value.pop_back();
    }
    return value;
}

void CryptLicense::Get2HardValue() {

    // ���������� ������� PowerShell
    const char* powershellScript = R"(
        # �������� �������� ������ ���� ������ ������ � �������
        Get-WmiObject -Class Win32_DiskDrive | ForEach-Object {
            $disk = $_
            $diskSerial = $disk.SerialNumber

            if ($diskSerial -ne $null) {
                Write-Output \"�������� ����� ����� $($disk.DeviceID): $($diskSerial)\"
            }
        }
    )";

    // ������ ��������� ���� � �������� PowerShell
    std::ofstream scriptFile("temp_script.ps1");
    if (scriptFile.is_open()) {
        scriptFile << powershellScript;
        scriptFile.close();

        // ��������� ������ PowerShell
        system("powershell.exe -ExecutionPolicy Bypass -File temp_script.ps1 > script_output.txt");

        // ������� ��������� ����
        remove("temp_script.ps1");
    }
    else {
        std::cerr << "������ ��� �������� ���������� �����." << std::endl;
    }

    std::ifstream file("script_output.txt");
    if (!file.is_open()) {
        std::cerr << "Unable to open file." << std::endl;
    }

    // ������ ����� �� ����� � ���������� �������� ���������� ��������
    std::string line;
    while (std::getline(file, line)) {
        HardValue = extractValue(line);
    }

    // �������� �����
    file.close();
}

bool CryptLicense::isFileEmpty(const std::wstring& filename) {
    std::ifstream file(filename, std::ios::ate | std::ios::binary);
    return file.tellg() == 0;
}

bool CryptLicense::checkFilesForEmptiness() {
    const std::wstring publicKeyFile = parentDir / L"public.bin";
    const std::wstring licenseFile = parentDir / L"License.dat";

    if (fileExists(publicKeyFile) && (fileExists(licenseFile))) {
        if (isFileEmpty(publicKeyFile) || isFileEmpty(licenseFile))
        {
            return false;
        }
        else {
            return true;
        }
    }
    return false;
}

void CryptLicense::start(int port, std::string ip) {
    setlocale(LC_ALL, "Russian");
    std::wstring filePath = parentDir / L"License.dat";

    if (checkFilesForEmptiness()) {
        std::wcout << filePath;
        CheckLicense();
    }
    else
    {
        if (GetLicense(ip, port)) {
            std::cout << "Good work" << std::endl;
        }
        else std::cout << "Client down or server don't work" << std::endl;

    }

}