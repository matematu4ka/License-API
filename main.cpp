#include "..\utils\CryptLicense.h"

CryptLicense Crypt;

int main() {

    std::string ip = "192.168.41.14";
    int port = 9000;
    Crypt.start(port, ip);
    return 0;
}
