#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>  
#include <thread> // �������� ������������ ���� ��� ������ � ��������
#include "Utils.h"
#include <fstream>
#include <sstream>
#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")
#define MAX_CLIENTS (100)
#define WIN32_LEAN_AND_MEAN

#define IDR_FILE_PRIVATE_KEY 101

std::string UnicKeyValue;

struct client_ctx
{
    SOCKET socket;
    CHAR buf_recv[512]; // ����� ������
    CHAR buf_send[512]; // ����� ��������
    unsigned int sz_recv; // ������� ������
    unsigned int sz_send_total; // ������ � ������ ��������
    unsigned int sz_send; // ������ ����������
    // ��������� OVERLAPPED ��� ����������� � ����������
    OVERLAPPED overlap_recv;
    OVERLAPPED overlap_send;
    OVERLAPPED overlap_cancel;
    DWORD flags_recv; // ����� ��� WSARecv
};

bool log(const std::string& message) {
    std::ifstream file("log.txt");
    if (file.is_open()) {
        std::string firstMessage;
        std::getline(file, firstMessage);
        file.close();

        if (firstMessage == message) {
            return false; // ��������� ��� ������������ � ����
        }
    }

    std::ofstream outFile("log.txt");
    if (outFile.is_open()) {
        outFile << message << std::endl;
        outFile.close();
        return true; // ��������� �������� � ���
    }
    else {
        // �� ������� ������� ���� ��� ������
        return false;
    }
}

void getLicense() {
    std::string publicKey;
    std::string privateKey;
    std::vector<char> vecPrivate;

    utils::SaveResToVector(L"PRIVATE_KEY", IDR_FILE_PRIVATE_KEY, &vecPrivate);

    if (vecPrivate.empty()) {
        utils::RsaGenerateStringKeys(publicKey, privateKey);
        std::vector<char> vecPublic(publicKey.begin(), publicKey.end());
        vecPrivate.assign(privateKey.begin(), privateKey.end());
        utils::SaveVectorToFile(L"private.bin", vecPrivate);
        utils::SaveVectorToFile(L"public.bin", vecPublic);
    }
    else {
        privateKey.assign(vecPrivate.begin(), vecPrivate.end());
    }

    //std::cout << "Public Key:\n" << publicKey << std::endl;
    std::string sign;

    std::vector<char> smallFile;

    std::vector<char> UnicKey(UnicKeyValue.begin(), UnicKeyValue.end());

    utils::RsaSignVector(privateKey, UnicKey, sign);

    std::vector<char> vec(sign.begin(), sign.end());
    utils::SaveVectorToFile(L"License.dat", vec);

    //std::cout << "Your license.dat file was saved in program's directory" << std::endl;
}

struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

void schedule_read(DWORD idx)
{
    WSABUF buf;
    buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
    buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
    memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
    g_ctxs[idx].flags_recv = 0;
    WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

void schedule_write(DWORD idx)
{
    WSABUF buf;
    buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
    buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
    memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
    WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

void add_accepted_connection()
{
    DWORD i;
    for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
    {
        if (g_ctxs[i].socket == 0)
        {
            unsigned int ip = 0;
            struct sockaddr_in* local_addr = 0, * remote_addr = 0;
            int local_addr_sz, remote_addr_sz;
            GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
                sizeof(struct sockaddr_in) + 16, (struct sockaddr**)&local_addr, &local_addr_sz, (struct sockaddr**)&remote_addr,
                &remote_addr_sz);
            if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
            printf(" connection created, remote IP: %u.%u.%u.%u\n", (ip >> 24) & 0xff, (ip >> 16) & 0xff,
                (ip >> 8) & 0xff, (ip) & 0xff);
            g_ctxs[i].socket = g_accepted_socket;
            if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
            {
                printf("CreateIoCompletionPort error: %x\n", GetLastError());
                return;
            }

            // ��������� ��������
            getLicense();

            // ��������� ��������� �� �������
            char buffer[1024];
            int bytesRead;

            // ��������� ������� ���������
            bytesRead = recv(g_ctxs[i].socket, buffer, sizeof(buffer), 0);
            if (bytesRead == SOCKET_ERROR) {
                std::cerr << "������ ��� ��������� ������� ��������� �� �������." << std::endl;
                closesocket(g_ctxs[i].socket);
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }
            else if (bytesRead == 0) {
                std::cerr << "������ ���������� ��� �������� ���������." << std::endl;
                closesocket(g_ctxs[i].socket);
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }

            std::cout << "��������� �� �������: " << std::string(buffer, bytesRead) << std::endl;

            // ��������� ������� ���������
            bytesRead = recv(g_ctxs[i].socket, buffer, sizeof(buffer), 0);
            if (bytesRead == SOCKET_ERROR) {
                std::cerr << "������ ��� ��������� ������� ��������� �� �������." << std::endl;
                closesocket(g_ctxs[i].socket);
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }
            else if (bytesRead == 0) {
                std::cerr << "������ ���������� ����� �������� ������� ���������." << std::endl;
                closesocket(g_ctxs[i].socket);
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }

            std::string HardValue(buffer, bytesRead);

            std::cout << "��������� �� �������: " << HardValue << std::endl;

            if (!log(HardValue)) {
                std::cerr << "������ ��������� ��� ������������ � ����." << std::endl;
                closesocket(g_ctxs[i].socket); // ������� ����� �������
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }

            std::vector<char> vecPublic;
            const std::wstring fileNamePublicKey = L"public.bin";
            utils::LoadFileToVector(fileNamePublicKey, vecPublic);

            std::vector<char> vecLicense;
            const std::wstring fileNameLicense = L"License.dat";
            utils::LoadFileToVector(fileNameLicense, vecLicense);

            std::string response1(vecPublic.begin(), vecPublic.end());
            std::string response2(vecLicense.begin(), vecLicense.end());

            // �������� ������� ���������
            if (send(g_ctxs[i].socket, response1.c_str(), response1.size(), 0) == SOCKET_ERROR) {
                std::cerr << "������ ��� �������� ������� ���������." << std::endl;
                closesocket(g_ctxs[i].socket);
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }

            std::cout << "���������� ������ ���������." << std::endl;

            // �������� ������� ���������
            if (send(g_ctxs[i].socket, response2.c_str(), response2.size(), 0) == SOCKET_ERROR) {
                std::cerr << "������ ��� �������� ������� ���������." << std::endl;
                closesocket(g_ctxs[i].socket);
                memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
                return; // ����� �� ������� ��������� �������
            }

            std::cout << "������ ������� ���������� �������." << std::endl;

            // �������� ������ �������
            closesocket(g_ctxs[i].socket);
            memset(&g_ctxs[i], 0, sizeof(g_ctxs[i])); // ���������� ������ � �����������
            return;
        }
    }
    closesocket(g_accepted_socket);
    g_accepted_socket = 0;
}


void schedule_accept()
{
    g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
    AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

int is_string_received(DWORD idx, int* len)
{
    DWORD i;
    for (i = 0; i < g_ctxs[idx].sz_recv; i++)
    {
        if (g_ctxs[idx].buf_recv[i] == '\n')
        {
            *len = (int)(i + 1);
            return 1;
        }
    }
    if (g_ctxs[idx].sz_recv == sizeof(g_ctxs[idx].buf_recv))
    {
        *len = sizeof(g_ctxs[idx].buf_recv);
        return 1;
    }
    return 0;
}

void io_serv()
{
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
    {
        printf("WSAStartup ok\n");
    }
    else
    {
        printf("WSAStartup error\n");
    }
    struct sockaddr_in addr;
    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
    g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (NULL == g_io_port)
    {
        printf("CreateIoCompletionPort error: %x\n", GetLastError());
        return;
    }
    memset(g_ctxs, 0, sizeof(g_ctxs));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 || listen(s, 1) < 0) { printf("error bind() or listen()\n"); return; }
    printf("Listening: %hu\n", ntohs(addr.sin_port));
    if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
    {
        printf("CreateIoCompletionPort error: %x\n", GetLastError());
        return;
    }
    g_ctxs[0].socket = s;
    schedule_accept();
    while (1)
    {
        DWORD transferred;
        ULONG_PTR key;
        OVERLAPPED* lp_overlap;
        BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
        if (b)
        {
            if (key == 0)
            {
                g_ctxs[0].sz_recv += transferred;
                add_accepted_connection();
                schedule_accept();
            }
            else
            {
                if (&g_ctxs[key].overlap_recv == lp_overlap)
                {
                    int len;
                    if (transferred == 0)
                    {
                        CancelIo((HANDLE)g_ctxs[key].socket);
                        PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
                        continue;
                    }
                    g_ctxs[key].sz_recv += transferred;
                    if (is_string_received(key, &len))
                    {
                        sprintf(g_ctxs[key].buf_send, "You string length: %d\n", len);
                        g_ctxs[key].sz_send_total = strlen(g_ctxs[key].buf_send);
                        g_ctxs[key].sz_send = 0;
                        schedule_write(key);
                    }
                    else
                    {
                        schedule_read(key);
                    }
                }
                else if (&g_ctxs[key].overlap_send == lp_overlap)
                {
                    g_ctxs[key].sz_send += transferred;
                    if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
                    {
                        schedule_write(key);
                    }
                    else
                    {
                        CancelIo((HANDLE)g_ctxs[key].socket);
                        PostQueuedCompletionStatus(g_io_port, 0, key, &g_ctxs[key].overlap_cancel);
                    }
                }
                else if (&g_ctxs[key].overlap_cancel == lp_overlap)
                {
                    closesocket(g_ctxs[key].socket);
                    memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
                    printf(" connection %u closed\n", key);
                }
            }
        }
        else
        {
            // Handle timeout or other actions
        }
    }
}

int main()
{
    setlocale(LC_ALL, "Russian");
    io_serv();
    return 0;
}
