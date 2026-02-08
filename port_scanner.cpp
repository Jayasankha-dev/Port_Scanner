#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

class PortScanner {
private:
    std::mutex mtx;

public:
    PortScanner() {
        WSADATA wsaData;
        WSAStartup(MAKEWORD(2, 2), &wsaData);
    }

    ~PortScanner() {
        WSACleanup();
    }

    bool scanPort(const std::string& ip, int port, int timeout_ms = 800) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return false;

        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);

        sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        connect(sock, (sockaddr*)&addr, sizeof(addr));

        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        bool isOpen = false;
        if (select(0, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            int len = sizeof(so_error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
            if (so_error == 0) isOpen = true;
        }

        closesocket(sock);

        if (isOpen) {
            std::lock_guard<std::mutex> lock(mtx);
            std::cout << "[+] Port " << port << " is OPEN" << std::endl;
        }
        return isOpen;
    }

    void run(const std::string& ip, int startPort, int endPort, int maxConcurrent = 100) {
        std::cout << "[*] Scanning Host: " << ip << " (Ports " << startPort << "-" << endPort << ")\n";
        std::vector<std::thread> threads;
        std::atomic<int> openPorts{0};

        for (int port = startPort; port <= endPort; port++) {
            threads.emplace_back([this, &openPorts, ip, port]() {
                if (this->scanPort(ip, port)) openPorts++;
            });

            if (threads.size() >= maxConcurrent) {
                for (auto& t : threads) if (t.joinable()) t.join();
                threads.clear();
            }
        }
        for (auto& t : threads) if (t.joinable()) t.join();
        std::cout << "\n[!] Scan Complete. Found " << openPorts << " open ports." << std::endl;
    }
};

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cout << "Usage: port_scanner.exe <IP> <Start> <End>\n";
        return 1;
    }
    try {
        PortScanner scanner;
        scanner.run(argv[1], std::stoi(argv[2]), std::stoi(argv[3]));
    } catch (...) {
        std::cout << "[-] Error: Invalid Parameters.\n";
    }
    return 0;
}