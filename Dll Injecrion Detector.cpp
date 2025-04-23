#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "comctl32.lib")

#define ID_BUTTON_SCAN 1001

HWND hListView;
HWND hButton;

// 檢查是否為系統進程
bool IsSystemProcess(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (hProcess) {
        char szProcessPath[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, NULL, szProcessPath, MAX_PATH)) {
            std::string processPath(szProcessPath);
            // 檢查是否位於系統目錄
            if (processPath.find("C:\\Windows") != std::string::npos) {
                CloseHandle(hProcess);
                return true;
            }
        }
        CloseHandle(hProcess);
    }
    return false;
}

// 檢查是否為白名單進程（支援寬字符）
bool IsWhitelistedProcess(const WCHAR* processName) {
    const std::vector<std::wstring> whitelist = {
        L"explorer.exe", L"msedge.exe", L"SearchHost.exe", L"StartMenuExperienceHost.exe",
        L"Widgets.exe", L"TextInputHost.exe", L"ShellExperienceHost.exe", L"OneDrive.exe",
        L"WidgetService.exe", L"msedgewebview2.exe"
    };
    for (const auto& name : whitelist) {
        if (name == processName) {
            return true;
        }
    }
    return false;
}

// 檢查是否為惡意 DLL
bool IsMaliciousDLL(const char* dllName) {
    // 這裡可以擴展為檢查 DLL 的簽名或路徑
    return (strstr(dllName, "bad.dll") != nullptr);
}

// 檢查是否有遠程線程創建
bool CheckRemoteThread(HANDLE hProcess, DWORD processID) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == processID) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    CloseHandle(hThread);
                    CloseHandle(hThreadSnap);
                    return true;
                }
            }
        } while (Thread32Next(hThreadSnap, &te));
    }

    CloseHandle(hThreadSnap);
    return false;
}

// 檢測 DLL 注入
void DetectDLLInjection(HWND hListView) {
    SendMessage(hListView, LVM_DELETEALLITEMS, 0, 0);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnap, &pe)) {
        do {
            if (!IsSystemProcess(pe.th32ProcessID) && !IsWhitelistedProcess(pe.szExeFile)) {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    HMODULE hMods[1024];
                    DWORD cbNeeded;
                    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                        for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                            char szModName[MAX_PATH];
                            if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                                if (IsMaliciousDLL(szModName)) {
                                    LVITEM lvItem = { 0 };
                                    lvItem.mask = LVIF_TEXT;
                                    lvItem.iItem = ListView_GetItemCount(hListView);
                                    lvItem.pszText = pe.szExeFile;
                                    ListView_InsertItem(hListView, &lvItem);
                                }
                            }
                        }
                    }
                    if (CheckRemoteThread(hProcess, pe.th32ProcessID)) {
                        LVITEM lvItem = { 0 };
                        lvItem.mask = LVIF_TEXT;
                        lvItem.iItem = ListView_GetItemCount(hListView);
                        lvItem.pszText = pe.szExeFile;
                        ListView_InsertItem(hListView, &lvItem);
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
}

// 按鈕點擊事件
void OnScanButtonClick() {
    DetectDLLInjection(hListView);
}

// 視窗消息處理函數
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    LVCOLUMN lvCol;

    switch (uMsg) {
    case WM_CREATE:
        hListView = CreateWindowA(WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT,
            10, 10, 460, 300, hwnd, NULL, NULL, NULL);

        lvCol = { 0 };
        lvCol.mask = LVCF_TEXT | LVCF_WIDTH;
        lvCol.cx = 200;
        lvCol.pszText = const_cast<wchar_t*>(L"Suspicious Process");
        ListView_InsertColumn(hListView, 0, &lvCol);

        hButton = CreateWindowA("BUTTON", "Scan", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            180, 320, 100, 30, hwnd, (HMENU)ID_BUTTON_SCAN, NULL, NULL);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_BUTTON_SCAN) {
            OnScanButtonClick();
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcA(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

// 主函數
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSA wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "DLLDetectionApp";
    RegisterClassA(&wc);

    HWND hwnd = CreateWindowA("DLLDetectionApp", "DLL Injection Detection Tool", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 400, NULL, NULL, hInstance, NULL);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg = { 0 };
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}