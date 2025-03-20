/************************************************************************************
 * FinalAdvancedDetector_WithManualMap
 *
 * 功能總覽：
 * 1) 下拉選單(ComboBox)可選擇：
 *    - All
 *    - ALERT Only
 *    - SUSPICIOUS DLL Only
 *    - WARNING Only
 *    - MANUAL MAP Only  <-- 新增
 *
 * 2) RichEdit 顯示大量掃描輸出，不會被截斷。
 * 3) WinVerifyTrust 驗簽，判斷是否 "Valid" 或 "No signature found"、"Certificate is revoked" 等。
 * 4) Memory Scan: 若某段記憶體是 MEM_PRIVATE + PAGE_EXECUTE & 有 'MZ' 簽名，即歸類為 [MANUAL MAP]。
 * 5) Save Log: 將顯示結果匯出 .txt。
 * 6) 單次掃描(背景執行緒)，跳過系統行程 (PID < 100、名稱含 "System"/"Registry"/"Memory Compression")。
 ************************************************************************************/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <fstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")

 // GUI control IDs
#define ID_SCANALL    101
#define ID_SCANPID    102
#define ID_CLEAR      103
#define ID_EXIT       104
#define ID_SAVELOG    105
#define ID_COMBOMODE  106
#define IDC_PROGRESS  107
#define ID_SEARCHBOX  108
#define ID_SEARCHBTN  109

// Custom message
#define WM_SCAN_DONE  (WM_USER + 1)

// Global handles
HWND g_hWndMain = nullptr;
HWND g_hRichEdit = nullptr;
HWND g_hComboMode = nullptr;
HWND g_hProgress = nullptr;
HWND g_hSearchBox = nullptr;
HWND g_hEditPID = nullptr;

// Shared state
std::mutex gMutex;
std::unordered_set<std::wstring> g_detectedSet;  // to deduplicate lines
std::vector<std::wstring> g_allLines;            // all raw logs
std::vector<std::wstring> g_filtered;            // after search
std::wstring g_searchText;
int  g_displayMode = 0; // 0=All, 1=ALERT, 2=SUSPICIOUS DLL, 3=WARNING, 4=MANUALMAP
bool g_isScanning = false;

// ---------------------------------------------------------------------------
// Enable debug privilege
// ---------------------------------------------------------------------------
void EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

// ---------------------------------------------------------------------------
// WinVerifyTrust => return L"Valid" or reason
// ---------------------------------------------------------------------------
std::wstring VerifyFileSignature(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL; // offline

    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &wtd);

    switch (status) {
    case ERROR_SUCCESS:
        return L"Valid";
    case TRUST_E_NOSIGNATURE:
        return L"No signature found";
    case TRUST_E_EXPLICIT_DISTRUST:
        return L"Signature is explicitly distrusted";
    case CERT_E_UNTRUSTEDROOT:
        return L"Untrusted root CA";
    case CERT_E_CHAINING:
        return L"Cannot build certificate chain";
    case CERT_E_EXPIRED:
        return L"Certificate expired";
    case CRYPT_E_REVOKED:
        return L"Certificate is revoked";
    default:
    {
        std::wstringstream ws;
        ws << L"WinVerifyTrust error: " << status;
        return ws.str();
    }
    }
}

// ---------------------------------------------------------------------------
// IsSystemProcess => skip scanning
// ---------------------------------------------------------------------------
bool IsSystemProcess(DWORD pid, const std::wstring& exeName)
{
    if (pid < 100) return true;
    std::wstring low = exeName;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    if (low.find(L"system") != std::wstring::npos ||
        low.find(L"registry") != std::wstring::npos ||
        low.find(L"memory compression") != std::wstring::npos)
    {
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Memory check: if MEM_PRIVATE + PAGE_EXECUTE => check if "MZ"
// => label "[MANUAL MAP]" in logs
// ---------------------------------------------------------------------------
void CheckProcessMemory(HANDLE hProc, DWORD pid, std::vector<std::wstring>& outResults)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)si.lpMaximumApplicationAddress;

    BYTE signature[2];
    SIZE_T readSize = 0;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += 0x1000;
            continue;
        }
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & PAGE_EXECUTE || mbi.Protect & PAGE_EXECUTE_READ ||
                mbi.Protect & PAGE_EXECUTE_READWRITE || mbi.Protect & PAGE_EXECUTE_WRITECOPY))
        {
            // read first 2 bytes
            bool hasMZ = false;
            if (ReadProcessMemory(hProc, (LPCVOID)addr, signature, 2, &readSize)) {
                if (readSize == 2 && signature[0] == 'M' && signature[1] == 'Z') {
                    hasMZ = true;
                }
            }
            std::wstringstream ws;
            if (hasMZ) {
                ws << L"[MANUAL MAP] PID " << pid << L" => 0x" << std::hex << (uintptr_t)addr
                    << L", Size=" << mbi.RegionSize << L"\r\n";
            }
            else {
                // could label [WARNING] or skip
                ws << L"[WARNING] PID " << pid << L" => Executable private mem @0x" << std::hex << addr
                    << L", Size=" << mbi.RegionSize << L"\r\n";
            }
            outResults.push_back(ws.str());
        }
        addr += mbi.RegionSize;
    }
}

// ---------------------------------------------------------------------------
// check process => threads, modules, memory
// ---------------------------------------------------------------------------
void CheckProcess(DWORD pid, const std::wstring& exeName, std::vector<std::wstring>& outResults)
{
    if (IsSystemProcess(pid, exeName)) {
        return;
    }
    // Thread check
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te; te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid && pid != GetCurrentProcessId()) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if (!hThread) {
                            DWORD err = GetLastError();
                            if (err != ERROR_ACCESS_DENIED) {
                                std::wstringstream ws;
                                ws << L"[ALERT] Could not open thread " << te.th32ThreadID
                                    << L" in PID " << pid << L" => injection? (Err=" << err << L")\r\n";
                                outResults.push_back(ws.str());
                            }
                        }
                        else {
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
    }

    // open process to read modules & memory
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) {
        DWORD err = GetLastError();
        if (err != ERROR_ACCESS_DENIED) {
            std::wstringstream ws;
            ws << L"[ALERT] OpenProcess failed on PID " << pid
                << L" => injection? (Err=" << err << L")\r\n";
            outResults.push_back(ws.str());
        }
        return;
    }

    // DLL check
    {
        HMODULE hMods[1024];
        DWORD cbNeeded = 0;
        if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            size_t count = cbNeeded / sizeof(HMODULE);
            for (size_t i = 0; i < count; i++) {
                WCHAR modPath[MAX_PATH] = {};
                if (GetModuleFileNameExW(hProc, hMods[i], modPath, MAX_PATH)) {
                    std::wstring full(modPath);
                    std::wstring sig = VerifyFileSignature(full);
                    if (sig != L"Valid") {
                        std::wstringstream ws;
                        ws << L"[SUSPICIOUS DLL] " << full << L" => " << sig << L"\r\n";
                        outResults.push_back(ws.str());
                    }
                }
            }
        }
    }

    // Memory check => detect manual map or other suspicious
    CheckProcessMemory(hProc, pid, outResults);

    CloseHandle(hProc);
}

// ---------------------------------------------------------------------------
// CollectAll => vector of {pid, exeName}
// ---------------------------------------------------------------------------
struct PROCINFO {
    DWORD pid;
    std::wstring exe;
};

std::vector<PROCINFO> CollectAllProcesses()
{
    std::vector<PROCINFO> arr;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                PROCINFO pi;
                pi.pid = pe.th32ProcessID;
                pi.exe = pe.szExeFile;
                arr.push_back(pi);
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return arr;
}

// ---------------------------------------------------------------------------
// BG thread param
// ---------------------------------------------------------------------------
struct ScanParams {
    bool  scanAll;
    DWORD pid;
};

// ---------------------------------------------------------------------------
// BG thread => scanning
// ---------------------------------------------------------------------------
DWORD WINAPI ScanThreadProc(LPVOID param)
{
    ScanParams* sp = (ScanParams*)param;
    bool doAll = sp->scanAll;
    DWORD singlePID = sp->pid;
    delete sp;

    {
        std::lock_guard<std::mutex>lk(gMutex);
        g_detectedSet.clear();
        g_allLines.clear();
    }
    SendMessage(g_hProgress, PBM_SETPOS, 0, 0);

    if (doAll) {
        std::lock_guard<std::mutex>lk(gMutex);
        g_allLines.push_back(L"[INFO] Scanning all processes...\r\n");
    }
    else {
        std::wstringstream ws;
        ws << L"[INFO] Scanning PID " << singlePID << L"...\r\n";
        {
            std::lock_guard<std::mutex>lk(gMutex);
            g_allLines.push_back(ws.str());
        }
    }

    if (doAll) {
        auto vec = CollectAllProcesses();
        SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, (LPARAM)vec.size()));
        size_t idx = 0;
        for (auto& p : vec) {
            std::vector<std::wstring> local;
            CheckProcess(p.pid, p.exe, local);
            {
                std::lock_guard<std::mutex>lk(gMutex);
                for (auto& line : local) {
                    if (g_detectedSet.insert(line).second) {
                        g_allLines.push_back(line);
                    }
                }
            }
            idx++;
            SendMessage(g_hProgress, PBM_SETPOS, (WPARAM)idx, 0);
        }
    }
    else {
        // find exeName
        std::wstring exname;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
            if (Process32First(snap, &pe)) {
                do {
                    if (pe.th32ProcessID == singlePID) {
                        exname = pe.szExeFile;
                        break;
                    }
                } while (Process32Next(snap, &pe));
            }
            CloseHandle(snap);
        }
        std::vector<std::wstring> local;
        CheckProcess(singlePID, exname, local);
        {
            std::lock_guard<std::mutex>lk(gMutex);
            for (auto& line : local) {
                if (g_detectedSet.insert(line).second) {
                    g_allLines.push_back(line);
                }
            }
        }
    }

    bool foundSusp = false;
    {
        std::lock_guard<std::mutex>lk(gMutex);
        for (auto& ln : g_allLines) {
            if (ln.find(L"[ALERT]") != std::wstring::npos ||
                ln.find(L"[SUSPICIOUS") != std::wstring::npos ||
                ln.find(L"[WARNING]") != std::wstring::npos ||
                ln.find(L"[MANUAL MAP]") != std::wstring::npos)
            {
                foundSusp = true;
                break;
            }
        }
        if (!foundSusp) {
            g_allLines.push_back(L"[INFO] No suspicious found.\r\n");
        }
        g_allLines.push_back(L"[INFO] Scan completed.\r\n");
    }

    g_isScanning = false;
    PostMessage(g_hWndMain, WM_SCAN_DONE, 0, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Searching
// ---------------------------------------------------------------------------
void ApplySearchFilter()
{
    g_filtered.clear();
    if (g_searchText.empty()) {
        g_filtered = g_allLines;
        return;
    }
    std::wstring lower = g_searchText;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (auto& line : g_allLines) {
        std::wstring tmp = line;
        std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::towlower);
        if (tmp.find(lower) != std::wstring::npos) {
            g_filtered.push_back(line);
        }
    }
}

// ---------------------------------------------------------------------------
// RebuildDisplay => depends on g_displayMode
// ---------------------------------------------------------------------------
void RebuildDisplay()
{
    // clear RichEdit
    SETTEXTEX stx;
    stx.flags = ST_DEFAULT;
    stx.codepage = 1200;
    SendMessage(g_hRichEdit, EM_SETTEXTEX, (WPARAM)&stx, (LPARAM)L"");

    for (auto& l : g_filtered) {
        bool pass = true;
        // 0=All, 1=ALERT, 2=SUSPICIOUS, 3=WARNING, 4=MANUAL MAP
        switch (g_displayMode) {
        case 1: // ALERT
            if (l.find(L"[ALERT]") == std::wstring::npos) pass = false;
            break;
        case 2: // SUSPICIOUS DLL
            if (l.find(L"[SUSPICIOUS DLL]") == std::wstring::npos) pass = false;
            break;
        case 3: // WARNING
            if (l.find(L"[WARNING]") == std::wstring::npos) pass = false;
            break;
        case 4: // MANUAL MAP
            if (l.find(L"[MANUAL MAP]") == std::wstring::npos) pass = false;
            break;
        }
        if (pass) {
            SendMessageW(g_hRichEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
            SendMessageW(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)l.c_str());
        }
    }
}

// ---------------------------------------------------------------------------
// SaveLog => write g_filtered to .txt
// ---------------------------------------------------------------------------
void SaveLogToFile()
{
    OPENFILENAMEW ofn = {};
    wchar_t szFile[MAX_PATH] = L"ScanLog.txt";
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Text Files\0*.txt\0All\0*.*\0";
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.hwndOwner = g_hWndMain;

    if (!GetSaveFileNameW(&ofn)) {
        return; // user canceled
    }
    std::wofstream ofs(szFile);
    {
        std::lock_guard<std::mutex>lk(gMutex);
        for (auto& line : g_filtered) {
            ofs << line;
        }
    }
    ofs.close();
    MessageBoxW(g_hWndMain, L"Log saved successfully.", L"Save Log", MB_OK);
}

// ---------------------------------------------------------------------------
// WindowProc
// ---------------------------------------------------------------------------
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        LoadLibraryW(L"Msftedit.dll"); // for RICHEDIT50W

        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(icex);
        icex.dwICC = ICC_PROGRESS_CLASS;
        InitCommonControlsEx(&icex);

        CreateWindowW(L"BUTTON", L"Scan All",
            WS_VISIBLE | WS_CHILD, 10, 10, 80, 30,
            hwnd, (HMENU)ID_SCANALL, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Scan PID",
            WS_VISIBLE | WS_CHILD, 100, 10, 80, 30,
            hwnd, (HMENU)ID_SCANPID, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Clear",
            WS_VISIBLE | WS_CHILD, 190, 10, 80, 30,
            hwnd, (HMENU)ID_CLEAR, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Exit",
            WS_VISIBLE | WS_CHILD, 280, 10, 80, 30,
            hwnd, (HMENU)ID_EXIT, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Save Log",
            WS_VISIBLE | WS_CHILD, 370, 10, 80, 30,
            hwnd, (HMENU)ID_SAVELOG, NULL, NULL);

        CreateWindowW(L"STATIC", L"Search:",
            WS_VISIBLE | WS_CHILD, 470, 15, 50, 20,
            hwnd, nullptr, NULL, NULL);

        g_hSearchBox = CreateWindowW(L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            520, 12, 150, 24,
            hwnd, (HMENU)ID_SEARCHBOX, NULL, NULL);

        CreateWindowW(L"BUTTON", L"Find",
            WS_VISIBLE | WS_CHILD,
            680, 10, 80, 30,
            hwnd, (HMENU)ID_SEARCHBTN, NULL, NULL);

        // Combo Mode
        g_hComboMode = CreateWindowW(L"COMBOBOX", NULL,
            CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE,
            10, 50, 180, 100,
            hwnd, (HMENU)ID_COMBOMODE, NULL, NULL);

        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"All");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"ALERT Only");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"SUSPICIOUS DLL Only");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"WARNING Only");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"MANUAL MAP Only");
        SendMessageW(g_hComboMode, CB_SETCURSEL, 0, 0);

        CreateWindowW(L"STATIC", L"PID:",
            WS_VISIBLE | WS_CHILD,
            210, 55, 30, 20,
            hwnd, nullptr, NULL, NULL);

        g_hEditPID = CreateWindowW(L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER,
            240, 52, 80, 24,
            hwnd, nullptr, NULL, NULL);

        g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE,
            10, 80, 960, 20,
            hwnd, (HMENU)IDC_PROGRESS, NULL, NULL);

        g_hRichEdit = CreateWindowW(L"RICHEDIT50W", L"",
            WS_VISIBLE | WS_CHILD |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
            WS_VSCROLL | WS_HSCROLL,
            10, 110, 960, 500,
            hwnd, nullptr, NULL, NULL);

        // enlarge to 1000x700
        SetWindowPos(hwnd, nullptr, 0, 0, 1000, 700, SWP_NOZORDER | SWP_NOMOVE);

        EnableDebugPrivilege();
    }
    break;

    case WM_COMMAND:
    {
        switch (LOWORD(wParam)) {
        case ID_SCANALL:
        {
            if (!g_isScanning) {
                g_isScanning = true;
                auto* sp = new ScanParams;
                sp->scanAll = true;
                sp->pid = 0;
                HANDLE hT = CreateThread(NULL, 0, ScanThreadProc, sp, 0, NULL);
                CloseHandle(hT);
            }
        }
        break;
        case ID_SCANPID:
        {
            if (!g_isScanning) {
                wchar_t buf[32] = {};
                GetWindowTextW(g_hEditPID, buf, 32);
                DWORD pid = (DWORD)wcstoul(buf, nullptr, 10);
                if (pid < 5) {
                    MessageBoxW(hwnd, L"Invalid PID (>=5)", L"Error", MB_OK | MB_ICONERROR);
                }
                else {
                    g_isScanning = true;
                    auto* sp = new ScanParams;
                    sp->scanAll = false;
                    sp->pid = pid;
                    HANDLE hT = CreateThread(NULL, 0, ScanThreadProc, sp, 0, NULL);
                    CloseHandle(hT);
                }
            }
        }
        break;
        case ID_CLEAR:
        {
            std::lock_guard<std::mutex>lk(gMutex);
            g_detectedSet.clear();
            g_allLines.clear();
            g_filtered.clear();
            // clear RichEdit
            SETTEXTEX stx;
            stx.flags = ST_DEFAULT;
            stx.codepage = 1200;
            SendMessage(g_hRichEdit, EM_SETTEXTEX, (WPARAM)&stx, (LPARAM)L"");
        }
        break;
        case ID_EXIT:
            PostQuitMessage(0);
            break;
        case ID_SAVELOG:
            SaveLogToFile();
            break;
        case ID_SEARCHBTN:
        {
            wchar_t sbuf[128] = {};
            GetWindowTextW(g_hSearchBox, sbuf, 128);
            {
                std::lock_guard<std::mutex> lk(gMutex);
                g_searchText = sbuf;
            }
            ApplySearchFilter();
            RebuildDisplay();
        }
        break;
        case ID_COMBOMODE:
        {
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_hComboMode, CB_GETCURSEL, 0, 0);
                {
                    std::lock_guard<std::mutex> lk(gMutex);
                    g_displayMode = sel; // 0=All,1=ALERT,2=SUSPICIOUS,3=WARNING,4=MANUAL MAP
                }
                RebuildDisplay();
            }
        }
        break;
        }
    }
    break;

    case WM_SCAN_DONE:
    {
        std::lock_guard<std::mutex>lk(gMutex);
        ApplySearchFilter();
        RebuildDisplay();
    }
    break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// wWinMain
// ---------------------------------------------------------------------------
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow)
{
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"FinalAdvancedDetector_WithManualMap";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(
        0,
        L"FinalAdvancedDetector_WithManualMap",
        L"Final Advanced Detector (RichEdit + WinVerifyTrust + ManualMap + Categorized Combo)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1000, 700,
        NULL, NULL,
        hInstance, nullptr
    );
    g_hWndMain = hwnd;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
