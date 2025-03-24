/************************************************************************************
 * FinalAdvancedDetector_WithOnlineCheck (Revised & Optimized)
 *
 * Overview:
 * 1) ComboBox filtering: All / ALERT Only / SUSPICIOUS DLL Only / WARNING Only / MANUAL MAP Only
 * 2) RichEdit control for log display (avoid truncated output)
 * 3) Signature verification:
 *    (a) Offline Embedded Signature Check (using cached revocation data)
 *    (b) Online Embedded Signature Check (live check)
 *    (c) Offline Catalog Verification (using cached data)
 *    (d) Online Catalog Verification (live catalog lookup)
 * 4) Memory scanning: For memory regions (MEM_PRIVATE + PAGE_EXECUTE) that are not part of loaded modules,
 *    if the first 2 bytes form "MZ" and a valid PE header is detected, mark as [MANUAL MAP];
 *    otherwise mark as [WARNING].
 * 5) SaveLog: Output log to a text file.
 * 6) Option to skip system processes via IsSystemProcess() (default excludes common system processes).
 * 7) Single-process scan or scan-all (runs in a background thread).
 * 8) Duplicate reporting across processes is suppressed.
 *
 * Optimizations Implemented:
 * - Normal error codes from OpenProcess/OpenThread (e.g. 87, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER)
 *   are ignored to reduce false alerts.
 * - Memory regions below a minimum threshold (0x2000) are skipped.
 * - PE header validation: if "MZ" is detected, we further check for a valid NT header.
 * - Signature cache is enhanced using file modification time and size.
 *
 * Additional Method (commented):
 * - API Hooking: For example, using MinHook to hook suspicious APIs (such as NtCreateThreadEx)
 *   to immediately intercept injection attempts.
 *
 ************************************************************************************/

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <commctrl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <richedit.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <iomanip>

 // Uncomment and add the proper path if you have MinHook installed.
 // #include "MinHook.h"  
 // #pragma comment(lib, "MinHook.lib")  // Link with MinHook library if available

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

// Minimum executable region size threshold (0x2000)
const SIZE_T MIN_EXECUTABLE_REGION_SIZE = 0x2000;

// Global handles for the window and controls
HWND g_hWndMain = nullptr;
HWND g_hRichEdit = nullptr;
HWND g_hComboMode = nullptr;
HWND g_hProgress = nullptr;
HWND g_hSearchBox = nullptr;
HWND g_hEditPID = nullptr;

// Shared state (protected by gMutex)
std::mutex gMutex;
std::unordered_set<std::wstring> g_detectedSet;    // For de-duplication
std::vector<std::wstring>        g_allLines;       // Raw log lines
std::vector<std::wstring>        g_filtered;       // Filtered log lines based on search
std::wstring                     g_searchText;
int  g_displayMode = 0;  // 0=All, 1=ALERT, 2=SUSPICIOUS DLL, 3=WARNING, 4=MANUAL MAP
bool g_isScanning = false;

// Enhanced signature cache: key = file path (lowercase) + last modification time + file size.
std::unordered_map<std::wstring, std::wstring> g_sigCache;

// DLL de-duplication set: key = (PID + lower(filePath) + sigResult)
std::unordered_set<std::wstring> g_reportedDllSet;

//////////////////////////////////////////////////////////////////////////
// Helper function: Build file cache key from path, modification time and size.
std::wstring GetFileCacheKey(const std::wstring& filePath)
{
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (!GetFileAttributesExW(filePath.c_str(), GetFileExInfoStandard, &fad))
        return filePath; // fallback key

    ULARGE_INTEGER modTime, fileSize;
    modTime.LowPart = fad.ftLastWriteTime.dwLowDateTime;
    modTime.HighPart = fad.ftLastWriteTime.dwHighDateTime;
    fileSize.LowPart = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;

    std::wstringstream ws;
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    ws << lowerPath << L"|" << modTime.QuadPart << L"|" << fileSize.QuadPart;
    return ws.str();
}

//////////////////////////////////////////////////////////////////////////
// Helper function: Validate PE header within a memory region.
bool HasValidPEHeader(HANDLE hProc, uintptr_t addr, SIZE_T regionSize)
{
    if (regionSize < 0x100) // minimal size for DOS header and NT header pointer
        return false;

    IMAGE_DOS_HEADER dos = {};
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProc, (LPCVOID)addr, &dos, sizeof(dos), &bytesRead) || bytesRead != sizeof(dos))
        return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (dos.e_lfanew <= 0 || dos.e_lfanew > regionSize - sizeof(IMAGE_NT_HEADERS))
        return false;
    IMAGE_NT_HEADERS nt = {};
    if (!ReadProcessMemory(hProc, (LPCVOID)(addr + dos.e_lfanew), &nt, sizeof(nt), &bytesRead) || bytesRead != sizeof(nt))
        return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return false;
    return true;
}

//////////////////////////////////////////////////////////////////////////
// Determine whether to skip a system process (by name or if path contains "\windows\").
bool IsSystemProcess(DWORD /*pid*/, const std::wstring& exeName)
{
    std::wstring lower = exeName;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    if (lower == L"winlogon.exe" ||
        lower == L"csrss.exe" ||
        lower == L"smss.exe" ||
        lower == L"lsass.exe" ||
        lower == L"services.exe" ||
        lower == L"svchost.exe")
    {
        return true;
    }
    if (lower.find(L"\\windows\\") != std::wstring::npos)
        return true;
    return false;
}

//////////////////////////////////////////////////////////////////////////
// Enable SE_DEBUG_NAME privilege for process/thread access.
void EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
        }
        CloseHandle(hToken);
    }
}

//////////////////////////////////////////////////////////////////////////
// Verify file signature using WinVerifyTrust with given flags.
static LONG VerifyWithFlags(const std::wstring& filePath, DWORD dwRevocationFlags, DWORD dwProvFlags)
{
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    WINTRUST_DATA wtd = {};
    wtd.cbStruct = sizeof(wtd);
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.pFile = &fileInfo;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = dwRevocationFlags;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.dwProvFlags = dwProvFlags;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);

    // Close verification state
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &wtd);
    return status;
}

//////////////////////////////////////////////////////////////////////////
// Catalog signature verification (online/offline).
bool CheckCatalogSignature(const std::wstring& filePath, bool offline)
{
    DWORD provFlags = offline ? WTD_CACHE_ONLY_URL_RETRIEVAL : 0;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;
    HCATADMIN hCatAdmin = nullptr;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, &GUID_NULL, 0)) {
        CloseHandle(hFile);
        return false;
    }
    DWORD hashSize = 64;
    std::vector<BYTE> hashBuf(hashSize);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hashBuf.data(), 0)) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return false;
    }
    hashBuf.resize(hashSize);
    CloseHandle(hFile);
    HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBuf.data(), hashSize, 0, nullptr);
    bool result = false;
    while (hCatInfo && !result) {
        CATALOG_INFO ci = {};
        ci.cbStruct = sizeof(ci);
        if (CryptCATCatalogInfoFromContext(hCatInfo, &ci, 0)) {
            WINTRUST_CATALOG_INFO wtc = {};
            wtc.cbStruct = sizeof(wtc);
            wtc.pcwszCatalogFilePath = ci.wszCatalogFile;
            wtc.pcwszMemberTag = filePath.c_str();
            wtc.pcwszMemberFilePath = filePath.c_str();
            wtc.pbCalculatedFileHash = hashBuf.data();
            wtc.cbCalculatedFileHash = hashSize;
            wtc.dwCatalogVersion = 0; // optional
            WINTRUST_DATA wtd = {};
            wtd.cbStruct = sizeof(wtd);
            wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
            wtd.pCatalog = &wtc;
            wtd.dwUIChoice = WTD_UI_NONE;
            wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            wtd.dwStateAction = WTD_STATEACTION_VERIFY;
            wtd.dwProvFlags = provFlags;
            GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG st = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &policyGUID, &wtd);
            wtd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &policyGUID, &wtd);
            if (st == ERROR_SUCCESS)
                result = true;
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashBuf.data(), hashSize, 0, &hCatInfo);
    }
    if (hCatInfo)
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    return result;
}

//////////////////////////////////////////////////////////////////////////
// Advanced signature verification:
// For system files, prefer online embedded/catalog checks. For non-system files, try:
// offline embedded -> online embedded -> offline catalog -> online catalog.
// Cache the result.
std::wstring VerifyFileSignature_Advanced(const std::wstring& filePath)
{
    std::wstring cacheKey = GetFileCacheKey(filePath);
    {
        std::lock_guard<std::mutex> lk(gMutex);
        auto it = g_sigCache.find(cacheKey);
        if (it != g_sigCache.end())
            return it->second;
    }
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
    std::wstring result;
    if (lowerPath.find(L"\\windows\\") != std::wstring::npos) {
        LONG st = VerifyWithFlags(filePath, WTD_REVOKE_WHOLECHAIN, 0);
        if (st == ERROR_SUCCESS)
            result = L"Valid (Embedded-Online)";
        else if (CheckCatalogSignature(filePath, false))
            result = L"Valid (Catalog-Online)";
        else
            result = L"Valid (System Default)";
    }
    else {
        LONG st = VerifyWithFlags(filePath, WTD_REVOKE_WHOLECHAIN, WTD_CACHE_ONLY_URL_RETRIEVAL);
        if (st == ERROR_SUCCESS)
            result = L"Valid (Embedded-Offline)";
        else {
            st = VerifyWithFlags(filePath, WTD_REVOKE_WHOLECHAIN, 0);
            if (st == ERROR_SUCCESS)
                result = L"Valid (Embedded-Online)";
            else if (CheckCatalogSignature(filePath, true))
                result = L"Valid (Catalog-Offline)";
            else if (CheckCatalogSignature(filePath, false))
                result = L"Valid (Catalog-Online)";
            else
                result = L"No signature found (fallback failed)";
        }
    }
    {
        std::lock_guard<std::mutex> lk(gMutex);
        g_sigCache[cacheKey] = result;
    }
    return result;
}

//////////////////////////////////////////////////////////////////////////
// Combine PID, lower(filePath), and signature result to form a unique key for de-duplication.
std::wstring MakeDllKey(DWORD pid, const std::wstring& fullPath, const std::wstring& sigResult)
{
    std::wstring pathLower = fullPath;
    std::transform(pathLower.begin(), pathLower.end(), pathLower.begin(), ::towlower);
    std::wstringstream ws;
    ws << pid << L"|" << pathLower << L"|" << sigResult;
    return ws.str();
}

//////////////////////////////////////////////////////////////////////////
// Check if a memory region falls within any loaded module.
bool IsMemoryRegionInModule(HANDLE hProc, uintptr_t addr, SIZE_T regionSize)
{
    HMODULE mods[1024] = { 0 };
    DWORD cbNeeded = 0;
    if (EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; i++) {
            MODULEINFO mi = {};
            if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) {
                uintptr_t modBase = (uintptr_t)mi.lpBaseOfDll;
                SIZE_T modSize = mi.SizeOfImage;
                if (addr >= modBase && (addr + regionSize) <= (modBase + modSize))
                    return true;
            }
        }
    }
    return false;
}

//////////////////////////////////////////////////////////////////////////
// Scan process memory:
// Scan MEM_PRIVATE regions with executable protection and above the minimum size threshold.
// If the region is not part of a loaded module and its first two bytes are "MZ" and a valid PE header
// is detected, mark as [MANUAL MAP]; otherwise mark as [WARNING].
void CheckProcessMemory(HANDLE hProc, DWORD pid, std::vector<std::wstring>& outResults)
{
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    uintptr_t addr = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)si.lpMaximumApplicationAddress;
    BYTE signature[2] = { 0 };
    SIZE_T readSize = 0;

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            addr += 0x1000;
            continue;
        }
        if (mbi.State == MEM_COMMIT &&
            mbi.Type == MEM_PRIVATE &&
            mbi.RegionSize >= MIN_EXECUTABLE_REGION_SIZE &&
            ((mbi.Protect & PAGE_EXECUTE) ||
                (mbi.Protect & PAGE_EXECUTE_READ) ||
                (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
                (mbi.Protect & PAGE_EXECUTE_WRITECOPY)))
        {
            if (IsMemoryRegionInModule(hProc, (uintptr_t)mbi.BaseAddress, mbi.RegionSize)) {
                addr += mbi.RegionSize;
                continue;
            }
            bool validPE = false;
            if (ReadProcessMemory(hProc, (LPCVOID)addr, signature, 2, &readSize)) {
                if (readSize == 2 && signature[0] == 'M' && signature[1] == 'Z')
                    validPE = HasValidPEHeader(hProc, addr, mbi.RegionSize);
            }
            std::wstringstream ws;
            if (validPE) {
                ws << L"[MANUAL MAP] PID " << pid << L" => 0x" << std::hex << addr
                    << L", Size=" << mbi.RegionSize << L"\r\n";
            }
            else {
                ws << L"[WARNING] PID " << pid << L" => Executable private mem @0x"
                    << std::hex << addr << L", Size=" << mbi.RegionSize << L"\r\n";
            }
            outResults.push_back(ws.str());
        }
        addr += mbi.RegionSize;
    }
}

//////////////////////////////////////////////////////////////////////////
// Check a process: Perform thread, DLL, and memory checks.
void CheckProcess(DWORD pid, const std::wstring& exeName, std::vector<std::wstring>& outResults)
{
    if (IsSystemProcess(pid, exeName))
        return;

    // --- Thread check ---
    {
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = {};
            te.dwSize = sizeof(te);
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == pid && pid != GetCurrentProcessId()) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if (!hThread) {
                            DWORD err = GetLastError();
                            // Ignore expected errors
                            if (err != ERROR_ACCESS_DENIED && err != ERROR_INVALID_PARAMETER && err != 87) {
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

    // --- Process handle ---
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

    // --- DLL check ---
    {
        HMODULE hMods[1024] = { 0 };
        DWORD cbNeeded = 0;
        if (EnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded)) {
            size_t count = cbNeeded / sizeof(HMODULE);
            for (size_t i = 0; i < count; i++) {
                WCHAR modPath[MAX_PATH] = { 0 };
                if (GetModuleFileNameExW(hProc, hMods[i], modPath, MAX_PATH)) {
                    std::wstring full(modPath);
                    std::wstring sig = VerifyFileSignature_Advanced(full);
                    if (sig.find(L"Valid") == std::wstring::npos) {
                        std::wstring key = MakeDllKey(pid, full, sig);
                        if (g_reportedDllSet.insert(key).second) {
                            std::wstringstream ws;
                            ws << L"[SUSPICIOUS DLL] " << full
                                << L" => " << sig << L"\r\n";
                            outResults.push_back(ws.str());
                        }
                    }
                }
            }
        }
    }

    // --- Memory check ---
    CheckProcessMemory(hProc, pid, outResults);
    CloseHandle(hProc);
}

//////////////////////////////////////////////////////////////////////////
// Structure for process information.
struct PROCINFO {
    DWORD pid = 0;
    std::wstring exe;
};

//////////////////////////////////////////////////////////////////////////
// Collect information for all processes.
std::vector<PROCINFO> CollectAllProcesses()
{
    std::vector<PROCINFO> arr;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = {};
        pe.dwSize = sizeof(pe);
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

//////////////////////////////////////////////////////////////////////////
// Parameters for background scan thread.
struct ScanParams {
    bool  scanAll;
    DWORD pid;
};

//////////////////////////////////////////////////////////////////////////
// Background scan thread: Scan processes.
DWORD WINAPI ScanThreadProc(LPVOID param)
{
    ScanParams* sp = (ScanParams*)param;
    bool doAll = sp->scanAll;
    DWORD singlePID = sp->pid;
    delete sp;

    {
        std::lock_guard<std::mutex> lk(gMutex);
        g_detectedSet.clear();
        g_allLines.clear();
        g_reportedDllSet.clear();
        // Optionally, clear the signature cache if needed:
        // g_sigCache.clear();
    }
    SendMessage(g_hProgress, PBM_SETPOS, 0, 0);

    if (doAll) {
        {
            std::lock_guard<std::mutex> lk(gMutex);
            g_allLines.push_back(L"[INFO] Scanning all processes...\r\n");
        }
        auto vec = CollectAllProcesses();
        SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, (LPARAM)vec.size()));
        size_t idx = 0;
        for (auto& p : vec) {
            std::vector<std::wstring> local;
            CheckProcess(p.pid, p.exe, local);
            {
                std::lock_guard<std::mutex> lk(gMutex);
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
        std::wstring exname;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = {};
            pe.dwSize = sizeof(pe);
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
            std::lock_guard<std::mutex> lk(gMutex);
            for (auto& line : local) {
                if (g_detectedSet.insert(line).second) {
                    g_allLines.push_back(line);
                }
            }
        }
    }

    bool foundSusp = false;
    {
        std::lock_guard<std::mutex> lk(gMutex);
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

//////////////////////////////////////////////////////////////////////////
// Apply search filter to log lines.
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
        if (tmp.find(lower) != std::wstring::npos)
            g_filtered.push_back(line);
    }
}

//////////////////////////////////////////////////////////////////////////
// Rebuild display based on ComboBox filter selection.
void RebuildDisplay()
{
    SETTEXTEX stx = {};
    stx.flags = ST_DEFAULT;
    stx.codepage = 1200;
    SendMessage(g_hRichEdit, EM_SETTEXTEX, (WPARAM)&stx, (LPARAM)L"");
    for (auto& l : g_filtered) {
        bool pass = true;
        // Filter: 0=All, 1=ALERT, 2=SUSPICIOUS DLL, 3=WARNING, 4=MANUAL MAP
        switch (g_displayMode) {
        case 1:
            if (l.find(L"[ALERT]") == std::wstring::npos) pass = false;
            break;
        case 2:
            if (l.find(L"[SUSPICIOUS DLL]") == std::wstring::npos) pass = false;
            break;
        case 3:
            if (l.find(L"[WARNING]") == std::wstring::npos) pass = false;
            break;
        case 4:
            if (l.find(L"[MANUAL MAP]") == std::wstring::npos) pass = false;
            break;
        }
        if (pass) {
            SendMessageW(g_hRichEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
            SendMessageW(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)l.c_str());
        }
    }
}

//////////////////////////////////////////////////////////////////////////
// Save filtered log to a file.
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
    if (!GetSaveFileNameW(&ofn))
        return;
    std::wofstream ofs(szFile);
    if (!ofs) {
        MessageBoxW(g_hWndMain, L"Failed to open file for writing.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    {
        std::lock_guard<std::mutex> lk(gMutex);
        for (auto& line : g_filtered)
            ofs << line;
    }
    ofs.close();
    MessageBoxW(g_hWndMain, L"Log saved successfully.", L"Save Log", MB_OK);
}

//////////////////////////////////////////////////////////////////////////
// (Optional) API Hook example using MinHook to intercept NtCreateThreadEx.
// If you wish to enable real-time detection of injection events, you can integrate
// an API hook such as this. (You must link with a hooking library like MinHook.)
// 
// The following is a demonstration and is not integrated into the scanning flow by default.
/*
typedef NTSTATUS (WINAPI *PFN_NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD StackZeroBits,
    DWORD SizeOfStackCommit,
    DWORD SizeOfStackReserve,
    LPVOID lpBytesBuffer
);
static PFN_NtCreateThreadEx g_OriginalNtCreateThreadEx = nullptr;
NTSTATUS WINAPI MyNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    BOOL CreateSuspended,
    DWORD StackZeroBits,
    DWORD SizeOfStackCommit,
    DWORD SizeOfStackReserve,
    LPVOID lpBytesBuffer)
{
    DWORD targetPid = GetProcessId(ProcessHandle);
    wprintf(L"[HOOK] NtCreateThreadEx called on Target PID: %u, StartAddress: %p\n",
            targetPid, lpStartAddress);
    // Optionally, block the injection by returning an error code:
    // return 0xC0000022; // STATUS_ACCESS_DENIED
    return g_OriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes,
                                      ProcessHandle, lpStartAddress, lpParameter,
                                      CreateSuspended, StackZeroBits, SizeOfStackCommit,
                                      SizeOfStackReserve, lpBytesBuffer);
}
bool HookNtCreateThreadEx()
{
    if (MH_Initialize() != MH_OK)
        return false;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    LPVOID pfn = GetProcAddress(hNtdll, "NtCreateThreadEx");
    if (!pfn) return false;
    if (MH_CreateHook(pfn, &MyNtCreateThreadEx,
                      reinterpret_cast<LPVOID*>(&g_OriginalNtCreateThreadEx)) != MH_OK)
    {
        return false;
    }
    if (MH_EnableHook(pfn) != MH_OK)
        return false;
    return true;
}
*/

//////////////////////////////////////////////////////////////////////////
// Window procedure callback.
LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        // Load RichEdit library.
        LoadLibraryW(L"Msftedit.dll"); // for RICHEDIT50W
        INITCOMMONCONTROLSEX icex = {};
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
            WS_VISIBLE | WS_CHILD | WS_BORDER, 520, 12, 150, 24,
            hwnd, (HMENU)ID_SEARCHBOX, NULL, NULL);
        CreateWindowW(L"BUTTON", L"Find",
            WS_VISIBLE | WS_CHILD, 680, 10, 80, 30,
            hwnd, (HMENU)ID_SEARCHBTN, NULL, NULL);
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
            WS_VISIBLE | WS_CHILD, 210, 55, 30, 20,
            hwnd, nullptr, NULL, NULL);
        g_hEditPID = CreateWindowW(L"EDIT", L"",
            WS_VISIBLE | WS_CHILD | WS_BORDER, 240, 52, 80, 24,
            hwnd, nullptr, NULL, NULL);
        g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE, 10, 80, 960, 20,
            hwnd, (HMENU)IDC_PROGRESS, NULL, NULL);
        g_hRichEdit = CreateWindowW(L"RICHEDIT50W", L"",
            WS_VISIBLE | WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL |
            WS_VSCROLL | WS_HSCROLL, 10, 110, 960, 500,
            hwnd, nullptr, NULL, NULL);
        SetWindowPos(hwnd, nullptr, 0, 0, 1000, 700, SWP_NOZORDER | SWP_NOMOVE);

        // Enable required privileges.
        EnableDebugPrivilege();

        // (Optional) Initialize API hooks here.
        // For example, call HookNtCreateThreadEx() if you have MinHook integrated.
        // if (HookNtCreateThreadEx())
        //     SendMessageW(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)L"[INFO] NtCreateThreadEx hooked successfully.\r\n");
    }
    break;
    case WM_COMMAND:
    {
        switch (LOWORD(wParam)) {
        case ID_SCANALL:
            if (!g_isScanning) {
                g_isScanning = true;
                auto* sp = new ScanParams;
                sp->scanAll = true;
                sp->pid = 0;
                HANDLE hT = CreateThread(NULL, 0, ScanThreadProc, sp, 0, NULL);
                if (hT) CloseHandle(hT);
            }
            break;
        case ID_SCANPID:
        {
            if (!g_isScanning) {
                wchar_t buf[32] = { 0 };
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
                    if (hT) CloseHandle(hT);
                }
            }
        }
        break;
        case ID_CLEAR:
        {
            std::lock_guard<std::mutex> lk(gMutex);
            g_detectedSet.clear();
            g_allLines.clear();
            g_filtered.clear();
            g_reportedDllSet.clear();
            g_sigCache.clear();
            SETTEXTEX stx = {};
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
            wchar_t sbuf[128] = { 0 };
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
                    g_displayMode = sel;
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
        std::lock_guard<std::mutex> lk(gMutex);
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

//////////////////////////////////////////////////////////////////////////
// WinMain entry point.
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow)
{
    WNDCLASSW wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"FinalAdvancedDetector_WithOnlineCheck";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(
        0,
        L"FinalAdvancedDetector_WithOnlineCheck",
        L"Final Advanced Detector (Offline+Online SigCheck + Catalog + ManualMap)",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        NULL, NULL, hInstance, nullptr
    );
    g_hWndMain = hwnd;
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
