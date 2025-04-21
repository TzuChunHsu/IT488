// main.cpp
#define _WIN32_WINNT 0x0601
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>           // EnumProcessModulesEx, GetModuleInformation, GetModuleBaseNameW
#include <commctrl.h>
#include <richedit.h>
#include <tchar.h>
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
#include <winternl.h>        // NtQueryInformationThread

// ---------------- MinHook ----------------
#include "MinHook.h"
#pragma comment(lib, "MinHook.x64.lib")   // Link x64 MinHook; swap if needed

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")

// Control IDs
#define ID_SCANALL    101
#define ID_SCANPID    102
#define ID_CLEAR      103
#define ID_EXIT       104
#define ID_SAVELOG    105
#define ID_COMBOMODE  106
#define IDC_PROGRESS  107
#define ID_SEARCHBOX  108
#define ID_SEARCHBTN  109

// Custom Windows message to signal scan completion
#define WM_SCAN_DONE  (WM_USER + 1)

// Minimum size for an executable memory region
static const SIZE_T MIN_EXECUTABLE_REGION_SIZE = 0x2000;
// ThreadInfoClass value to get Win32 start address via NtQueryInformationThread
static const ULONG THREAD_QUERY_WIN32_START = 9;

// Global window/control handles
static HWND g_hWndMain = nullptr;
static HWND g_hRichEdit = nullptr;
static HWND g_hComboMode = nullptr;
static HWND g_hProgress = nullptr;
static HWND g_hSearchBox = nullptr;
static HWND g_hEditPID = nullptr;

// Shared state
static std::mutex                        gMutex;
static std::unordered_set<std::wstring>  g_detectedSet;
static std::vector<std::wstring>         g_allLines;
static std::vector<std::wstring>         g_filtered;
static std::wstring                      g_searchText;
static int                               g_displayMode = 0; // 0=All,1=ALERT,2=DLL,3=WARNING,4=MAP
static bool                              g_isScanning = false;
static bool                              g_enableHooks = true;

// For incremental scanning: store known exec regions per PID
struct RegionInfo { uintptr_t BaseAddress; SIZE_T RegionSize; DWORD Protect; };
static std::unordered_map<DWORD, std::vector<RegionInfo>> g_knownRegions;

// 3‑step injection detection state
static std::mutex               g_handleMutex;
static std::unordered_set<HANDLE> g_allocHandles;
static std::unordered_set<HANDLE> g_writeHandles;

// -----------------------------------------------------------------------------
// Only one declaration of the NT API pointer.
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationThread)(
    HANDLE  ThreadHandle,
    ULONG   ThreadInformationClass,
    PVOID   ThreadInformation,
    ULONG   ThreadInformationLength,
    PULONG  ReturnLength
    );
static PFN_NtQueryInformationThread g_pNtQIT = nullptr;

// Original function‑pointer typedefs
typedef HANDLE(WINAPI* PFN_CreateRemoteThread)(
    HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
    LPTHREAD_START_ROUTINE, LPVOID,
    DWORD, LPDWORD);
typedef LPVOID(WINAPI* PFN_VirtualAllocEx)(
    HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* PFN_WriteProcessMemory)(
    HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef NTSTATUS(NTAPI* PFN_NtAllocateVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR*, SIZE_T*, ULONG, ULONG);
typedef NTSTATUS(NTAPI* PFN_NtProtectVirtualMemory)(
    HANDLE, PVOID*, ULONG_PTR*, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(
    HANDLE, PVOID, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* PFN_NtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS(NTAPI* PFN_RtlCreateUserThread)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
    PULONG, PULONG, PVOID, PVOID, PHANDLE, CLIENT_ID);
typedef NTSTATUS(NTAPI* PFN_NtQueueApcThread)(
    HANDLE, PVOID, PVOID, ULONG_PTR, ULONG_PTR);

static PFN_VirtualAllocEx            g_OriginalVAE = nullptr;
static PFN_WriteProcessMemory        g_OriginalWPM = nullptr;
static PFN_CreateRemoteThread        g_OriginalCRT = nullptr;
static PFN_NtAllocateVirtualMemory   g_OriginalNtAlloc = nullptr;
static PFN_NtProtectVirtualMemory    g_OriginalNtProtect = nullptr;
static PFN_NtWriteVirtualMemory      g_OriginalNtWrite = nullptr;
static PFN_NtCreateThreadEx          g_OriginalNtCreateTE = nullptr;
static PFN_RtlCreateUserThread       g_OriginalRtlCreate = nullptr;
static PFN_NtQueueApcThread          g_OriginalNtQueue = nullptr;

//----------------------------------------------------------------------------
// Get the executable name for a given PID (always closes handle)
static std::wstring GetExeNameByPid(DWORD pid) {
    std::wstring result;
    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (hProc) {
        HMODULE hMod = nullptr;
        DWORD  cb = 0;
        if (EnumProcessModulesEx(
            hProc, &hMod, sizeof(hMod), &cb, LIST_MODULES_ALL)
            && hMod)
        {
            wchar_t buf[MAX_PATH] = {};
            if (GetModuleBaseNameW(hProc, hMod, buf, MAX_PATH))
                result = buf;
        }
        CloseHandle(hProc);
    }
    return result;
}

// Unified injection report
static void ReportInjection(HANDLE hProc, uintptr_t addr, const char* api) {
    DWORD pid = GetProcessId(hProc);
    std::wstringstream ws;
    ws << L"[DLL INJECTION] PID " << pid
        << L" (" << GetExeNameByPid(pid) << L")"
        << L", Addr=0x" << std::hex << addr
        << L" (" << api << L")\r\n";
    std::lock_guard<std::mutex> lk(gMutex);
    g_allLines.push_back(ws.str());
}

//----------------------------------------------------------------------------
// Hook #1: VirtualAllocEx / NtAllocateVirtualMemory
static LPVOID WINAPI MyVirtualAllocEx(
    HANDLE hProc, LPVOID addr, SIZE_T sz,
    DWORD type, DWORD prot)
{
    std::lock_guard<std::mutex> lk(g_handleMutex);
    g_allocHandles.insert(hProc);
    return g_OriginalVAE(hProc, addr, sz, type, prot);
}

static NTSTATUS NTAPI MyNtAllocateVirtualMemory(
    HANDLE hProc, PVOID* base, ULONG_PTR* zero,
    SIZE_T* sz, ULONG type, ULONG prot)
{
    std::lock_guard<std::mutex> lk(g_handleMutex);
    g_allocHandles.insert(hProc);
    return g_OriginalNtAlloc(hProc, base, zero, sz, type, prot);
}

// Hook #2: WriteProcessMemory / NtWriteVirtualMemory / NtProtectVirtualMemory
static BOOL WINAPI MyWriteProcessMemory(
    HANDLE hProc, LPVOID base, LPCVOID buf,
    SIZE_T n, SIZE_T* written)
{
    std::lock_guard<std::mutex> lk(g_handleMutex);
    if (g_allocHandles.count(hProc))
        g_writeHandles.insert(hProc);
    return g_OriginalWPM(hProc, base, buf, n, written);
}

static NTSTATUS NTAPI MyNtWriteVirtualMemory(
    HANDLE hProc, PVOID base, PVOID buf,
    ULONG n, PULONG written)
{
    std::lock_guard<std::mutex> lk(g_handleMutex);
    if (g_allocHandles.count(hProc))
        g_writeHandles.insert(hProc);
    return g_OriginalNtWrite(hProc, base, buf, n, written);
}

static NTSTATUS NTAPI MyNtProtectVirtualMemory(
    HANDLE hProc, PVOID* base, ULONG_PTR* size,
    ULONG newProt, PULONG oldProt)
{
    std::lock_guard<std::mutex> lk(g_handleMutex);
    if (g_allocHandles.count(hProc))
        g_writeHandles.insert(hProc);
    return g_OriginalNtProtect(hProc, base, size, newProt, oldProt);
}

// Hook #3: CreateRemoteThread / NtCreateThreadEx / RtlCreateUserThread / NtQueueApcThread
static HANDLE WINAPI MyCreateRemoteThread(
    HANDLE hProc, LPSECURITY_ATTRIBUTES sa,
    SIZE_T stk, LPTHREAD_START_ROUTINE start,
    LPVOID prm, DWORD flg, LPDWORD tid)
{
    bool inj = false;
    {
        std::lock_guard<std::mutex> lk(g_handleMutex);
        if (g_writeHandles.erase(hProc)) {
            g_allocHandles.erase(hProc);
            inj = true;
        }
    }
    if (inj)
        ReportInjection(hProc, reinterpret_cast<uintptr_t>(start), "CreateRemoteThread");
    return g_OriginalCRT(hProc, sa, stk, start, prm, flg, tid);
}

static NTSTATUS NTAPI MyNtCreateThreadEx(
    PHANDLE ph, ACCESS_MASK acc, PVOID oa,
    HANDLE hProc, PVOID start, PVOID prm,
    ULONG flg, SIZE_T s1, SIZE_T s2, SIZE_T s3,
    PVOID unk)
{
    bool inj = false;
    {
        std::lock_guard<std::mutex> lk(g_handleMutex);
        if (g_writeHandles.erase(hProc)) {
            g_allocHandles.erase(hProc);
            inj = true;
        }
    }
    if (inj)
        ReportInjection(hProc, reinterpret_cast<uintptr_t>(start), "NtCreateThreadEx");
    return g_OriginalNtCreateTE(
        ph, acc, oa, hProc, start, prm, flg, s1, s2, s3, unk);
}

static NTSTATUS NTAPI MyRtlCreateUserThread(
    HANDLE hProc, PSECURITY_DESCRIPTOR sd,
    BOOLEAN susp, ULONG z, PULONG r, PULONG c,
    PVOID start, PVOID prm,
    PHANDLE ph, CLIENT_ID cid)
{
    bool inj = false;
    {
        std::lock_guard<std::mutex> lk(g_handleMutex);
        if (g_writeHandles.erase(hProc)) {
            g_allocHandles.erase(hProc);
            inj = true;
        }
    }
    if (inj)
        ReportInjection(hProc, reinterpret_cast<uintptr_t>(start), "RtlCreateUserThread");
    return g_OriginalRtlCreate(
        hProc, sd, susp, z, r, c, start, prm, ph, cid);
}

static NTSTATUS NTAPI MyNtQueueApcThread(
    HANDLE th, PVOID fn, PVOID a1,
    ULONG_PTR a2, ULONG_PTR a3)
{
    // APC always treated as injection
    ReportInjection(th, reinterpret_cast<uintptr_t>(fn), "NtQueueApcThread");
    return g_OriginalNtQueue(th, fn, a1, a2, a3);
}

//----------------------------------------------------------------------------
// Initialize / uninitialize hooks
bool InitializeApiHooks()
{
    if (MH_Initialize() != MH_OK)
        return false;

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");

#define HOOK(mod,name,fn,orig) \
    do { \
        FARPROC p = GetProcAddress(mod, name); \
        if (p) { \
            MH_CreateHook(p, fn, reinterpret_cast<LPVOID*>(&orig)); \
            MH_EnableHook(p); \
        } \
    } while(0)

    HOOK(k32, "VirtualAllocEx", MyVirtualAllocEx, g_OriginalVAE);
    HOOK(k32, "WriteProcessMemory", MyWriteProcessMemory, g_OriginalWPM);
    HOOK(k32, "CreateRemoteThread", MyCreateRemoteThread, g_OriginalCRT);
    HOOK(nt, "NtAllocateVirtualMemory", MyNtAllocateVirtualMemory, g_OriginalNtAlloc);
    HOOK(nt, "NtProtectVirtualMemory", MyNtProtectVirtualMemory, g_OriginalNtProtect);
    HOOK(nt, "NtWriteVirtualMemory", MyNtWriteVirtualMemory, g_OriginalNtWrite);
    HOOK(nt, "NtCreateThreadEx", MyNtCreateThreadEx, g_OriginalNtCreateTE);
    HOOK(nt, "RtlCreateUserThread", MyRtlCreateUserThread, g_OriginalRtlCreate);
    HOOK(nt, "NtQueueApcThread", MyNtQueueApcThread, g_OriginalNtQueue);

#undef HOOK

    return true;
}

void UninitializeApiHooks()
{
    MH_Uninitialize();
}

//----------------------------------------------------------------------------
// Enable debug privilege
static void EnableDebugPrivilege()
{
    HANDLE hToken = nullptr;
    if (OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &hToken))
    {
        LUID luid;
        if (LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        }
        CloseHandle(hToken);
    }
}

// Check whether exeName is a core system process
static bool IsSystemProcess(
    DWORD /*pid*/, const std::wstring& exeName)
{
    std::wstring low = exeName;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    static const wchar_t* sysList[] = {
        L"winlogon.exe", L"csrss.exe", L"smss.exe",
        L"lsass.exe",    L"services.exe", L"svchost.exe"
    };
    for (auto s : sysList)
        if (low == s)
            return true;
    return low.find(L"\\windows\\") != std::wstring::npos;
}

// Query thread start address via NtQueryInformationThread
static uintptr_t GetThreadStartAddress(HANDLE hThread)
{
    if (!g_pNtQIT) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        g_pNtQIT = reinterpret_cast<PFN_NtQueryInformationThread>(
            GetProcAddress(hNtdll, "NtQueryInformationThread"));
    }
    uintptr_t addr = 0;
    if (g_pNtQIT) {
        g_pNtQIT(hThread, THREAD_QUERY_WIN32_START,
            &addr, sizeof(addr), nullptr);
    }
    return addr;
}

// Return true if addr belongs to a loaded module in hProc
static bool IsAddressInModules(HANDLE hProc, uintptr_t addr)
{
    HMODULE mods[1024];
    DWORD cb = 0;
    if (!EnumProcessModulesEx(
        hProc, mods, sizeof(mods),
        &cb, LIST_MODULES_ALL))
        return false;

    size_t count = cb / sizeof(HMODULE);
    for (size_t i = 0; i < count; ++i) {
        MODULEINFO mi;
        if (GetModuleInformation(hProc, mods[i], &mi, sizeof(mi))) {
            uintptr_t base = reinterpret_cast<uintptr_t>(mi.lpBaseOfDll);
            if (addr >= base && addr < base + mi.SizeOfImage)
                return true;
        }
    }
    return false;
}

// Validate a private exec region's PE headers for manual‑map
static bool ValidatePEHeadersExtended(
    HANDLE hProc, uintptr_t base, SIZE_T size)
{
    if (size < 0x200) return false;
    BYTE sig[2]; SIZE_T r = 0;
    if (!ReadProcessMemory(
        hProc, reinterpret_cast<LPCVOID>(base),
        sig, 2, &r) || r < 2)
        return false;
    if (sig[0] != 'M' || sig[1] != 'Z')
        return false;

    IMAGE_DOS_HEADER dos;
    if (!ReadProcessMemory(
        hProc, reinterpret_cast<LPCVOID>(base),
        &dos, sizeof(dos), &r))
        return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    if (dos.e_lfanew < sizeof(dos) ||
        dos.e_lfanew > size - sizeof(IMAGE_NT_HEADERS))
        return false;

    IMAGE_NT_HEADERS nt;
    if (!ReadProcessMemory(
        hProc,
        reinterpret_cast<LPCVOID>(base + dos.e_lfanew),
        &nt, sizeof(nt), &r))
        return false;
    if (nt.Signature != IMAGE_NT_SIGNATURE)
        return false;
    if (nt.FileHeader.NumberOfSections == 0 ||
        nt.FileHeader.NumberOfSections > 100)
        return false;
    if (nt.OptionalHeader.SizeOfHeaders == 0 ||
        nt.OptionalHeader.SizeOfHeaders > nt.OptionalHeader.SizeOfImage)
        return false;
    if (nt.OptionalHeader.SizeOfImage > size)
        return false;

    return true;
}

// Forward declarations
static void CheckProcessThreads(
    DWORD pid, HANDLE hProc,
    const std::wstring& exe,
    std::vector<std::wstring>& out);
static void CheckProcessMemory(
    HANDLE hProc, DWORD pid,
    std::vector<std::wstring>& out);

// Check threads + memory for one process
static void CheckProcess(
    DWORD pid, const std::wstring& exe,
    std::vector<std::wstring>& out)
{
    if (IsSystemProcess(pid, exe))
        return;

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        DWORD e = GetLastError();
        if (e != ERROR_ACCESS_DENIED &&
            e != ERROR_INVALID_PARAMETER &&
            e != 87)
        {
            std::wstringstream ws;
            ws << L"[ALERT] OpenProcess failed on PID "
                << pid << L" (" << exe << L") Err=" << e << L"\r\n";
            out.push_back(ws.str());
        }
        return;
    }

    CheckProcessThreads(pid, hProc, exe, out);
    CheckProcessMemory(hProc, pid, out);
    CloseHandle(hProc);
}

// Gather all processes
static std::vector<std::pair<DWORD, std::wstring>> CollectAllProcesses()
{
    std::vector<std::pair<DWORD, std::wstring>> v;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                v.emplace_back(pe.th32ProcessID, pe.szExeFile);
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return v;
}

// Memory‐region scan for manual‐map vs suspicious
static void CheckProcessMemory(
    HANDLE hProc, DWORD pid,
    std::vector<std::wstring>& out)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    auto& known = g_knownRegions[pid];
    std::vector<RegionInfo> newRegs;

    uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    uintptr_t end = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(
            hProc,
            reinterpret_cast<LPCVOID>(addr),
            &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            addr += 0x1000;
            continue;
        }

        bool execRegion =
            (mbi.State == MEM_COMMIT) &&
            (mbi.Type == MEM_PRIVATE) &&
            (mbi.RegionSize >= MIN_EXECUTABLE_REGION_SIZE) &&
            (mbi.Protect & (
                PAGE_EXECUTE | PAGE_EXECUTE_READ |
                PAGE_EXECUTE_READWRITE |
                PAGE_EXECUTE_WRITECOPY));

        if (!execRegion) {
            addr += mbi.RegionSize;
            continue;
        }

        bool seen = false;
        for (const auto& k : known) {
            if (k.BaseAddress == reinterpret_cast<uintptr_t>(mbi.BaseAddress) &&
                k.RegionSize == mbi.RegionSize &&
                k.Protect == mbi.Protect) {
                seen = true;
                break;
            }
        }
        if (seen) {
            addr += mbi.RegionSize;
            continue;
        }

        // If region is inside a loaded module, skip
        if (IsAddressInModules(hProc, reinterpret_cast<uintptr_t>(mbi.BaseAddress))) {
            newRegs.push_back({ reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                                mbi.RegionSize, mbi.Protect });
            addr += mbi.RegionSize;
            continue;
        }

        // Try PE‐header validation for manual‐mapped DLLs
        bool valid = ValidatePEHeadersExtended(
            hProc,
            reinterpret_cast<uintptr_t>(mbi.BaseAddress),
            mbi.RegionSize);

        std::wstringstream ws;
        std::wstring exeName = GetExeNameByPid(pid);
        if (valid) {
            ws << L"[MANUAL MAP] PID " << pid
                << L" (" << exeName << L") => 0x"
                << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                << L", Size=0x" << std::hex << mbi.RegionSize << L"\r\n";
        }
        else {
            ws << L"[WARNING] PID " << pid
                << L" (" << exeName << L") => Executable private mem @0x"
                << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                << L", Size=0x" << std::hex << mbi.RegionSize << L"\r\n";
        }
        out.push_back(ws.str());

        newRegs.push_back({ reinterpret_cast<uintptr_t>(mbi.BaseAddress),
                            mbi.RegionSize, mbi.Protect });

        addr += mbi.RegionSize;
    }

    // Merge new regions into known
    known.insert(known.end(), newRegs.begin(), newRegs.end());
}

// Thread scan for suspicious start addresses
static void CheckProcessThreads(
    DWORD pid, HANDLE hProc,
    const std::wstring& exe,
    std::vector<std::wstring>& out)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (!Thread32First(snap, &te)) {
        CloseHandle(snap);
        return;
    }

    do {
        if (te.th32OwnerProcessID == pid &&
            pid != GetCurrentProcessId())
        {
            HANDLE th = OpenThread(
                THREAD_QUERY_INFORMATION,
                FALSE,
                te.th32ThreadID);

            if (th) {
                uintptr_t sa = GetThreadStartAddress(th);
                if (sa && !IsAddressInModules(hProc, sa)) {
                    std::wstringstream ws;
                    ws << L"[DLL INJECTION] PID " << pid
                        << L" (" << exe << L")"
                        << L", TID " << te.th32ThreadID
                        << L": 0x" << std::hex << sa << L"\r\n";
                    out.push_back(ws.str());
                }
                CloseHandle(th);
            }
            else {
                DWORD e = GetLastError();
                if (e != ERROR_ACCESS_DENIED &&
                    e != ERROR_INVALID_PARAMETER &&
                    e != 87)
                {
                    std::wstringstream ws;
                    ws << L"[ALERT] Cannot open TID "
                        << te.th32ThreadID
                        << L" in PID "
                        << pid
                        << L" (" << exe << L") Err=" << e << L"\r\n";
                    out.push_back(ws.str());
                }
            }
        }
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
}

// Scan thread parameters
struct ScanParams { bool scanAll; DWORD pid; };

// The background scan thread
static DWORD WINAPI ScanThreadProc(LPVOID param)
{
    auto* sp = static_cast<ScanParams*>(param);
    bool doAll = sp->scanAll;
    DWORD single = sp->pid;
    delete sp;

    {
        std::lock_guard<std::mutex> lk(gMutex);
        g_detectedSet.clear();
        g_allLines.clear();
        g_knownRegions.clear();
    }
    SendMessage(g_hProgress, PBM_SETPOS, 0, 0);

    auto procs = CollectAllProcesses();
    if (doAll) {
        {
            std::lock_guard<std::mutex> lk(gMutex);
            g_allLines.push_back(L"[INFO] Scanning all processes...\r\n");
        }
        SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, (LPARAM)procs.size()));

        for (size_t i = 0; i < procs.size(); ++i) {
            std::vector<std::wstring> local;
            CheckProcess(procs[i].first, procs[i].second, local);
            {
                std::lock_guard<std::mutex> lk(gMutex);
                for (auto& ln : local) {
                    if (g_detectedSet.insert(ln).second)
                        g_allLines.push_back(ln);
                }
            }
            SendMessage(g_hProgress, PBM_SETPOS, (WPARAM)(i + 1), 0);
        }
    }
    else {
        // Single PID
        std::wstring exeName;
        for (auto& p : procs)
            if (p.first == single)
                exeName = p.second;
        std::vector<std::wstring> local;
        CheckProcess(single, exeName, local);
        {
            std::lock_guard<std::mutex> lk(gMutex);
            for (auto& ln : local) {
                if (g_detectedSet.insert(ln).second)
                    g_allLines.push_back(ln);
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(gMutex);
        bool found = false;
        for (auto& s : g_allLines) {
            if (s.find(L"[ALERT]") != std::wstring::npos ||
                s.find(L"[DLL INJECTION]") != std::wstring::npos ||
                s.find(L"[WARNING]") != std::wstring::npos ||
                s.find(L"[MANUAL MAP]") != std::wstring::npos)
            {
                found = true;
                break;
            }
        }
        if (!found)
            g_allLines.push_back(L"[INFO] No suspicious found.\r\n");
        g_allLines.push_back(L"[INFO] Scan completed.\r\n");
    }

    g_isScanning = false;
    PostMessage(g_hWndMain, WM_SCAN_DONE, 0, 0);
    return 0;
}

// Search / display
static void ApplySearchFilter()
{
    g_filtered.clear();
    if (g_searchText.empty()) {
        g_filtered = g_allLines;
    }
    else {
        std::wstring low = g_searchText;
        std::transform(low.begin(), low.end(), low.begin(), ::towlower);
        for (auto& s : g_allLines) {
            std::wstring tmp = s;
            std::transform(tmp.begin(), tmp.end(), tmp.begin(), ::towlower);
            if (tmp.find(low) != std::wstring::npos)
                g_filtered.push_back(s);
        }
    }
}

static void RebuildDisplay()
{
    SETTEXTEX stx{ ST_DEFAULT, 1200 };
    SendMessage(g_hRichEdit, EM_SETTEXTEX, (WPARAM)&stx, (LPARAM)L"");

    for (auto& s : g_filtered) {
        bool pass = false;
        switch (g_displayMode) {
        case 0: pass = true; break;
        case 1: pass = (s.find(L"[ALERT]") != std::wstring::npos); break;
        case 2: pass = (s.find(L"[DLL INJECTION]") != std::wstring::npos); break;
        case 3: pass = (s.find(L"[WARNING]") != std::wstring::npos); break;
        case 4: pass = (s.find(L"[MANUAL MAP]") != std::wstring::npos); break;
        }
        if (pass) {
            SendMessage(g_hRichEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
            SendMessageW(g_hRichEdit, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
        }
    }
}

static void SaveLogToFile()
{
    OPENFILENAMEW ofn{};
    wchar_t szFile[MAX_PATH] = L"ScanLog.txt";
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Text Files\0*.txt\0All Files\0*.*\0";
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.hwndOwner = g_hWndMain;

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream ofs(szFile);
    if (!ofs) {
        MessageBoxW(g_hWndMain, L"Failed to open file for writing.", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    for (auto& s : g_filtered) ofs << s;
    ofs.close();
    MessageBoxW(g_hWndMain, L"Log saved successfully.", L"Save Log", MB_OK);
}

// WindowProc
static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_CREATE: {
        LoadLibraryW(L"Msftedit.dll");
        INITCOMMONCONTROLSEX icex{ sizeof(icex), ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);

        CreateWindowW(L"BUTTON", L"Scan All", WS_VISIBLE | WS_CHILD, 10, 10, 80, 30, hwnd, (HMENU)ID_SCANALL, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Scan PID", WS_VISIBLE | WS_CHILD, 100, 10, 80, 30, hwnd, (HMENU)ID_SCANPID, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Clear", WS_VISIBLE | WS_CHILD, 190, 10, 80, 30, hwnd, (HMENU)ID_CLEAR, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Exit", WS_VISIBLE | WS_CHILD, 280, 10, 80, 30, hwnd, (HMENU)ID_EXIT, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Save Log", WS_VISIBLE | WS_CHILD, 370, 10, 80, 30, hwnd, (HMENU)ID_SAVELOG, nullptr, nullptr);

        CreateWindowW(L"STATIC", L"Search:", WS_VISIBLE | WS_CHILD, 470, 15, 50, 20, hwnd, nullptr, nullptr, nullptr);
        g_hSearchBox = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 520, 12, 150, 24, hwnd, (HMENU)ID_SEARCHBOX, nullptr, nullptr);
        CreateWindowW(L"BUTTON", L"Find", WS_VISIBLE | WS_CHILD, 680, 10, 80, 30, hwnd, (HMENU)ID_SEARCHBTN, nullptr, nullptr);

        g_hComboMode = CreateWindowW(L"COMBOBOX", nullptr, CBS_DROPDOWNLIST | WS_CHILD | WS_VISIBLE, 10, 50, 200, 120, hwnd, (HMENU)ID_COMBOMODE, nullptr, nullptr);
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"All");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"ALERT");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"DLL INJECTION");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"WARNING");
        SendMessageW(g_hComboMode, CB_ADDSTRING, 0, (LPARAM)L"MANUAL MAP");
        SendMessageW(g_hComboMode, CB_SETCURSEL, 0, 0);

        CreateWindowW(L"STATIC", L"PID:", WS_VISIBLE | WS_CHILD, 230, 55, 30, 20, hwnd, nullptr, nullptr, nullptr);
        g_hEditPID = CreateWindowW(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER, 260, 52, 80, 24, hwnd, nullptr, nullptr, nullptr);

        g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE, 10, 80, 960, 20, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
        g_hRichEdit = CreateWindowW(L"RICHEDIT50W", L"", WS_VISIBLE | WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | WS_VSCROLL | WS_HSCROLL, 10, 110, 960, 500, hwnd, nullptr, nullptr, nullptr);

        SetWindowPos(hwnd, nullptr, 0, 0, 1000, 700, SWP_NOZORDER | SWP_NOMOVE);
        EnableDebugPrivilege();
        if (g_enableHooks) InitializeApiHooks();
        break;
    }
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_SCANALL:
            if (!g_isScanning) {
                g_isScanning = true;
                auto* sp = new ScanParams{ true, 0 };
                if (HANDLE h = CreateThread(nullptr, 0, ScanThreadProc, sp, 0, nullptr)) CloseHandle(h);
            }
            break;
        case ID_SCANPID:
            if (!g_isScanning) {
                wchar_t buf[32]{};
                GetWindowTextW(g_hEditPID, buf, _countof(buf));
                DWORD pid = wcstoul(buf, nullptr, 10);
                if (pid < 5) {
                    MessageBoxW(hwnd, L"Invalid PID (>=5)", L"Error", MB_OK | MB_ICONERROR);
                }
                else {
                    g_isScanning = true;
                    auto* sp = new ScanParams{ false,pid };
                    if (HANDLE h = CreateThread(nullptr, 0, ScanThreadProc, sp, 0, nullptr)) CloseHandle(h);
                }
            }
            break;
        case ID_CLEAR: {
            std::lock_guard<std::mutex> lk(gMutex);
            g_detectedSet.clear();
            g_allLines.clear();
            g_filtered.clear();
            g_knownRegions.clear();
            SETTEXTEX stx{ ST_DEFAULT,1200 };
            SendMessage(g_hRichEdit, EM_SETTEXTEX, (WPARAM)&stx, (LPARAM)L"");
            break;
        }
        case ID_SAVELOG:
            SaveLogToFile();
            break;
        case ID_EXIT:
            if (g_enableHooks) UninitializeApiHooks();
            PostQuitMessage(0);
            break;
        case ID_SEARCHBTN: {
            wchar_t sb[128]{};
            GetWindowTextW(g_hSearchBox, sb, _countof(sb));
            {
                std::lock_guard<std::mutex> lk(gMutex);
                g_searchText = sb;
            }
            ApplySearchFilter();
            RebuildDisplay();
            break;
        }
        case ID_COMBOMODE:
            if (HIWORD(wParam) == CBN_SELCHANGE) {
                int sel = (int)SendMessageW(g_hComboMode, CB_GETCURSEL, 0, 0);
                {
                    std::lock_guard<std::mutex> lk(gMutex);
                    g_displayMode = sel;
                }
                RebuildDisplay();
            }
            break;
        }
        break;
    case WM_SCAN_DONE:
        ApplySearchFilter();
        RebuildDisplay();
        break;
    case WM_DESTROY:
        if (g_enableHooks) UninitializeApiHooks();
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

// Entry point
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int nCmdShow)
{
    WNDCLASSW wc{};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInst;
    wc.lpszClassName = L"FinalAdvancedDetector";
    RegisterClassW(&wc);

    g_hWndMain = CreateWindowExW(0, L"FinalAdvancedDetector", L"Final Advanced Detector",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1000, 700,
        nullptr, nullptr, hInst, nullptr);

    ShowWindow(g_hWndMain, nCmdShow);
    UpdateWindow(g_hWndMain);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return (int)msg.wParam;
}
