
---

## Contents

### `DLL Inj/`  
Contains three sample DLLs to demonstrate various injection payloads:
- **`createNewUserDLL.cpp`**  
  Allocates memory and creates a remote thread that, once executed in the target process, creates a new Windows user account.
- **`helloDLL.cpp`**  
  Allocates memory and creates a remote thread that simply shows a “Hello, DLL!” message box in the target process.
- **`reverseShell.cpp`**  
  Allocates memory and creates a remote thread that opens a reverse shell back to an attacker-controlled server.

### `Release/`  
Prebuilt binaries for immediate use:
- **`FinalAdvancedDetector.exe`**  
  The compiled 64-bit detector executable.
- Supporting DLLs, PDBs, and resources.

### `Dll Injection Detector.cpp`  
Implements the core detection logic:
1. **MinHook initialization** and hooks for all relevant APIs/NT APIs:  
   - Allocation: `VirtualAllocEx`, `NtAllocateVirtualMemory`  
   - Write: `WriteProcessMemory`, `NtWriteVirtualMemory`  
   - Protect: `VirtualProtectEx`, `NtProtectVirtualMemory`  
   - Thread creation: `CreateRemoteThread`, `RtlCreateUserThread`, `NtCreateThreadEx`
2. **Suspect-region tracking**: records every newly allocated region and marks it “written” when data or executable permissions are applied.
3. **Scan logic**:  
   - Walk all processes (or a specific PID)  
   - Enumerate their memory regions for privately committed executable pages (detect manual maps or warnings)  
   - Enumerate threads and check if the thread start address falls within a “written” suspect region → flag as `[DLL INJECTION]`. Otherwise flag as `[SUSPICIOUS THREAD]`.
4. **GUI**: simple Windows interface with buttons for “Scan All”, “Scan PID”, result filtering, progress bar, and log view.

---

## How to Use

1. Open the Release file.
2. Run the precompiled `Release/FinalAdvancedDetector.exe` (requires Windows 7+ x64).  
3. Click **Scan All** to scan every running process, or enter a PID and click **Scan PID**.
4. Use the dropdown filter to view only `[DLL INJECTION]`, `[SUSPICIOUS THREAD]`, `[WARNING]`, `[MANUAL MAP]`, or `[ALERT]` entries.
---
Google drive: https://drive.google.com/drive/folders/1Wc5JQBb5_tCWWCoueXYpdJ4flGikXWnL?usp=sharing

Feel free to open issues, request features, or contribute pull requests!
