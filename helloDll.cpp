#include <windows.h>
#include <shlobj.h>   // 取得桌面路徑
#include <fstream>
#include <string>

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int nCmdShow)
{
    MessageBoxW(NULL, L"Hello DLL", L"Hello DLL", MB_OK | MB_ICONINFORMATION);
    WCHAR desktopPath[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, desktopPath)))
    {
        std::wstring filePath = std::wstring(desktopPath) + L"\\Hello DLL.txt";
        std::wofstream file(filePath);
        if (file.is_open())
        {
            file << L"Hello DLL";
            file.close();
        }
    }
    return 0;
}
