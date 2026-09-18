#include <windows.h>
#include <stdio.h>

#define RUN_USER   L"USERNAME"
#define RUN_DOMAIN L"."
#define RUN_PASS   L"PASSWORD"
#define RUN_STEP   L"cmd.exe /c C:\\path\\to\\step.bat"

int main(void)
{
    STARTUPINFOW si = { sizeof si };
    PROCESS_INFORMATION pi = {0};
    BOOL ok = CreateProcessWithLogonW(RUN_USER, RUN_DOMAIN, RUN_PASS, 0,
        L"C:\\Windows\\System32\\cmd.exe",
        (LPWSTR)RUN_STEP,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    printf("cpwl %d err %lu\n", ok, GetLastError());
    if (ok) {
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD c = 0;
        GetExitCodeProcess(pi.hProcess, &c);
        printf("step exit %lu\n", c);
    }
    return 0;
}
