#include <windows.h>
#include <stdio.h>

static void enable_priv(HANDLE tok, const char *name)
{
    TOKEN_PRIVILEGES tp; LUID luid;
    if(!LookupPrivilegeValueA(NULL,name,&luid)) return;
    tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok,FALSE,&tp,sizeof tp,NULL,NULL);
}

int main(void)
{
    HANDLE hTok=NULL, hDup=NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hTok)) return 1;
    enable_priv(hTok, "SeTcbPrivilege");
    enable_priv(hTok, "SeAssignPrimaryTokenPrivilege");
    if (!DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hDup)) return 1;

    DWORD sess = WTSGetActiveConsoleSessionId();
    if (sess != 0xFFFFFFFF)
        SetTokenInformation(hDup, TokenSessionId, &sess, sizeof sess);

    STARTUPINFOA si = { sizeof si };
    si.lpDesktop = (char *)"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOW;
    PROCESS_INFORMATION pi = {0};
    char cmd[] = "cmd.exe /k whoami & echo.";
    CreateProcessAsUserA(hDup, NULL, cmd, NULL, NULL, FALSE,
                         CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

    Sleep(60000);
    return 0;
}
