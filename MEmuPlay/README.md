# MEmu / MEmuDrv.sys

local user to system on MEmu 9.x. virtualbox 6.1.40 supdrv fork, no hardening,
no admin needed. this one also leaves LDR_LOAD open, so it doubles as a signed
driver loader.

- driver / device: `MEmuDrv.sys` / `\Device\MEmuDrv`
- vmm module: `HPVR0.r0`

## files

- `memupoc.c` kaslr leak, full lpe, and arbitrary signed driver load
- `memu_suptable.h` preferred on-disk pfns for the base vote

## modes

```
memupoc kaslr          leak: drv base, session, dual page, nt base
memupoc lpe            full chain: vmm load, pdm call, token swap, shell
memupoc load <path>    map any signed driver into kernel space
```

## chain

open `\Device\MEmuDrv`, COOKIE (0x228204) handshake. QUERY_FUNCS (0x228208)
export pfns voted against `memu_suptable.h` gives the driver base. PAGE_ALLOC_EX
(0x228228) grabs 16 pages dual-mapped (the control block sits at +0x61c4).

unlike LDPlayer and bluestacks, LDR_LOAD (0x228210) is open here, so `load_vmm`
maps `HPVR0.r0` off disk (from `Program Files\Microvirt\MEmuHyperv\` or
`C:\memu\`) and GVMMR0CreateVM arms the call path. the big VMMR0 call (0x22826C)
runs a pdm request whose handler points at gadgets in the loaded r0, which is
your kernel rd32/wr32. from there: PsInitialSystemProcess, system's token, walk
ActiveProcessLinks, overwrite your own EPROCESS token, pop cmd on the desktop.

`load <signed.sys>` is that same LDR_LOAD path exposed directly. any validly
signed driver into the kernel, no SCM, no service install.

offsets: pid 0x1D0, links 0x1D8, token 0x248.

## build & run

```
cl /O2 memupoc.c /link advapi32.lib
x86_64-w64-mingw32-gcc -O2 memupoc.c -o memupoc.exe -ladvapi32
memupoc lpe
```

lpe and kaslr need `HPVR0.r0` reachable at one of those paths (a default MEmu
install). every stage validates a canonical kernel address first, so a version
mismatch fails quietly.

```
     -- _SiCk // afflicted.sh
```
