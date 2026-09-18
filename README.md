# four-horsemen-pocs
what happens when multiple products fork a driver and strip it's security?


four android emulators. four kernel LPEs. one root cause.

they all ship a stale fork of the virtualbox support driver (VBoxDrv / VBoxSup)
with the hardening filed off. the cookie gate that's supposed to authenticate
callers waves everyone through. LDR_LOAD, which upstream disabled for a reason,
is left wide open on two of them. the whole SUPDrv ioctl surface sits on a device
object any logged-in user can open. from there it's one VMMR0 call to a kernel
read/write, and one write to drop system's token onto your own process.

none of this is clever. it's the same bug class virtualbox hardened against years
ago, vendored once and never rebased, then shipped again under five different
names. rename the driver, keep the hole.

## on "responsible" disclosure

someone always asks why this is just going out. here's why.

responsible disclosure is a fantastic arrangement if you're the vendor. you get a
free audit, you get to hold the report as long as you like, and the person who
did the work carries all the risk while your legal team decides whether to say
thank you or send a letter. the users stay exposed the entire time and nobody
tells them.

 my last bug took **116+ days to triage**. not to fix. to triage. in the end the info which wasn't
 public is now public and case closed.

so no embargo. patch it, don't patch it, your call, but the people actually
running these things find out the same day you do. that's the whole disagreement.
116 days. lol.

## the targets

| dir | driver / device | version | notes |
|---|---|---|---|
| [LDPlayer](LDPlayer/) | `Ld9BoxSup.sys` / `\Device\Ld9BoxDrv` | LDPlayer 9, vbox 6.1.50 fork | reuses resident `Ld9VMMR0.r0` |
| [MEmuPlay](MEmuPlay/) | `MEmuDrv.sys` / `\Device\MEmuDrv` | MEmu 9.x, vbox 6.1.40 fork | LDR_LOAD open, loads `HPVR0.r0` |
| [MSIAppPlayer](MSIAppPlayer/) | `BstkDrv_nxt` / `\Device\BstkDrv_nxt` | bluestacks/MSI 5.22.261.1001 | reuses resident `BstkVMMR0_nxt.r0` |
| [NoxPlayer](NoxPlayer/) | `YSDrv` / `\Device\YSDrv` | Nox 7.0.6.1, vbox supdrv fork | LDR_LOAD open |

MSI app player is a bluestacks rebrand. same driver, same gadgets, different logo.

## the technique

same dance every time:

1. open the `\Device\...`. no admin, no gate.
2. `COOKIE` (0x228204) handshake, say the magic word, get the session cookie pair.
3. `QUERY_FUNCS` (0x228208) hands back the export table with live kernel pfns.
   subtract the on-disk RVAs (the `*_suptable.h` votes), take the majority, that's
   the driver base. `LDR_OPEN` (0x22820C) leaks the resident VMMR0 base.
4. `PAGE_ALLOC_EX` (0x228228) for a page mapped in both user and kernel (the
   pDrvIns alias). `GVMMR0CreateVM` for a private VM so the big VMMR0 path is live.
5. point the VMMR0 request handler at a mov-reg / mov-mem gadget inside the
   resident r0. rcx/edx/r8 are yours, eax comes back. that's rd32/wr32 anywhere.
6. walk ntoskrnl to `PsInitialSystemProcess`, read system's EPROCESS, walk
   `ActiveProcessLinks` to your own, copy system's token over yours. spawn cmd on
   the desktop as system.

MEmu and Nox also leave `LDR_LOAD` (0x228210) open, so their `load <signed.sys>`
mode maps any signed driver into the kernel without touching the SCM.

EPROCESS offsets throughout (win11 26200): pid 0x1D0, links 0x1D8, token 0x248.

## build

windows x64, msvc or mingw:

```
cl /O2 LDPlayer\ldpoc.c /link advapi32.lib
x86_64-w64-mingw32-gcc -O2 LDPlayer/ldpoc.c -o ldpoc.exe -ladvapi32
```

each poc has its own readme with the exact gadgets, offsets and run notes. the
offsets are version-locked. on any build but the one listed the leak or the gadget
resolve just fails, it validates a kernel address before it touches
anything, so a mismatch dies quietly instead of eating the box. run it against
your own machines and the versions named. i'm not your babysitter.
fuck responsible disclosure.

```
     -- _SiCk // afflicted.sh
```
