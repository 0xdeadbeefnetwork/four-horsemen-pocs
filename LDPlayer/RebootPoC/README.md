# LDPlayer reboot chain

no kernel bug here, just a service you're allowed to overwrite. escalation lands
on the next reboot. separate from the `Ld9BoxSup.sys` lpe upstairs, this one is
pure misconfiguration.

## the hole

`LDPlayerENSvr` runs `ldplayerserviceEN.exe` as LocalSystem, Auto-start,
unsigned, and every authenticated user has Modify on the binary. so a normal user
overwrites the service image and the SCM runs it as system at boot. that's it.
that's the bug. someone shipped a world-writable system service.

## files

- `svcplant.c` the payload you drop over `ldplayerserviceEN.exe`
- `planter.c` runs a step command as another standard account without the
  batch-logon right

### svcplant.c

replaces `ldplayerserviceEN.exe`. when the SCM starts it as system at boot it's
in session 0, so it dups its system token, retargets it to the active console
session (WTSGetActiveConsoleSessionId) and CreateProcessAsUser's a cmd on
winsta0\default, a system shell on the desktop where the human is sitting. then it
sleeps ~60s so the cmd outlives the SCM giving up on the deliberately broken
service dispatcher.

writes nothing to disk. the cmd on the desktop is the only receipt.

### planter.c

runs a step command as another standard user via CreateProcessWithLogonW.
schtasks wants the batch-logon right, this doesn't, so it works from a plain
interactive account. used to stage the copy-over as the low-priv user.

## set these first

both helpers ship with placeholders, not real creds or paths. fill them in
before building:

- `planter.c`: `RUN_USER`, `RUN_DOMAIN`, `RUN_PASS`, `RUN_STEP`, the defines at
  the top, for the account and the command to run as it.
- `svcplant.c`: nothing to set, it only touches the current token and the console
  session.

## chain

1. as the normal user, overwrite `ldplayerserviceEN.exe` with your built
   `svcplant`. the Modify ACL lets you.
2. reboot, or wait for one. `LDPlayerENSvr` is Auto-start.
3. on boot the SCM runs your binary as system and a system cmd shows up on the
   console desktop.

## build

```
cl /O2 svcplant.c /link advapi32.lib wtsapi32.lib
cl /O2 planter.c  /link advapi32.lib
```

```
     -- _SiCk // afflicted.sh
```
