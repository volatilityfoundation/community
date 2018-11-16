# Introduction

This plugin is intended to detect 'gargoyle' attacks, in which a system timer is used to ROP into VirtualProtect and mark attack code as executable immediately before it executes, and also to mark code as non-executable immediately after its execution.

The plugin operates by enumerating system timers using the existing 'Timer' plugin, finding those with user-mode APC handers. These handlers are then emulated, via the Unicorn engine, and various suspicious behaviors are reported if present.

# Installation

Any environment with Python should work. Known-good environments are Ubuntu Bionic and Win10.

You'll need to install a couple dependencies. The definitive list of dependencies is the associated test's Dockerfile, which is currently:
```
apt-get install -y volatility python-pip
python -m pip install scp pysphere unicorn
```
Also, install distorm3. I suggest using [https://pypi.org/project/distorm3/#files](precompiled binaries).

Finally, you must install a fixed-up version of the volatility 'timers' plugin, or risk incorrect results. Copy 'timers.py.updated' over your 'volatility\plugins\malware\timers.py' and you should be good to go.

# Example

Here's an example, taken from a 64-bit Windows 10 box (the dump is in git LFS so you can follow along):

```
$ volatility --plugins=volatility-plugins --profile Win10x64_15063 -f machine-dumps/dormant.vmem gargoyle
Volatility Foundation Volatility Framework 2.6
Process      Handler    Prolog                                        Adjusted page permissions Branched to code after altering page permission Probable payload
Gargoyle.exe 0x6f0bf3ee POP RCX; POP RSP; RET; MOV EDI, EDI; PUSH RBP True                      True                                                    0x810000
```

Here, the system has found a single timer which has a user-mode payload. It has identified the owning process - Gargoyle.exe, which is the gargoyle PoC - and provided us with a pointer to the handler for any further analysis. It has shown us the first five instructions in the handler, which might immediately raises suspicion, as they appear to be a stack pivot.
The plugin has then emulated the environment, and determined that the handler has called VirtualProtectEx (as reported by 'Adjusted page permissions'). Then, the code branched to the newly-altered page ('Branched to code after altering page permission'). Finally, the address in memory of the ROP payload is provided - 0x810000 in this case.

Manual analysis to confirm the threat may then be performed.

# Options

The plugin, by default, will ignore any timers which are not associated with a valid process context (ie, those where APC->Thread points to no registered system process). This is because the timer list sometimes contains data we cannot make sense of, likely due to undocumented kernel behavior. To disable this, pass the option "ALLTIMERS".

If you'd like to see what's going on in more detail, specify --VERBOSE. You'll see each Timer being checked, and some details about the emulation process, including a brief instruction trace.

# Limitations / TODO

I'm aware of the following limitations:

* Since we observe only APCs associated with system timers, an attacker may be able to use a different method to queue an APC and remain undetected. It is unclear if this is practical.
* Because we use Capstone to detect the ROP chain which gargoyle uses, we are subject to its limitations. For example, it is unable to deal with memory paging, which causes emulation to finish prematurely under certain circumstances (such as the timer code accessing the PEB via the FS selector).
* Currently, we check only for calls to VirtualProtect and VirtualProtectEx. Malware may hide by sidestepping this and calling NtProtectVirtualMemory directly; it would be good if we can detect emulated kernel-mode transitions via Unicorn, and just detect it at the user-to-kernel transistion.
* We don't check for pure 64-bit attacks. It's not yet clear if these are possible given the x64 calling convention.
