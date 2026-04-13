# Evasion Techniques Catalog — Research Notes

## Sources
- dev.to/excalibra: EDR/XDR Bypass and Detection Evasion Techniques (2026)
- ired.team: Detecting Hooked Syscall Functions
- whiteknightlabs.com: LayeredSyscall, ETW Bypass
- malwaretech.com: Bypassing User Mode EDR Hooks
- redops.at: Hell's Gate direct syscalls
- outflank.nl: Direct System Calls + sRDI
- windshock.github.io: Endpoint Evasion Techniques 2020-2025

## 1. API Unhooking

### Detection: EDR hooks ntdll.dll/kernel32.dll entry points with JMP instructions
### Evasion Techniques:
- **Memory-scan unhooking**: Compare in-memory DLL vs on-disk, overwrite hooked bytes with clean copy
- **Cross-process ntdll refresh**: Read clean ntdll from explorer.exe/svchost.exe memory, write to current process
- **Custom PE loader**: Load fresh DLL copy, perform relocation, overwrite .TEXT section
- **Perun's Fart**: Map clean ntdll from \KnownDlls\ntdll.dll section object
- **Hell's Gate**: Dynamically resolve syscall numbers from ntdll.dll export table at runtime

### Vendor-Specific Notes:
- Bitdefender: Hooks concentrated at ntdll.dll syscall entry points
- CrowdStrike: Kernel-level validation cross-checks user-mode code integrity
- SentinelOne: Advanced kernel behavioral analysis, user-mode unhooking alone insufficient

## 2. BOF (Beacon Object File) In-Memory Execution

### Detection: Process creation, DLL loading, file writes
### Evasion Techniques:
- **COFF-based execution**: No disk writes, no new process creation
- **Inline-execute**: Run BOF within existing Beacon process context
- **Manual DLL mapping**: Avoid LoadLibrary entirely, map DLL sections manually
- **Modular architecture**: Small purpose-specific modules loaded on-demand

### Vendor-Specific Notes:
- CrowdStrike: Traditional process injection readily detected, BOF inline-execute preferred
- EDR logs show no process creation events, only generic memory allocation

## 3. Indirect/Direct System Calls

### Detection: User-mode API hooks, syscall instruction monitoring
### Evasion Techniques:
- **Direct syscalls**: Bypass ntdll.dll hooks by executing syscall instruction directly
- **Indirect syscalls**: Route syscall through legitimate code paths (function pointers, jump tables)
- **Hell's Gate**: Dynamically resolve syscall numbers at runtime
- **Halo's Gate**: Resolve syscall numbers by reading neighboring syscall stubs when target is hooked
- **Tartarus' Gate**: Extended Halo's Gate with additional fallback resolution
- **LayeredSyscall**: Abuse VEH (Vectored Exception Handling) for indirect syscalls with legitimate call stacks
- **SysWhispers3**: Generate syscall stubs with randomized call stack spoofing

### Vendor-Specific Notes:
- Wazuh: Primarily user-mode hooking, indirect calls substantially reduce detection
- SentinelOne: Kernel-level behavioral analysis, indirect calls alone may still be identified
- Modern EDRs: Monitoring syscall frequency, context, and sequence anomalies

## 4. ETW (Event Tracing for Windows) Evasion

### Detection: ETW providers feed telemetry to EDR (process, file, network, memory events)
### Key ETW Providers Targeted:
- Microsoft-Windows-Threat-Intelligence
- Microsoft-Windows-Kernel-Process
- Microsoft-Windows-DotNETRuntime (for .NET/PowerShell)

### Evasion Techniques:
- **EtwEventWrite patching**: Overwrite function prologue with RET instruction
- **NtSetInformationProcess**: Suppress ETW per-process with specific ProcessInformationClass
- **Registry modification**: Disable ETW providers via registry keys (requires admin)
- **Provider GUID manipulation**: Remove or redirect specific ETW provider subscriptions
- **ETW consumer disruption**: Kill or suspend ETW consumer processes/threads

### Vendor-Specific Notes:
- Microsoft Defender: ETW is primary telemetry source; patching EtwEventWrite breaks behavioral correlation
- Kernel-protected ETW events becoming resistant to user-mode patching in newer Windows builds

## 5. Kernel Callback Evasion

### Detection: PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine
### Evasion Techniques:
- **Callback list manipulation**: Locate and remove EDR callback entries from kernel linked lists
- **BYOVD (Bring Your Own Vulnerable Driver)**: Load signed vulnerable driver for kernel R/W
- **Malicious driver injection**: Custom driver to enumerate and remove callbacks
- **Undocumented API abuse**: Forcibly unregister callbacks via internal kernel APIs
- **Callback pointer obfuscation**: Replace callback with benign stub function

### Risk: BSOD, system instability, PatchGuard detection
### Vendor-Specific Notes:
- Modern EDRs implement callback list encryption, periodic integrity verification, pointer obfuscation

## 6. AMSI (Antimalware Scan Interface) Bypass

### Detection: Script content inspection before execution (PowerShell, VBScript, JScript, .NET)
### Evasion Techniques:
- **AmsiScanBuffer patching**: Overwrite function to always return AMSI_RESULT_CLEAN
- **AmsiInitFailed forcing**: Set amsiContext to null/invalid to force initialization failure
- **CLR hooking**: Hook .NET CLR methods that call AMSI
- **Obfuscation**: String concatenation, encoding, variable substitution to evade signatures
- **Reflection-based bypass**: Use .NET reflection to modify AMSI internals
- **COM hijacking**: Redirect AMSI COM object to benign implementation

### Vendor-Specific Notes:
- CrowdStrike: Investigates patchless AMSI bypass attacks, monitors for AmsiScanBuffer modifications
- Microsoft Defender: AMSI is primary script defense; bypass is high-severity behavioral indicator

## 7. Sleep Obfuscation

### Detection: Memory scanning during process idle states
### Evasion Techniques:
- **Foliage**: Encrypt memory regions during sleep, queue wakeup via NtApcQueueThread
- **Ekko**: Timer-based sleep with memory encryption using RtlCreateTimer
- **Morpheus**: Polymorphic sleep with randomized encryption keys per cycle
- **Stack spoofing**: Modify return addresses on stack during sleep to appear legitimate

## 8. Multi-Technique Combinations

### Scheme 1: Indirect Syscalls + ETW Patching
- Indirect syscalls for memory allocation/write, ETW patch prevents behavioral logging
- End-to-end silence across execution, memory, and telemetry phases

### Scheme 2: PowerShell In-Memory + Sleep Obfuscation
- IEX + WebClient for fileless download, sleep obfuscation encrypts memory during idle
- Evades both file-based and memory-based scanning

### Scheme 3: BOF + Unhooking + Indirect Syscalls
- Unhook ntdll first, then use indirect syscalls within BOF context
- No process creation, no API hooks, no ETW events

## 9. BYOVD (Bring Your Own Vulnerable Driver)

### Detection: Driver loading, known vulnerable driver signatures
### Evasion Techniques:
- Load legitimately signed but vulnerable kernel driver
- Use driver's R/W primitives to disable EDR kernel callbacks
- Known vulnerable drivers: Dell dbutil_2_3.sys, MSI RTCore64.sys, Capcom.sys, etc.
- Microsoft maintains a vulnerable driver blocklist (HVCI)

## 10. Process Injection Alternatives

### Detection: VirtualAllocEx + WriteProcessMemory + CreateRemoteThread chain
### Evasion Techniques:
- **Thread pool abuse**: Queue work items to existing thread pool (no new thread creation)
- **APC injection**: Queue APCs to existing threads (NtQueueApcThread)
- **Callback-based execution**: Abuse legitimate callbacks (PTP_WORK, PTP_TIMER)
- **Module stomping**: Overwrite legitimate DLL's .text section in memory
- **Phantom DLL hollowing**: Map and hollow a DLL that's never loaded
- **Transacted hollowing**: Use NTFS transactions to create temporary file-backed sections

## 11. Network-Level Evasion

### Detection: IDS/IPS, DPI, SSL inspection, proxy analysis
### Evasion Techniques:
- **Domain fronting**: Use CDN to mask C2 traffic behind legitimate domains
- **DNS over HTTPS (DoH)**: Encrypt DNS queries to bypass DNS monitoring
- **Protocol tunneling**: Encapsulate C2 in legitimate protocols (HTTP/S, DNS, ICMP)
- **Malleable C2 profiles**: Customize C2 traffic to mimic legitimate web traffic
- **JA3/JA3S randomization**: Randomize TLS fingerprints to evade JA3 matching
- **Certificate pinning bypass**: Use legitimate certificates or rotate frequently
- **Traffic fragmentation**: Split payloads across multiple packets to evade DPI
- **Encrypted channels with legitimate services**: Use cloud storage APIs, Slack, Discord as C2

## 12. Host-Level Evasion

### Detection: Sysmon, auditd, file integrity monitoring, host firewall
### Evasion Techniques:
- **Sysmon config extraction**: Read Sysmon config to understand what's monitored, avoid those patterns
- **Sysmon driver unload**: Fltmc unload SysmonDrv (requires admin)
- **Sysmon event filtering**: Manipulate event IDs to avoid logged categories
- **Auditd rule evasion**: Identify monitored syscalls, use alternative paths
- **Timestomping**: Modify file timestamps to blend with legitimate files
- **Log tampering**: Clear or modify event logs (requires admin)
- **Living off the land**: Use built-in OS tools (certutil, bitsadmin, mshta) to avoid new file creation
