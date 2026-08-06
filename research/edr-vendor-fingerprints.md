# EDR/AV Vendor Fingerprint Database

## Source: github.com/websec/Security-Software-Process-and-Driver-Names + vendor docs

### EDR Products (Endpoint Detection & Response)

| Vendor | Product | Process Names | Driver Names | Kernel Mode | Service Names |
|--------|---------|--------------|-------------|-------------|---------------|
| CrowdStrike | Falcon | CSFalconService.exe | csfalcondrv.sys, csagent.sys | Y | CsFalconService, csagent |
| SentinelOne | Singularity | SentinelAgent.exe, SentinelServiceHost.exe, SentinelStaticEngine.exe | sentinelmonitor.sys | Y | SentinelAgent, SentinelStaticEngine |
| Microsoft | Defender for Endpoint | MsMpEng.exe, MsSense.exe, SenseIR.exe | WdFilter.sys, wdk.sys, WdNisDrv.sys | Y | WinDefend, Sense, WdNisSvc |
| Carbon Black | EDR/Cloud | cb.exe, RepMgr.exe, CbDefense.exe | carbonblackk.sys, CbELAM.sys | Y | CarbonBlack, CbDefense |
| Palo Alto | Cortex XDR | CyveraService.exe, CyveraConsole.exe, traps.exe, trapsagent.exe, trapsd.exe | cyverak.sys, tladriver.sys | Y | CyveraService, Traps |
| Sophos | Intercept X / XDR | SAVService.exe, SAVAdminService.exe, SophosHealth.exe | saviorsys.sys, hmpalert.sys, sophosed.sys | Y | SAVService, SAVAdminService |
| Elastic | Endpoint Security | elastic-endpoint.exe | elastic-endpoint.sys | Y | ElasticEndpoint |
| FireEye/Trellix | Endpoint Security | xagt.exe, FireSvc.exe | fe_sysmon.sys, FEWPP.sys | Y | xagt, FireSvc |
| Cybereason | Defense Platform | CybereasonRansomFreeService.exe, minionhost.exe | Cybereason.sys | Y | CybereasonActiveProbe |
| Tanium | EDR | tanclient.exe, TaniumClient.exe | tanium.sys | Y | TaniumClient |
| Rapid7 | InsightIDR | rapid7.exe, ir_agent.exe | rapid7drv.sys | Y | ir_agent |
| FortiEDR | FortiEDR | fdedr.exe, FortiEDR.exe | fdedrdrv.sys | Y | FortiEDR |
| Cynet | 360 | cyserver.exe, CynetMS.exe | cyndrv.sys | Y | CynetMS |
| Darktrace | Enterprise | darktracetsa.exe | darktrace.sys | Y | DarktraceAgent |
| BlackBerry | Protect/Optics | CylanceSvc.exe, CylanceUI.exe | cylance.sys | Y | CylanceSvc |

### AV Products (Antivirus / Antimalware)

| Vendor | Product | Process Names | Driver Names | Kernel Mode |
|--------|---------|--------------|-------------|-------------|
| Symantec | Endpoint Protection | ccSvchst.exe, Smc.exe, seplu.exe | SRTSP.sys, SymEFA.sys, SescDrv.sys | Y |
| McAfee | Endpoint Security | mfetp.exe, mfeesp.exe, mfefire.exe | mfewfpk.sys, mfeavfk.sys, mfehidk.sys | Y |
| Bitdefender | GravityZone | EPConsole.exe, bdservicehost.exe, bdagent.exe | trufos.sys, bdts.sys | Y |
| ESET | Endpoint Security | ekrn.exe, egui.exe | ehdrv.sys, eamonm.sys | Y |
| Kaspersky | Endpoint Security | avp.exe, avpui.exe | klif.sys, klhk.sys, klflt.sys | Y |
| Trend Micro | Apex One | ntrtscan.exe, pccntmon.exe, TMASOAgent.exe | TmXPFlt.sys, TMEBC64.sys, tmaso.sys | Y |
| Avast/AVG | Business | AvastSvc.exe, AvastUI.exe, avgsvc.exe | aswSP.sys, aswids.sys, avgmfx64.sys | Y |
| Malwarebytes | Endpoint Protection | mbamservice.exe, MBAMAgent.exe | MBAMSwissArmy.sys, mbam.sys | Y |
| Norton | 360/Security | nortonsecurity.exe, n360.exe | nortonsecurity.sys, n360drv.sys | Y |
| Webroot | SecureAnywhere | WRSA.exe | WRkrn.sys | Y |
| F-Secure | Client Security | F-Secure.exe | fses.sys | Y |
| Avira | Antivirus Pro | avguard.exe, avgnt.exe | avgntflt.sys | Y |
| G Data | Endpoint Protection | GDataAVK.exe, AVKService.exe | GDKBFlt64.sys | Y |
| Emsisoft | Enterprise Security | a2service.exe | a2dskm.sys | Y |
| Dr.Web | Enterprise Security | dwservice.exe | dwprot.sys | Y |
| Comodo | Advanced EP | cmdagent.exe | cmdguard.sys | Y |
| Check Point | SandBlast Agent | TracSrvWrapper.exe, cpda.exe | cpprotect.sys | Y |
| Quick Heal | Total Security | qhepsvc.exe | qhdisk.sys | Y |

### Additional Indicators

#### CrowdStrike Falcon
- Registry: HKLM\SYSTEM\CurrentControlSet\Services\CSAgent
- Registry: HKLM\SYSTEM\CurrentControlSet\Services\CSFalconService
- Install dir: C:\Windows\System32\drivers\CrowdStrike\
- Channel files: C-00000291-*.sys (sensor config)
- Named pipes: \\.\pipe\CrowdStrike\*

#### SentinelOne
- Registry: HKLM\SOFTWARE\Sentinel Labs\
- Install dir: C:\Program Files\SentinelOne\
- Named pipes: \\.\pipe\SentinelOne\*

#### Microsoft Defender for Endpoint
- Registry: HKLM\SOFTWARE\Microsoft\Windows Defender\
- Registry: HKLM\SOFTWARE\Microsoft\Windows Advanced Threat Protection\
- Service: WinDefend, Sense, WdNisSvc
- ETW Provider: Microsoft-Windows-Windows Defender (GUID: 11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78)
- AMSI Provider: {2781761E-28E0-4109-99FE-B9D127C57AFE}

#### Carbon Black
- Registry: HKLM\SOFTWARE\CarbonBlack\
- Install dir: C:\Program Files\Confer\ (CB Defense)
- Named pipes: \\.\pipe\CbDefense\*

#### Cortex XDR
- Registry: HKLM\SOFTWARE\Palo Alto Networks\Traps\
- Install dir: C:\Program Files\Palo Alto Networks\Traps\
- Service: CyveraService

### Linux EDR Indicators

| Vendor | Process Names | Config Paths | Kernel Modules |
|--------|--------------|-------------|----------------|
| CrowdStrike Falcon | falcon-sensor, falcond | /opt/CrowdStrike/ | falcon_lsm_serviceable |
| SentinelOne | sentinelone-agent | /opt/sentinelone/ | sentinelone |
| Microsoft Defender | mdatp, wdavdaemon | /etc/opt/microsoft/mdatp/ | - |
| Carbon Black | cbagentd, cbdaemon | /var/opt/carbonblack/ | cbsensor |
| Elastic | elastic-endpoint | /opt/Elastic/ | - |
| Sophos | savd, sophosssp | /opt/sophos-av/ | talpa_* |
| ClamAV | clamd, freshclam | /etc/clamav/ | - |
| OSSEC/Wazuh | ossec-syscheckd, wazuh-agentd | /var/ossec/ | - |
| Auditd | auditd, audispd | /etc/audit/ | audit (built-in) |
| Sysmon (Linux) | sysmon | /opt/sysmon/ | - |
