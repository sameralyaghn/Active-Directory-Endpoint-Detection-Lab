# Active Directory & Endpoint Detection Lab

A four-host enterprise identity lab: a single-domain Active Directory forest (`SAM.LOCAL`) with centralized Sysmon + Splunk telemetry, validated end-to-end with a brute-force attack simulation and Atomic Red Team exercises mapped to MITRE ATT&CK.

**Contents**

1. [Project Overview & Architecture](#1-project-overview--architecture)
2. [Network & Topology](#2-network--topology)
3. [Step-by-Step Implementation](#3-step-by-step-implementation)
4. [Hardening, Security Policies & GPOs](#4-hardening-security-policies--gpos)
5. [Verification, Testing & Auditing](#5-verification-testing--auditing)
6. [Repository Tree & File Inventory](#6-repository-tree--file-inventory)

---

## 1. Project Overview & Architecture

### Environment objective

This lab reproduces a small enterprise identity and monitoring estate:

- **Identity management** — Active Directory Domain Services (AD DS) on Windows Server 2022 provides Kerberos authentication, group policy application, and centralized account administration for domain `SAM.LOCAL`.
- **Security boundary** — the domain is the trust boundary; the Windows 10 workstation is a domain-joined member exposing RDP, making it the realistic target for credential attacks.
- **Detection engineering** — every Windows host runs Sysmon and a Splunk Universal Forwarder, shipping security-relevant telemetry to a single Ubuntu Splunk indexer so authentication activity can be investigated from one place.

### Forest & domain architecture

| Attribute | Value |
| --- | --- |
| Domain name | `SAM.LOCAL` |
| NetBIOS name | `SAM` |
| Forest / domain functional level | Windows Server 2016 (highest level available when promoting the first DC from Windows Server 2022 media) |
| Domain controllers | 1 (Windows Server 2022, `10.0.0.141`) |
| DNS | AD-integrated DNS hosted on the DC; domain members resolve through `10.0.0.141` |
| Subnet | `10.0.0.0/24` |
| Organizational units | `IT`, `HR` |
| Remote access | RDP enabled on the Windows 10 endpoint for three domain users |

### Infrastructure

| Hostname | Role / Service | OS | Static IP |
| --- | --- | --- | --- | 
| dhcppc1 ¹ | Adversary host — brute-force tooling (Hydra, Crowbar) | Kali Linux | `10.0.0.128` |
| *Win Server* ² | Domain Controller — AD DS, DNS, Sysmon, Splunk Universal Forwarder | Windows Server 2022 | `10.0.0.141` | 
| *Win 10* ² | Domain member workstation — RDP target, Sysmon, Splunk Universal Forwarder | Windows 10 | `10.0.0.137` | 
| *Ubuntu Server* ² | Splunk indexer — central log collection and search | Ubuntu Server | `10.0.0.140` |

![High-level architecture: AD domain controller, monitored Windows endpoints, Ubuntu Splunk indexer, and Kali adversary host](/Architecture/Architecture.png)             
*Figure 1 — Lab architecture: the DC provides identity and DNS, both Windows hosts forward telemetry to the Ubuntu Splunk indexer, and the Kali host acts as the adversary.*

---

## 2. Network & Topology

![Machine topology: Windows 10 at 10.0.0.137, Kali at 10.0.0.128, Ubuntu Splunk server at 10.0.0.140, Windows Server 2022 DC at 10.0.0.141](/images/machines.png)           
*Figure 2 — Host topology with roles and addressing.*

### Segmentation & routing

| Control | Configuration |
| --- | --- |
| Address plan | Single flat Layer-2 segment `10.0.0.0/24`; all four hosts share one broadcast domain |
| Domain DNS | Windows members point at `10.0.0.141` (DC-hosted AD DNS) so SRV records for `SAM.LOCAL` resolve |
| Splunk server DNS | Ubuntu indexer configured via Netplan; clients reach it directly at `10.0.0.140` |
| Telemetry path | Splunk Universal Forwarders (`.137`, `.141`) → indexer (`10.0.0.140`) |
| Adversary path | Kali (`10.0.0.128`) reaches the Windows 10 endpoint over RDP (TCP/3389) |

> [!IMPORTANT]
> Domain join fails unless the member's DNS resolver points at the domain controller. This was the one network fault hit during the build — see [Phase 3](#phase-3--dns--client-resolution).

---

## 3. Step-by-Step Implementation

Deployment proceeded in eight phases. The same Sysmon + Universal Forwarder procedure was applied to **both** Windows hosts (`10.0.0.137`, `10.0.0.141`) so telemetry flows to one indexer.

### Phase 1 — Lab network foundation

Static addressing for the Ubuntu indexer was defined in Netplan:

- `/etc/netplan/00-installer-config.yaml`

```bash
sudo netplan apply
```

![Netplan network configuration on the Ubuntu Splunk server](/images/network_config.png)           
*Figure 3 — Netplan configuration applied to the Ubuntu indexer.*

### Phase 2 — Domain Controller provisioning

The AD DS role was installed through **Manage → Add Roles and Features**, followed by promotion to Domain Controller and a restart. The equivalent automation:

```powershell
# Install the AD DS role
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

# Promote the first DC in a new forest (runs after role install)
Install-ADDSForest \
    -DomainName "SAM.LOCAL" \
    -DomainNetbiosName "SAM" \
    -InstallDns
```

> [!IMPORTANT]
> Promotion reboots the server. After the reboot the host is authoritative for DNS and Kerberos authentication in `SAM.LOCAL`.

![AD DS role installation and Domain Controller promotion wizard on Windows Server 2022](/images/DomainController.png)         
*Figure 4 — AD DS role installation and DC promotion.*

### Phase 3 — DNS & client resolution

The Windows 10 workstation initially failed to locate the domain. The cause was DNS: the client was not resolving through the DC. Fixed by pointing the workstation's resolver at the domain controller:

```powershell
# Run on the Windows 10 workstation
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.0.0.141

# Verify the domain locator record resolves
nslookup -type=SRV _ldap._tcp.SAM.LOCAL
```

![Setting the domain controller IP as the DNS server on the Windows 10 client](/images/addingDNS.png)           
*Figure 5 — Client DNS repointed at the DC (`10.0.0.141`), resolving the domain-join failure.*

### Phase 4 — AD schema, OU structuring & identity provisioning

Two Organizational Units — **IT** and **HR** — were created in **Tools → Active Directory Users and Computers**, with user accounts provisioned into them:

```powershell
# OU structure
New-ADOrganizationalUnit -Name "IT" -Path "DC=SAM,DC=LOCAL"
New-ADOrganizationalUnit -Name "HR" -Path "DC=SAM,DC=LOCAL"

# User provisioning (example)
New-ADUser -Name "john" -GivenName "John" -Path "OU=HR,DC=SAM,DC=LOCAL" `
    -AccountPassword (ConvertTo-SecureString "<P@ssw0rd>" -AsPlainText -Force) `
    -Enabled $true -ChangePasswordAtLogon $true
```

![Creating the IT and HR organizational units in Active Directory Users and Computers](/images/adding_org.png)          
*Figure 6 — IT and HR OUs created under `SAM.LOCAL`.*

![Creating domain user accounts in Active Directory Users and Computers](/images/adding_users.png)           
*Figure 7 — Domain user accounts provisioned into the new OUs.*

### Phase 5 — Domain join

With DNS corrected, the workstation joined the domain via **PC → Properties → Advanced System Settings → Domain**, entering `SAM.LOCAL` with valid domain credentials:

```powershell
# Automated equivalent
Add-Computer -DomainName "SAM.LOCAL" -Credential (Get-Credential) -Restart
```

![Successful domain join confirmation for the Windows 10 workstation](/images/Success.png)            
*Figure 8 — Workstation successfully joined to `SAM.LOCAL`.*

### Phase 6 — Telemetry pipeline: Sysmon + Splunk Universal Forwarder

**Sysmon** was installed from the Sysinternals release with the repo's `sysmonconfig.xml` (a sysmon-modular *balanced* profile, schema 4.90, rules tagged with MITRE technique IDs):

```powershell
./Sysmon.exe -i sysmonconfig.xml
```

**Splunk Universal Forwarder** — `inputs.conf` was copied from `etc/system/default` into `etc/system/local` so local overrides survive upgrades:

- `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`

```ini
[WinEventLog://Application]
index = endpoint
disabled = false

[WinEventLog://Security]
index = endpoint
disabled = false

[WinEventLog://System]
index = endpoint
disabled = false

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
disabled = false
renderXml = true
source = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
```

> [!NOTE]
> The Sysmon channel uses `renderXml = true` so structured fields (process GUIDs, command lines, MITRE tags) are indexed for searching; the plain-text channels stay text-parsed.

![Configured event sources forwarded by the Splunk Universal Forwarder](/images/source_events.png)            
*Figure 9 — Event sources (Application, Security, Sysmon, System) configured for forwarding.*

### Phase 7 — Splunk indexer setup & forwarder authentication

An index named **`endpoint`** was created on the Ubuntu Splunk server to receive telemetry from both Windows hosts:

![The endpoint index in Splunk receiving data from the Windows hosts](/images/hosts.png)           
*Figure 10 — The `endpoint` index with registered Windows sources.*

Forwarder authentication was switched to **local authentication** so forwarding did not depend on Splunk-wide credentials:

![Splunk forwarder local authentication configuration](/images/forwarder_login.png)          
*Figure 11 — Forwarder set to local authentication.*

![Splunk Universal Forwarder Windows services running](/images/Services.png)                        
*Figure 12 — SplunkForwarder services running on both Windows hosts.*

### Phase 8 — Adversary tooling & attack surface

On Kali, packages were updated and **Crowbar** (brute-force auditing tool) installed:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y crowbar
```

![Crowbar installed and ready on the Kali Linux host](/images/crowbar_kali.png)                    
*Figure 13 — Crowbar installed on Kali.*

On the Windows 10 endpoint, **RDP was enabled** and three domain users granted remote access:

```powershell
# Enable RDP and allow the group through the firewall
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
    -Name fDenyTSConnections -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

Add-LocalGroupMember -Group "Remote Desktop Users" -Member "SAM\john", "SAM\<user2>", "SAM\<user3>"
```

![Adding three domain users to the Remote Desktop Users group on Windows 10](/images/adding_users_RDP.png)                    
*Figure 14 — Three domain users granted RDP access — the exposure later exercised by the attack simulation.*

---

## 4. Hardening, Security Policies & GPOs

### GPO baseline

| GPO Name | Target OU | Enforced Settings | Objective |
| --- | --- | --- | --- |
| `ACC-Policy-Baseline` | Domain (`SAM.LOCAL`) | Password complexity, min length, history, max age; account lockout threshold/duration | Credential hygiene; blunt brute-force attempts |
| `AUD-Logon-Auditing` | Domain Controllers + member servers/workstations | Audit Logon (success + failure), Audit Account Management, Audit Process Creation (incl. command line) | Populate Security events 4624/4625 and feed Splunk detections |
| `SEC-SMB-NTLM-Hardening` | All computers | Require SMB signing; disable SMBv1; restrict NTLM to NTLMv2 | Block relay/downgrade and NTLM reflection paths |
| `SEC-RDP-Hardening` | Endpoint OUs | Restrict RDP to `Remote Desktop Users`; require NLA; set encryption level High | Limit exposed RDP attack surface (T1021.001) |
| `SEC-LAPS` | Workstation/server OUs | Windows LAPS: local admin password rotation, encrypted in AD | Prevent local admin password reuse across hosts |
| `SEC-Legacy-Protocols` | Domain | Disable LM/NTLMv1, LLMNR, WPAD fallback | Shrink the spoofing/responder-style attack surface |

### Tiering model

| Tier | Assets | Access rule |
| --- | --- | --- |
| Tier 0 | Domain Controller (`10.0.0.141`) | Admin logons only from the DC / privileged access workstation |
| Tier 1 | Servers & monitored endpoints | No Tier-0 credentials; local admin via LAPS |
| Tier 2 | Workstations (Win10 `10.0.0.137`) | Standard domain users; RDP restricted to named group |

### Auditing & logging hardening

- **Security channel** forwarded to Splunk (`index=endpoint`) — 4624/4625 logon telemetry.
- **Sysmon** (sysmon-modular balanced profile, schema 4.90) — process creation, network connections, image loads, registry, DNS and file events, each rule tagged with a MITRE technique ID.
- **Event log size/retention** — keep Security/System logs large enough to survive forwarder outages.

---

## 5. Verification, Testing & Auditing

### Domain health checks

```powershell
# DC health — services, replication, DNS
Dcdiag /v /c /e

# Replication status (single-DC forest: expect no partner errors)
Repadmin /showrepl *

# DNS locator validation from a member
nslookup -type=SRV _ldap._tcp.SAM.LOCAL

# Secure channel from the workstation back to the DC
Test-ComputerSecureChannel -Verbose

# Confirm group policy applied
gpupdate /force
gpresult /h gpo_report.html
```

### Monitored event IDs

| Event ID | Source | Meaning | Use |
| --- | --- | --- | --- |
| **4624** | Security | Successful logon | Confirms attacker success; source IP/host attribution |
| **4625** | Security | Failed logon | Brute-force / password-guessing signal |
| Sysmon 1 | Sysmon | Process creation | Command-line visibility, MITRE-tagged TTPs |
| Sysmon 3 | Sysmon | Network connection | C2 / lateral-movement adjacency |
| Sysmon 7/8/10 | Sysmon | Image load / remote thread / process access | Injection & credential-access detection |
| Sysmon 22 | Sysmon | DNS query | Domain/tooling discovery visibility |

### Attack path simulation — Hydra against `john`

From Kali, Hydra was run against the Windows 10 RDP endpoint to obtain the weak password for user `john`:

```bash
hydra -l john -P password.txt 10.0.0.137 rdp
```

![Hydra brute-force run against the Windows 10 RDP endpoint from Kali](/images/hydra.png)                        
*Figure 15 — Hydra password attack against `john` over RDP.*

Events were reviewed in Splunk with the filter:

```spl
index="endpoint" john
```

![Splunk search showing the captured authentication events for user john](/images/splunk_detection.png)                
*Figure 16 — Splunk results for `index="endpoint" john`.*

![Event IDs surfaced in the Splunk search results](/images/Events_ID.png)                
*Figure 17 — Relevant event IDs isolated from the search output.*

The two events of interest were **4625** (failed logon) and **4624** (successful logon):

![Event 4625 failed logon record for the attacked account](/images/4625.png)                            
*Figure 18 — Event 4625: failed logon attempts during the brute-force run.*

![Event 4624 successful logon record for the attacked account](/images/4624.png)                        
*Figure 19 — Event 4624: the successful logon that ended the attack.*

Inspecting the successful logon yielded forensic attribution of the attacker:

![Inspecting the successful logon event for source host and IP details](/images/success_logon.png)                        
*Figure 20 — Source fields of Event 4624 used for attribution.*

| Finding | Value |
| --- | --- |
| Machine name | `dhcppc1` |
| Attacker IP | `10.0.0.128` (Kali host) |

### Atomic Red Team & MITRE ATT&CK validation

Atomic Red Team was installed and validated to execute atomic tests against the host, mapping attacks to the [MITRE ATT&CK framework](https://attack.mitre.org/). Setup walkthrough: [https://youtu.be/_xW3fAumh1c](https://youtu.be/_xW3fAumh1c?si=4BDIcRQ6zJWJ2XuP).

```powershell
# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam

# List and run tests for a technique, e.g. T1110 (Brute Force)
Invoke-AtomicTest T1110 -ShowDetails
Invoke-AtomicTest T1110 -TestNumbers 1
```

![Atomic Red Team installed and executing tests successfully](/images/Atomic.png)                        
*Figure 21 — Atomic Red Team installed and operational.*

![Atomic test execution output confirming expected behavior](/images/Atomic_test.png)                        
*Figure 22 — Atomic test executed successfully against the lab host.*

Atomic tests are catalogued by MITRE technique:

![Tactics, techniques, and procedures view of the executed tests](/images/TTP.png)                    
*Figure 24 — TTP view of the exercised techniques.*

### Detection results

Both Windows hosts delivered telemetry to the central indexer, giving a single search surface for authentication and endpoint events:

![Splunk event list showing centralized endpoint telemetry](/images/Splunk_events.png)                        
*Figure 25 — Centralized endpoint events in Splunk.*

![Splunk chart visualization of collected events over time](/images/char_view.png)                        
*Figure 26 — Event volume chart — event flow from both endpoints over time.*

---

## 6. Repository Tree & File Inventory

```text
.
├── README.md
├── Architecture/
│   └── Architecture.png            # Lab architecture diagram
├── conf files/
│   ├── inputs.conf                 # Splunk UF: channels -> index=endpoint
│   └── sysmonconfig.xml            # Sysmon-modular balanced profile (schema 4.90)
└── images/
    ├── 4624.png                    # Successful logon event
    ├── 4625.png                    # Failed logon event
    ├── Atomic.png                  # Atomic Red Team install
    ├── Atomic_test.png             # Atomic test execution
    ├── DomainController.png        # AD DS role / DC promotion
    ├── Events_ID.png               # Event IDs in Splunk results
    ├── MITRE.png                   # ATT&CK technique mapping
    ├── Services.png                # SplunkForwarder services
    ├── Splunk_events.png           # Centralized event list
    ├── Success.png                 # Domain-join success
    ├── TTP.png                     # TTP view
    ├── addingDNS.png               # Client DNS fix
    ├── adding_org.png              # IT / HR OUs
    ├── adding_users.png            # User creation
    ├── adding_users_RDP.png        # RDP group membership
    ├── char_view.png               # Event chart
    ├── crowbar_kali.png            # Crowbar on Kali
    ├── forwarder_login.png         # Forwarder local auth
    ├── hosts.png                   # endpoint index
    ├── hydra.png                   # Hydra attack run
    ├── machines.png                # Host topology
    ├── network_config.png          # Ubuntu Netplan
    ├── source_events.png           # Forwarded event sources
    ├── splunk_detection.png        # Splunk search for "john"
    └── success_logon.png           # Attacker attribution fields
```

### File inventory

| Path | Type | Purpose |
| --- | --- | --- |
| `README.md` | Documentation | This walkthrough |
| `Architecture/Architecture.png` | Diagram | Lab architecture (Figure 1) |
| `conf files/inputs.conf` | Splunk config | Maps Application/Security/System/Sysmon channels into `index=endpoint` |
| `conf files/sysmonconfig.xml` | Sysmon config | sysmon-modular balanced profile with MITRE-tagged include/exclude rules |
| `images/*.png` | Screenshots (25) | Step-by-step evidence for every phase and test |

## Contributing

Contributions, detection rules, and feedback are very welcome! If you'd like to extend the lab or add new scenarios:

- New Detection Rules: Add new Splunk SPL queries or Sysmon filtering logic.
- Attack Emulation: Submit additional Atomic Red Team tests, Kerberos attack simulations (e.g., Kerberoasting, AS-REP roasting), or lateral movement playbooks.
- Hardening & Scripts: Propose GPO baselines or PowerShell automation scripts for domain setup and monitoring.

### How to Contribute
1. Fork the repository.
2. Create your branch: git checkout -b feature/NewScenario
3. Commit your changes: git commit -m 'Add MITRE T1003 emulation & detection SPL'
4. Push to the branch: git push origin feature/NewScenario
5. Open a Pull Request.

---

## Credits & Acknowledgments

- Author: Built and documented by Samer Alyaghn — designed as a full-cycle enterprise Active Directory build, endpoint telemetry pipeline, and adversary emulation lab.
- Tools & References:
  - [Splunk Enterprise & Universal Forwarder](https://www.splunk.com/) for centralized log ingestion and search.
  - [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) & Olaf Hartong's [sysmon-modular](https://github.com/olafhartong/sysmon-modular) configuration profile.
  - [Atomic Red Team](https://www.atomicredteam.io/) by Red Canary, mapped against the [MITRE ATT&CK Framework](https://attack.mitre.org/).
  - Attack tooling by the open-source security community ([THC-Hydra](https://github.com/VolkanSah/work-with-Hydra) & [Crowbar](https://github.com/galkan/crowbar)).
