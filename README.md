# Active Directory Security Monitoring with Splunk and Atomic Red Team

## 📌 Objective
This project simulates an **Active Directory enterprise environment** using **Windows Server 2022, Windows 10, Splunk, Sysmon, and Kali Linux** to:
- Detect **brute-force attacks and privilege escalation** attempts.
- Monitor security telemetry using **Splunk and Sysmon**.
- Simulate **real-world cyber threats** using **Atomic Red Team**.
- Align findings with the **CIA Triad, NIST Cybersecurity Framework, and MITRE ATT&CK Framework**.

---

## 🛠️ Skills Learned
✅ **Active Directory Setup & Configuration**  
✅ **Network Security & Monitoring with Splunk**  
✅ **Windows Event Log Analysis & SIEM Correlation**  
✅ **Sysmon & Splunk Forwarder Deployment**  
✅ **Threat Simulation using Atomic Red Team**  
✅ **Brute-force attack detection & mitigation**  
✅ **MITRE ATT&CK Framework Mapping**  

---

## 📚 Table of Contents
- [Cybersecurity Framework Alignment](#cybersecurity-framework-alignment)
- [Lab Topology](#lab-topology)
- [1. Creating a Private Network on VMware Fusion](#1-creating-a-private-network-on-vmware-fusion)
- [2. Installing Splunk on Ubuntu OS](#2-installing-splunk-on-ubuntu-os)
- [3. Installing Windows Server 2022 & Active Directory](#3-installing-windows-server-2022--active-directory)
- [4. Configuring Sysmon & Placing `inputs.conf` in Splunk](#4-configuring-sysmon--placing-inputsconf-in-splunk)
- [5. Setting Up Active Directory & Domain Controller](#5-setting-up-active-directory--domain-controller)
- [6. Simulating RDP Brute-Force Attack with Kali Linux & Atomic Red Team Tests](#6-simulating-rdp-brute-force-attack-with-kali-linux--atomic-red-team-tests)
- [7. Conclusion & Key Takeaways](#7-conclusion--key-takeaways)

---

## 🔍 Cybersecurity Framework Alignment

### **CIA Triad**
- **Confidentiality** → Implementing Active Directory security policies.
- **Integrity** → Detecting unauthorized logins and privilege escalation with Splunk.
- **Availability** → Ensuring network connectivity between systems.

### **NIST Cybersecurity Framework**
- **Identify** → Setting up an Active Directory domain for identity management.
- **Protect** → Using Sysmon and Splunk to log and monitor security events.
- **Detect** → Monitoring RDP brute-force attempts and unauthorized access.
- **Respond** → Investigating logs, alerts, and remediating security threats.
- **Recover** → Strengthening security policies to prevent future attacks.

### **MITRE ATT&CK Techniques**
| Technique ID  | Name                        | Description |
|--------------|----------------------------|-------------|
| **T1110.001** | Brute Force - Password Guessing | RDP brute-force attack with Crowbar. |
| **T1136.001** | New Local User Creation | Adversaries create new users to maintain persistence. |
| **T1134.001** | Token Impersonation | Attackers escalate privileges by hijacking tokens. |

---

## 🖥️ Lab Topology

| Component | Role | IP Address |
|-----------|------|------------|
| **Splunk Server** | SIEM & Log Collection | `192.168.10.10` |
| **Windows Server 2022 (AD/DC)** | Active Directory Domain Controller | `192.168.10.7` |
| **Windows 10 (Target-PC)** | Workstation under attack | `192.168.10.6` |
| **Kali Linux** | Attack Machine | `192.168.10.250` |


<img width="688" alt="Network Diagram" src="https://github.com/user-attachments/assets/08be2659-24cc-4f28-b0d3-b05f395b5e76" />

---

## **1. Creating a Private Network on VMware Fusion**

Configured a **private NAT network** on VMware Fusion:
```sh
# Check network interfaces on Kali Linux
ip a

# Set static IP on Kali
sudo nano /etc/network/interfaces

# Add the following lines:
auto eth0
iface eth0 inet static
    address 192.168.10.250
    netmask 255.255.255.0
    gateway 192.168.10.2
```
Restart networking:
```sh
sudo systemctl restart networking
```
### Network Configuration on VM Fusion

<div align="center">
  <table>
    <tr>
      <td><img src="https://github.com/user-attachments/assets/4482986a-4eeb-459f-b108-8a9430488776" width="300"></td>
      <td><img src="https://github.com/user-attachments/assets/c2b93a64-59bb-47eb-98b8-705352ce3612" width="300"></td>
      <td><img src="https://github.com/user-attachments/assets/8b159fb3-8315-49e6-9b39-07a645aa3abc" width="300"></td>
    </tr>
    <tr>
      <td align="center"><b>Step 1</b></td>
      <td align="center"><b>Step 2</b></td>
      <td align="center"><b>Step 3</b></td>
    </tr>
  </table>
</div>
---

## **2. Installing Splunk on Ubuntu OS**

```sh
# Update system
sudo apt update && sudo apt upgrade -y

# Download & Install Splunk
wget -O splunk-9.0.4-amd64.deb "https://download.splunk.com/products/splunk/releases/9.0.4/linux/splunk-9.0.4-amd64.deb"
sudo dpkg -i splunk-9.0.4-amd64.deb

# Start Splunk and enable boot persistence
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```
### **Editing `init-cloud.yaml` to Disable Cloud Init on Splunk Machine**

```sh
sudo nano /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
```
Add the following:
```yaml
network: {config: disabled}
```
<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/a621f7d8-64cb-4458-8696-639af16f811a" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/c5ffda5b-4c71-4f5e-b102-05e6c96a6f12" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/7a59debc-1e64-42ed-8901-1a8b1d1d59dc" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/48828131-6460-475b-8652-0a4c64212a3a" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/8d945a4d-7de9-4a3d-bb43-db9d7c316c08" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/320eadd4-fdca-45ba-b5de-fdce13be4fb9" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Install Ubuntu on VM (Step 1)</b></td>
      <td align="center"><b>2. Install Ubuntu on VM (Step 2)</b></td>
      <td align="center"><b>3. Change DHCP to Static IP</b></td>
      <td align="center"><b>4. Update Network Config</b></td>
      <td align="center"><b>5. Set Static IP (Check Ping)</b></td>
      <td align="center"><b>6. Connect Ubuntu to Network</b></td>
    </tr>
  <table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/dba4a88b-8386-482e-ae87-1b433d41a3fb" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/8d945a4d-7de9-4a3d-bb43-db9d7c316c08" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/ab6750f7-342f-453f-9523-62bf4a42eb8b" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/357c017a-7e73-48a9-996b-aede87804601" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/19225033-30b4-4a0a-92da-1fbe44a2a00e" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/35cf3325-7510-4a81-a6f2-15068173f3d8" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>7. Install Splunk on Ubuntu</b></td>
      <td align="center"><b>8. Configure Splunk Firewall</b></td>
      <td align="center"><b>9. Start Splunk Services</b></td>
      <td align="center"><b>10. Verify Splunk Login</b></td>
      <td align="center"><b>11. Check Splunk Dashboard</b></td>
      <td align="center"><b>12. Confirm Splunk Web GUI</b></td>
    </tr>
  </table>
</div>
---

## **3. Installing Windows Server 2022 & Active Directory**

```powershell
# Install Active Directory Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promote to Domain Controller
Install-ADDSForest -DomainName "techgneek.local"
```
<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/a5887200-0a7e-4a44-9083-c76a6ee59395" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/b86095ac-35b3-421b-a7ae-886ffc355ff7" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/76f93bb0-63e3-4a57-9e7e-50eeb9cfb7c7" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/277199dd-b61c-4dc7-9da4-ab9c7bee7cca" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/81c56d6c-40f7-45ac-a975-a0cebede9935" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Install Windows Server (Start)</b></td>
      <td align="center"><b>2. Load Windows ISO</b></td>
      <td align="center"><b>3. Configure VM Settings</b></td>
      <td align="center"><b>4. Choose Install Type</b></td>
      <td align="center"><b>5. Set Processor & Memory</b></td>
    </tr>
  <table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/19aaf37b-0a60-425f-a2b7-13077031a339" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/311d132f-857d-4f20-9dc9-254b1d483a39" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/89ffc14b-adfb-4f3d-a9ae-d193950827d0" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/68ab4d26-e203-4be1-bef2-055d097f8cb4" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/3af24758-d907-4866-9b9f-7a6e0cba82b6" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>6. Configure Network Adapter</b></td>
      <td align="center"><b>7. Select Network</b></td>
      <td align="center"><b>8. Connect to Network</b></td>
      <td align="center"><b>9. Setup Windows OS</b></td>
      <td align="center"><b>10. Authenticate Install</b></td>
    </tr>
  </table>
</div>

---

## **4. Configuring Sysmon & Placing `inputs.conf` in Splunk**

```powershell
# Create local folder and move inputs.conf
mkdir "C:\Program Files\SplunkUniversalForwarder\etc\apps\Splunk_TA_windows\local"
mv inputs.conf "C:\Program Files\SplunkUniversalForwarder\etc\apps\Splunk_TA_windows\local"
```

Example `inputs.conf`:
```ini
[WinEventLog://Security]
disabled = 0
index = endpoint
sourcetype = WinEventLog:Security
```
Restart the forwarder:
```powershell
net stop SplunkForwarder
net start SplunkForwarder
```
### **Prepping Sysmon & Splunk Install**
<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/40033f95-ea7b-43cc-b200-f5b4e069539c" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/e3f0481c-86bc-485e-b5c4-99e976bc576a" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/1fbfe906-fa8a-45d6-805c-a4d4ff5be316" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/7c4636c7-5137-44dd-bbe0-314964fc7d32" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/25cba471-305a-4533-a7c8-ad917c12a8df" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Assign Windows New IP (Step 1)</b></td>
      <td align="center"><b>2. Assign Windows New IP (Step 2)</b></td>
      <td align="center"><b>3. Assign Windows New IP (Step 3)</b></td>
      <td align="center"><b>4. Assign Windows New IP (Step 4)</b></td>
      <td align="center"><b>5. Assign Windows New IP (Confirmed)</b></td>
    </tr>
<table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/d151e709-a21a-4ff5-a16b-aa26236f98cf" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/898c4612-a1a6-4583-873e-3365774bcebc" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/665109de-31c8-4db9-ba01-5b541e7e1b27" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/681c1704-96ca-4179-912e-261157af6657" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/0f6bfa0f-478b-407d-bae2-f13819722a05" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>6. Download & Install Splunk Universal Forwarder (Step 1)</b></td>
      <td align="center"><b>7. Download & Install Splunk Universal Forwarder (Step 2)</b></td>
      <td align="center"><b>8. Rename Windows 10 PC (Step 1)</b></td>
      <td align="center"><b>9. Rename Windows 10 PC (Step 2)</b></td>
      <td align="center"><b>10. Rename Windows 10 PC (Confirm & Restart)</b></td>
    </tr>
  </table>
</div>

### **Installing Sysmon & Splunk Universal Forwarder on Windows 10**

<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/d2c2e926-84d3-4fa9-9a47-3ab82f3f7f3f" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/78e5a1ae-e7c4-46bf-b93b-0c345d4797a9" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/4700d079-e278-4343-84d1-bc9eb8b495bb" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/03a63e06-6a2d-4710-85f4-69bdbd8d62fe" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/5c080452-250d-4449-8fa6-fd542f734602" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Download Sysmon Zip File</b></td>
      <td align="center"><b>2. Extract Sysmon Zip File</b></td>
      <td align="center"><b>3. Download Sysmon Config XML</b></td>
      <td align="center"><b>4. Install Sysmon with XML</b></td>
      <td align="center"><b>5. Confirm Sysmon Installation</b></td>
    </tr>
  <table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/8b78f5e1-9ed6-47c7-9c6f-8fd0c98e65b5" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/e8e81c96-a14f-4a63-8885-3d5d37c4983d" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/0d6f5f44-2850-4d7f-8932-13ba95cfd66a" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/f5c1b53b-8fe0-4799-a4e5-d69542d0d701" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/03212e09-1fa1-4745-96ce-3b9cb644eaa5" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>6. Add New Index in Splunk</b></td>
      <td align="center"><b>7. Set Splunk to Listen on Port 9997</b></td>
      <td align="center"><b>8. Confirm Data Indexing</b></td>
      <td align="center"><b>9. Configure Inputs.conf for Splunk</b></td>
      <td align="center"><b>10. Restart Splunk & Set to Local Services</b></td>
    </tr>
  </table>
</div>


---

## **5. Setting Up Active Directory & Domain Controller**

### **Install Active Directory role**
```powershell
# Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
```

### **Promote to Domain Controller**
```powershell
Install-ADDSForest -DomainName "techgneek.local"
```

### **Add Users & Groups**
```powershell
New-ADUser -Name "klamar" -UserPrincipalName "klamar@techgneek.local"
```

<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/adaa7fa6-5e8c-4154-a5b4-15c8cb2f1368" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/ea55cde2-0a33-4c65-89be-93271b7a3e6e" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/2591f522-05e3-4a2a-b52c-492c59601ac0" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/063f6b06-05bf-4e4a-b805-de77d2ecf072" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Install Active Directory (Step 1)</b></td>
      <td align="center"><b>2. Install Active Directory (Step 2)</b></td>
      <td align="center"><b>3. Promote AD Server to DC (Step 1)</b></td>
      <td align="center"><b>4. Set Root Domain (techgneek.local)</b></td>
    </tr>
<table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/adda9fed-06ce-48b3-8be6-843cf6751066" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/bde31617-2aed-4459-90d7-414257a5601a" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/47cc2ef8-7b0e-498a-b6ae-aadf94a63a01" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/9b6b84ca-44aa-49ec-9521-d569c8b85371" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>5. Install DC & Complete Setup</b></td>
      <td align="center"><b>6. Ping Machines to Verify Connectivity</b></td>
      <td align="center"><b>7. Add Organizations to AD</b></td>
      <td align="center"><b>8. Add Users to Active Directory</b></td>
    </tr>
  </table>
</div>

### **Joining Windows 10 to Techgneek.Local Domain Controller**

<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/60c44bc4-9c38-4514-b63e-58202f059143" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/663c4f05-d535-4af9-9f9c-96221a5d44c2" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/220eaf62-af34-4d3e-8321-4c3535372fb7" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Join Windows 10 to Domain (Start)</b></td>
      <td align="center"><b>2. Point Windows 10 DNS to AD Server</b></td>
      <td align="center"><b>3. Join Windows 10 to techgneek.local</b></td>
    </tr>
<table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/11841f53-0b52-49fa-9656-8aeb47ce9636" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/288bb219-63d3-489e-906b-8915436873ee" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/c095fe81-adcf-42d7-bdea-bd85154ba9cd" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>4. Confirm Windows 10 in Domain (Step 1)</b></td>
      <td align="center"><b>5. Confirm Windows 10 in Domain (Step 2)</b></td>
      <td align="center"><b>6. Confirm Windows 10 in Domain (Step 3)</b></td>
    </tr>
  </table>
</div>



---



## **6. Simulating RDP Brute-Force Attack with Kali Linux & Atomic Red Team Tests**

```sh
# Perform RDP brute-force attack on Windows 10
crowbar -b rdp -u klamar -C password.txt -s 192.168.10.6/32
```

### **Connecting to the Target Machine Using `xfreerdp`**
```sh
xfreerdp /u:klamar /p:P@ssword! /v:192.168.10.6
```

<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/dd2d3b46-1b2c-4dd2-92c8-5bd60b3c1557" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/18a2f630-f2b2-4345-bbd5-1fee7f626884" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/08a7a10e-bfd6-44e3-a059-4a4a1b7a24ce" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/458761d3-a786-4656-bf19-52c60766fefb" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/09cdbc87-70d5-4144-8e60-d3a7af203c87" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Add Kali Linux to Network (Set IP)</b></td>
      <td align="center"><b>2. Confirm Kali Linux IP</b></td>
      <td align="center"><b>3. Enable Remote Connection on Windows</b></td>
      <td align="center"><b>4. Install Crowbar & Create Folder</b></td>
      <td align="center"><b>5. Add Password for Bruteforce Attempt</b></td>
    </tr>
  <table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/a9354263-9e65-42b0-957f-6129d319c419" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/236a868f-e810-4aba-add2-739af12bb3c2" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/fd9a5139-2079-48d4-bd78-4e5986d47820" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/da0d9f15-a2ee-4a29-9896-2aeebc07204e" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/8e390914-0fc0-45ba-8220-77f0753f4555" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>6. Install Crowbar & Get Wordlist</b></td>
      <td align="center"><b>7. Perform Bruteforce RDP (Success)</b></td>
      <td align="center"><b>8. Detect Failed Logins in Splunk</b></td>
      <td align="center"><b>9. Detect Successful Logins in Splunk</b></td>
      <td align="center"><b>10. View Splunk Telemetry for KLamar</b></td>
    </tr>
  </table>
</div>


### **Atomic Red Team Test & Splunk Log Analysis**

<div align="center">
  <table>
    <!-- Top Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/8e6f60b3-0fc1-454f-9c08-60876e13ee88" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/fb02fef5-1bee-4c45-a6e3-e62116dbec3c" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/a9166fc6-a25b-48da-a107-c3bb14818349" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/7e9240e9-0925-46ae-8c2f-00b9936e4a98" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>1. Install Atomic Red Team</b></td>
      <td align="center"><b>2. Run MITRE Tactic ID T1136.001</b></td>
      <td align="center"><b>3. New Local User Created</b></td>
      <td align="center"><b>4. Generate Atomic Red Team Test (TestSVC)</b></td>
    </tr>
  <table>
    <!-- Bottom Row -->
    <tr>
      <td><img src="https://github.com/user-attachments/assets/50bb589d-7a8f-4ce5-a31c-1b18a0361dc4" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/a50f061e-994a-4049-8959-01e699679359" width="250"></td>
      <td><img src="https://github.com/user-attachments/assets/4b0c5555-15c5-4285-9d1f-18f57e0b2dac" width="250"></td>
    </tr>
    <tr>
      <td align="center"><b>5. Invoke Atomic Red Team Test (T1134.001)</b></td>
      <td align="center"><b>6. Confirm Splunk Telemetry (TestSVC)</b></td>
      <td align="center"><b>7. Confirm Splunk Telemetry (NewLocalUser)</b></td>
    </tr>
  </table>
</div>

✅ **Splunk Detection Query**

```spl
# Search for brute-force attempts
index=endpoint EventCode=4625

# Search for successful logins
index=endpoint EventCode=4624

# Search for 
```
---

## **7. Conclusion & Key Takeaways**
✅ **Configured an Active Directory Lab for security monitoring.**  
✅ **Simulated real-world cyber threats & analyzed logs in Splunk.**  
✅ **Aligned findings with cybersecurity frameworks (NIST, MITRE, CIA Triad).**  

---

### 🔗 **Project by James Moore | TechGneek**
