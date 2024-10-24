# Network Traffic Simulator (TGEN)

A Python-based network traffic generator for simulating various protocols and connections in testing environments. Perfect for security product demonstrations and network monitoring tool testing.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
  - [Windows Installation](#windows-installation)
  - [Linux Installation](#linux-installation)
- [Target Machine Setup](#target-machine-setup)
  - [Windows Target Configuration](#windows-target-configuration)
  - [Linux Target Configuration](#linux-target-configuration)
- [Usage](#usage)
  - [CSV Configuration](#csv-configuration)
  - [Example Configurations](#example-configurations)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

### Multiple Protocol Support

- Windows Remote Management (WinRM)
- SMB File Sharing
- RDP (Remote Desktop Protocol)
- SSH
- FTP/SFTP
- LDAP
- Kerberos Authentication

### Flexible Configuration

- CSV-based configuration
- Support for both Windows and Linux environments
- Domain and non-domain authentication

### Realistic Traffic Generation

- Randomized timing intervals
- File operations simulation
- Network discovery capabilities

## Prerequisites

### Windows Installation

- **Install Python 3.11 or 3.12** (3.13 has NTLM issues)
  - Download from [Python.org](https://www.python.org/downloads/)
- **Install Visual C++ Build Tools**
  - Download from [Microsoft Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
  - Select **Desktop development with C++**
- **Install required Python packages:**

  ```shell
  pip install paramiko requests python-nmap pywinrm ldap3 gssapi dnspython
  ```

- **For domain authentication:**
  - Install MIT Kerberos for Windows
  - Add to PATH: `C:\Program Files\MIT\Kerberos\bin`

### Linux Installation

#### Ubuntu/Debian:

- **Install system dependencies**

  ```bash
  # Update package list
  sudo apt-get update

  # Install dependencies
  sudo apt-get install python3-pip python3-dev build-essential libkrb5-dev nmap samba-client

  # Install Python packages
  pip3 install paramiko requests python-nmap pywinrm ldap3 gssapi dnspython
  ```

#### RHEL/CentOS:

- **Install system dependencies**

  ```bash
  # Install dependencies
  sudo yum install python3-pip python3-devel gcc krb5-devel nmap samba-client

  # Install Python packages
  pip3 install paramiko requests python-nmap pywinrm ldap3 gssapi dnspython
  ```

## Target Machine Setup

### Windows Target Configuration

Run the following commands as **Administrator**:

```powershell
# Enable WinRM
Enable-PSRemoting -Force
winrm quickconfig
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Enable File Sharing
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=Yes

# Create Test Share
New-Item -Path "C:\SharedFolder" -ItemType Directory
New-SmbShare -Name "SharedDrive" -Path "C:\SharedFolder" -FullAccess "Everyone"

# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

### Linux Target Configuration

```bash
# SSH Server Setup
sudo apt-get install openssh-server
sudo systemctl enable ssh
sudo systemctl start ssh

# Samba Setup
sudo apt-get install samba
sudo mkdir /shared
sudo chmod 777 /shared

# Configure Samba
sudo bash -c 'cat >> /etc/samba/smb.conf << EOL
[SharedDrive]
    path = /shared
    browseable = yes
    read only = no
    guest ok = yes
EOL'

# Restart Samba
sudo systemctl restart smbd
```

## Usage

1. **Clone the repository**
2. **Create `network_config.csv` in the same directory as the script**
3. **Run the script:**

   ```bash
   python tgen.py
   ```

## CSV Configuration

The CSV file requires the following columns:

| Column        | Description                                                             |
|---------------|-------------------------------------------------------------------------|
| `ip`          | Target IP address                                                       |
| `protocol`    | Connection protocol (`winrm`/`smb`/`rdp`/`ssh`/`ftp`/`sftp`/`ldap`)     |
| `username`    | Authentication username                                                 |
| `password`    | Authentication password                                                 |
| `port`        | Port number (optional, uses default if blank)                           |
| `share_path`  | UNC path for SMB shares                                                 |
| `domain`      | Domain name for authentication                                          |
| `auth_method` | Authentication method (`NTLM`/`SIMPLE` for LDAP)                        |

## Example Configurations

```csv
# Windows Domain Controller
10.160.69.233,ldap,administrator,Password123,389,,tgen.com,NTLM
10.160.69.233,winrm,administrator,Password123,5985,,tgen.com,

# Windows File Server
10.160.69.224,smb,administrator,Password123,445,\\10.160.69.224\SharedDrive,tgen.com,
10.160.69.224,rdp,administrator,Password123,3389,,,

# Linux Server
192.168.1.100,ssh,linuxuser,Password123,22,,,
192.168.1.100,sftp,linuxuser,Password123,22,,,
192.168.1.100,smb,smbuser,Password123,445,\\192.168.1.100\SharedDrive,,

# Multiple Services on One Machine
10.160.69.225,winrm,administrator,Password123,5985,,tgen.com,
10.160.69.225,rdp,administrator,Password123,3389,,,
10.160.69.225,smb,administrator,Password123,445,\\10.160.69.225\SharedDrive,tgen.com,

# FTP Server
192.168.1.101,ftp,ftpuser,Password123,21,,,
```

## Troubleshooting

### Common Issues

#### Network Share Access Issues

```powershell
# Test share access manually
net use \\server\share /user:username password
```

#### WinRM Connection Problems

```powershell
# Test WinRM connectivity
Test-WSMan -ComputerName server
Enter-PSSession -ComputerName server -Credential (Get-Credential)
```

#### DNS Resolution

```powershell
nslookup server.domain.com
ping server.domain.com
```

#### LDAP Connectivity

```powershell
# Use ldp.exe to test LDAP
ldp.exe
# Connect to: server:389
```

### Logging

The script creates a `network_simulator.log` file with detailed operation logs. Check this file for debugging information.

## Security Considerations

### Authentication

- Use strong passwords
- Prefer domain accounts when possible
- Rotate credentials regularly

### Network Security

- Limit network access to required ports
- Use firewalls to restrict access
- Monitor traffic patterns

### File Operations

- Clean up test files regularly
- Use dedicated test shares
- Monitor disk space usage

### Testing Environment

- Use in isolated/lab environments
- Don't use production credentials
- Monitor resource usage

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Note:** This tool is designed for testing environments. Use appropriate security measures when deploying in any environment.
