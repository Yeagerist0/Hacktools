# Hacking Lab Setup Guide

A comprehensive guide to setting up safe, legal practice environments for ethical hacking and bug bounty training.

---

## Table of Contents

1. [Local Lab Setup](#local-lab-setup)
2. [Vulnerable Web Applications](#vulnerable-web-applications)
3. [Online Practice Platforms](#online-practice-platforms)
4. [CTF Platforms](#ctf-platforms)
5. [Virtual Machine Labs](#virtual-machine-labs)
6. [Docker-based Labs](#docker-based-labs)

---

## Local Lab Setup

### System Requirements

- **Minimum:** 8GB RAM, 100GB storage, quad-core CPU
- **Recommended:** 16GB+ RAM, 256GB+ SSD, 6+ core CPU
- **Virtualization:** VT-x/AMD-V enabled in BIOS

### Recommended Hypervisors

1. **VirtualBox** (Free) - [Download](https://www.virtualbox.org/)
2. **VMware Workstation** (Paid) / VMware Player (Free)
3. **Proxmox** (Free) - For dedicated lab servers
4. **Hyper-V** (Windows Pro/Enterprise)

### Network Configuration

```
Recommended Network Setup:
┌─────────────────────────────────────────────────┐
│                 Host Machine                     │
│                                                 │
│  ┌─────────────┐    ┌─────────────┐            │
│  │   Kali VM   │    │ Vulnerable  │            │
│  │  (Attacker) │    │     VM      │            │
│  │             │    │  (Target)   │            │
│  └──────┬──────┘    └──────┬──────┘            │
│         │                  │                    │
│         └────────┬─────────┘                    │
│                  │                              │
│         ┌───────┴────────┐                      │
│         │  Internal NAT  │                      │
│         │   Network      │                      │
│         └────────────────┘                      │
└─────────────────────────────────────────────────┘
```

**VirtualBox Network Setup:**
```bash
# Create internal network
VBoxManage natnetwork add --netname "HackLab" --network "10.0.2.0/24" --enable --dhcp on

# Assign VM to network
# VM Settings > Network > Attached to: NAT Network > Name: HackLab
```

---

## Vulnerable Web Applications

### DVWA (Damn Vulnerable Web Application)

**Docker Setup:**
```bash
# Pull and run DVWA
docker run -d -p 80:80 vulnerables/web-dvwa

# Access at http://localhost
# Default credentials: admin/password
```

**Manual Setup:**
```bash
# Clone repository
git clone https://github.com/digininja/DVWA.git

# Move to web root
sudo mv DVWA /var/www/html/

# Configure database
mysql -u root -p
CREATE DATABASE dvwa;
CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';

# Copy config
cp /var/www/html/DVWA/config/config.inc.php.dist /var/www/html/DVWA/config/config.inc.php

# Edit config with database credentials
# Access at http://localhost/DVWA
```

**Vulnerabilities to Practice:**
- SQL Injection
- XSS (Reflected, Stored, DOM)
- Command Injection
- File Inclusion (LFI/RFI)
- File Upload
- CSRF
- Brute Force

---

### OWASP WebGoat

**Docker Setup:**
```bash
docker run -d -p 8080:8080 -p 9090:9090 webgoat/webgoat

# Access at http://localhost:8080/WebGoat
```

**Features:**
- Guided lessons
- Interactive challenges
- Covers OWASP Top 10

---

### bWAPP (Buggy Web Application)

**Docker Setup:**
```bash
docker run -d -p 80:80 raesene/bwapp

# Access at http://localhost/bWAPP
# Install: http://localhost/bWAPP/install.php
```

**100+ Vulnerabilities including:**
- Injection flaws
- Broken authentication
- XSS
- Insecure direct object references
- Security misconfiguration

---

### OWASP Juice Shop

**Docker Setup:**
```bash
docker run -d -p 3000:3000 bkimminich/juice-shop

# Access at http://localhost:3000
```

**Features:**
- Modern web application
- 100+ challenges
- Score board to track progress
- Covers OWASP Top 10

---

### Vulnhub Machines

Download vulnerable VMs from [Vulnhub](https://www.vulnhub.com/)

**Beginner-Friendly:**
- Kioptrix Series
- Mr-Robot
- Basic Pentesting
- DC Series (DC-1 through DC-9)
- Toppo

**Intermediate:**
- HackLab: Vulnix
- Stapler
- SickOs
- Lord of the Root

**Advanced:**
- Hack The Box retired machines
- Vulnhub Pro Labs

---

## Online Practice Platforms

### Hack The Box

**Website:** https://www.hackthebox.com/

```
Features:
- Active and retired machines
- Challenges by category
- Pro Labs for advanced training
- Starting Point for beginners
- Certified Penetration Testing Specialist (CPTS)
```

**Getting Started:**
1. Create free account
2. Start with "Starting Point" machines
3. Progress to Easy machines
4. Use writeups for retired machines to learn

---

### TryHackMe

**Website:** https://tryhackme.com/

```
Features:
- Guided learning paths
- Browser-based attack box
- Beginner-friendly
- Structured curriculum
```

**Recommended Paths:**
1. Complete Beginner
2. Web Fundamentals
3. Jr Penetration Tester
4. Offensive Pentesting

---

### PortSwigger Web Security Academy

**Website:** https://portswigger.net/web-security

```
Features:
- Free comprehensive web security training
- Interactive labs
- All OWASP Top 10 covered
- Burp Suite integration
```

**Topics:**
- SQL Injection
- Cross-site scripting
- CSRF
- Clickjacking
- DOM-based vulnerabilities
- CORS
- XXE
- SSRF
- OS command injection
- Directory traversal
- Access control
- Authentication
- Business logic
- HTTP Host header attacks
- OAuth
- JWT attacks
- Prototype pollution
- Web cache poisoning

---

### PentesterLab

**Website:** https://pentesterlab.com/

```
Features:
- Progressive exercises
- Pro subscription for full access
- Real-world scenarios
- Certificate upon completion
```

---

### HackerOne CTF

**Website:** https://ctf.hacker101.com/

```
Features:
- Free CTF challenges
- Earn private bug bounty invites
- Various difficulty levels
```

---

## CTF Platforms

### picoCTF

**Website:** https://picoctf.org/

Best for beginners, educational focus.

### CTFtime

**Website:** https://ctftime.org/

Calendar of upcoming CTF competitions.

### OverTheWire

**Website:** https://overthewire.org/wargames/

```
Wargames (in order of difficulty):
1. Bandit - Linux basics
2. Natas - Web security basics
3. Leviathan - Basic exploitation
4. Krypton - Cryptography
5. Narnia - Binary exploitation intro
6. Behemoth - Binary exploitation
7. Utumno - Advanced exploitation
8. Maze - Binary exploitation
```

**Getting Started with Bandit:**
```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
# Password: bandit0
```

---

## Virtual Machine Labs

### Metasploitable 2/3

**Metasploitable 2:**
```bash
# Download from: https://sourceforge.net/projects/metasploitable/
# Default credentials: msfadmin/msfadmin
```

**Metasploitable 3:**
```bash
# Build with Vagrant
git clone https://github.com/rapid7/metasploitable3.git
cd metasploitable3
vagrant up
```

---

### DVCP (Damn Vulnerable Cloud Platform)

For cloud security practice.

```bash
# AWS-based vulnerable environment
# Requires AWS account
git clone https://github.com/m6a-UdS/dvcp.git
cd dvcp
terraform init
terraform apply
```

---

### CloudGoat

```bash
# AWS vulnerable by design
git clone https://github.com/RhinoSecurityLabs/cloudgoat.git
cd cloudgoat
pip3 install -r requirements.txt
./cloudgoat.py config profile
./cloudgoat.py create scenario_name
```

---

## Docker-based Labs

### Complete Lab Stack

```yaml
# docker-compose.yml
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8081:80"
    
  juiceshop:
    image: bkimminich/juice-shop
    ports:
      - "3000:3000"
  
  webgoat:
    image: webgoat/webgoat
    ports:
      - "8080:8080"
      - "9090:9090"
  
  bwapp:
    image: raesene/bwapp
    ports:
      - "8082:80"
  
  mutillidae:
    image: citizenstig/nowasp
    ports:
      - "8083:80"
```

**Start all labs:**
```bash
docker-compose up -d
```

**Access:**
- DVWA: http://localhost:8081
- Juice Shop: http://localhost:3000
- WebGoat: http://localhost:8080/WebGoat
- bWAPP: http://localhost:8082/bWAPP
- Mutillidae: http://localhost:8083/mutillidae

---

## Setting Up Kali Linux

### VirtualBox Installation

1. Download Kali VM from https://www.kali.org/get-kali/
2. Import into VirtualBox
3. Configure:
   - RAM: 4GB minimum
   - CPU: 2 cores minimum
   - Network: NAT or Bridged

### Essential Post-Install

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install additional tools
sudo apt install -y \
    golang \
    python3-pip \
    docker.io \
    docker-compose

# Add user to docker group
sudo usermod -aG docker $USER

# Install Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

---

## Practice Workflow

### Daily Practice Routine

1. **Warm-up (30 min)**
   - OverTheWire Bandit levels
   - TryHackMe daily challenges

2. **Skill Building (1-2 hours)**
   - PortSwigger Labs
   - Focused vulnerability practice

3. **Machine Practice (1-2 hours)**
   - HTB/TryHackMe machines
   - Vulnhub VMs

4. **CTF Practice (Weekly)**
   - Participate in weekend CTFs
   - Review writeups

### Skill Progression Path

```
Beginner:
├── Linux basics (Bandit)
├── Web fundamentals (TryHackMe)
├── DVWA (Low security)
└── PortSwigger (Apprentice labs)

Intermediate:
├── HTB Easy machines
├── DVWA (Medium security)
├── PortSwigger (Practitioner labs)
└── Bug bounty basics

Advanced:
├── HTB Medium/Hard machines
├── DVWA (High/Impossible)
├── PortSwigger (Expert labs)
├── Real bug bounty programs
└── CTF competitions
```

---

## Legal Reminder

⚠️ **IMPORTANT:** Only practice on:
- Systems you own
- Systems you have explicit written permission to test
- Designated practice platforms (HTB, TryHackMe, etc.)
- Bug bounty programs within their scope

**Never:**
- Test production systems without authorization
- Access systems you don't have permission for
- Cause denial of service to any system
- Exfiltrate real user data

---

## Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [HackTricks](https://book.hacktricks.xyz/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [GTFOBins](https://gtfobins.github.io/)
- [CyberChef](https://gchq.github.io/CyberChef/)
