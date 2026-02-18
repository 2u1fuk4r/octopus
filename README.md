<img width="297" height="162" alt="image" src="https://github.com/user-attachments/assets/2056c8f1-6403-4597-b45f-0c64da3ab081" />

# 🐙 octopus.sh (8PUS)

> Advanced Bug Bounty & Web Reconnaissance Framework  
> Eight arms. One target.

## 🚀 What It Does

 octopus automates a full recon pipeline:

- 🔎 Subdomain enumeration  
- 🌐 Alive host detection  
- 🕸 Archive + crawler URL collection  
- 🧠 Smart URL categorization  
- 🎯 XSS candidate detection  
- ⚔ Automated Dalfox XSS testing  
- 📊 TXT + Excel reporting  


## ⚡ Features

- Multi-source recon (subfinder, assetfinder, gau, wayback, katana)
- Fast / Thorough performance modes
- Auto privilege escalation (sudo)
- Clean workspace structure
- Interrupt-safe reporting (CTRL+C)
- Auto-generated Excel report (styled)


recon_target_timestamp/
├── 01_subdomains/
├── 02_alive/
├── 03_urls/
├── 04_categorized/
├── 05_xss/
└── 06_report/


 📦 Usage
chmod +x install.sh
./install.sh
 bash octopus.sh -d example.com
</p>


