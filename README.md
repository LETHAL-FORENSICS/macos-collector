<p align="center"><a href="https://github.com/ohmyzsh/ohmyzsh"><img src="https://img.shields.io/badge/Language-Shell-blue" style="text-align:center;display:block;"></a> <a href="https://github.com/LETHAL-FORENSICS/macos-collector/releases/latest"><img src="https://img.shields.io/github/v/release/LETHAL-FORENSICS/macos-collector?label=Release" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/macOS-12.0+-brightgreen" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;"> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social" style="text-align:center;display:block;"></a></p>  

# macos-collector
macos-collector - Automated Collection of macOS Forensic Artifacts for DFIR  

macos-collector.sh is a Shell script utilized to collect macOS Forensic Artifacts from a compromised macOS endpoint using primarily [Aftermath](https://github.com/jamf/aftermath) by Jamf Threat Labs.  

## Download  
Download the latest version of **macos-collector** from the [Releases](https://github.com/LETHAL-FORENSICS/macos-collector/releases/latest) section.  

> [!NOTE]
> macos-collector includes all external tools by default. 

## Usage  
```Shell
sudo bash macos-collector.sh [OPTION]
```

Example 1 - Collect forensic artifacts from a compromised macOS endpoint using Aftermath  
```Shell
sudo bash macos-collector.sh --collect  
```

Example 2 - Analyze previous collected Aftermath archive file    
```Shell
sudo bash macos-collector.sh --analyze
```

Example 3 - Collect FSEvents Data from a compromised macOS endpoint   
```Shell
sudo bash macos-collector.sh --fsevents  
```

</br>

![Help-Message](https://github.com/user-attachments/assets/b307b992-4cc3-4290-b7cd-47ec6924637c)  
**Fig 1:** Help Message  

![Aftermath-Collection](https://github.com/user-attachments/assets/27d73f2d-c139-446d-b1b6-20f0d4a52fb8)  
**Fig 2:** Aftermath Collection w/ Deep Scan  

![Aftermath-Analysis](https://github.com/user-attachments/assets/cfa5c6d1-c188-4648-ac7f-111ade15c943)  
**Fig 3:** Analyzing Aftermath Archive  

![FSEvents](https://github.com/user-attachments/assets/9f298c1b-d65b-45e6-b086-1fe14a82cb7d)  
**Fig 4:** Collecting FSEvents Data  

## Dependencies
Aftermath v2.3.0 (2025-09-24)  
MD5: A0668EB91650513F40CE8753A277E0E0  
SHA1: 782077A3FE5351C72157142C437EA5D20BEF00E9  
SHA256: A58489ACC3E3BB7D5BC70B66DFF5897CBF93BFE38E66C119C4FF1013559D912A  
https://github.com/jamf/aftermath  

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  

## Links
[Aftermath by Jamf Threat Labs](https://github.com/jamf/aftermath)  
[Aftermath - SOAR Playbooks](https://github.com/jamf/jamfprotect/tree/main/soar_playbooks/aftermath_collection)  
[TrueTree by Jaron Bradley](https://github.com/themittenmac/TrueTree)  
[The Mitten Mac - Incident Response and Threat Hunting Knowledge for macOs](https://themittenmac.com/)  
[What Happened?: Swiftly Investigating macOS Security Incidents with Aftermath | JNUC 2023](https://www.youtube.com/watch?v=lvfQMnkOZDM)  