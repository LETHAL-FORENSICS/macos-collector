<p align="center"><a href="https://github.com/ohmyzsh/ohmyzsh"><img src="https://img.shields.io/badge/Language-Shell-blue" style="text-align:center;display:block;"></a> <a href="https://github.com/LETHAL-FORENSICS/macos-collector/releases/latest"><img src="https://img.shields.io/github/v/release/LETHAL-FORENSICS/macos-collector?label=Release" style="text-align:center;display:block;"></a> <img src="https://img.shields.io/badge/macOS-12.0+-brightgreen" style="text-align:center;display:block;"> <img src="https://img.shields.io/badge/Maintenance%20Level-Actively%20Developed-brightgreen" style="text-align:center;display:block;"> <a href="https://x.com/LETHAL_DFIR"><img src="https://img.shields.io/twitter/follow/LETHAL_DFIR?style=social" style="text-align:center;display:block;"></a></p>  

# macos-collector
macos-collector - Automated Collection of macOS Forensic Artifacts for DFIR  

macos-collector.sh is a Shell script utilized to collect macOS Forensic Artifacts from a compromised macOS endpoint using primarily [Aftermath](https://github.com/jamf/aftermath) by Jamf Threat Labs.  

## Download  
Download the latest version of **macos-collector** from the [Releases](https://github.com/LETHAL-FORENSICS/macos-collector/releases/latest) section.  

> [!NOTE]
> macos-collector includes all external tools by default.  

> [!NOTE]
`Default Archive Password:` IncidentResponse, `Quarantine Files Password:` infected  

> [!TIP]
> macos-collector will write the output directly to the current working directory. It is recommended to run the tool from a remote location or external device (such as a USB flash drive) to reduce writing to the actual disk on the target endpoint.  

> [!IMPORTANT]
> Aftermath needs to be root, as well as have full disk access (FDA) in order to run. FDA can be granted to the Terminal application in which it is running. 
> 
> To give your Terminal application temporarily full disk access, go to `System Settings` &#8594; `Privacy & Security` &#8594; `Full Disk Access`, click the `+` button, unlock the settings with Touch ID or enter your password, and choose your Terminal application. You will then need to quit and reopen your Terminal application for the changes to take effect. To revoke the access, simply return to the same menu and uncheck your Terminal application.  

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

Example 4 - Collect ALL supported macOS Forensic Artifacts     
```Shell
sudo bash macos-collector.sh --triage  
```

</br>

![Help-Message](https://github.com/user-attachments/assets/dcbdd5c1-5511-40d0-87b8-93358ca3e3ad)  
**Fig 1:** Help Message  

![Aftermath-Collection](https://github.com/user-attachments/assets/27d73f2d-c139-446d-b1b6-20f0d4a52fb8)  
**Fig 2:** Aftermath Collection w/ Deep Scan  

![Aftermath-Analysis](https://github.com/user-attachments/assets/cfa5c6d1-c188-4648-ac7f-111ade15c943)  
**Fig 3:** Analyzing Aftermath Archive &#8594; switch to a clean macOS endpoint  

![BTM](https://github.com/user-attachments/assets/8b4d7bbd-8b02-4d45-a52f-fcccd9ae1b0b)  
**Fig 4:** Collecting BTM Dump File (Background Task Management)  

![DS_Store](https://github.com/user-attachments/assets/0af153b0-df11-4ec4-a6de-3fd6fec8cb41)  
**Fig 5:** Collecting DS_Store Files  

![FSEvents](https://github.com/user-attachments/assets/c3d9a361-8d85-47d4-9da9-08671e038f67)  
**Fig 6:** Collecting FSEvents Data  

![KnockKnock](https://github.com/user-attachments/assets/69a15eca-54c2-46ad-933b-f95f167c42ed)  
**Fig 7:** Live System Scan w/ KnockKnock (Persistence)    

![UnifiedLogs](https://github.com/user-attachments/assets/f80a175c-ee1b-4b95-95d3-c3005a009510)  
**Fig 8:** Collecting Apple Unified Logs (AUL)  

![Sysdiagnose](https://github.com/user-attachments/assets/25e3b02a-a6ed-480f-a10f-1db5eb37376f)  
**Fig 9:** Collecting Sysdiagnose Logs  

![Spotlight](https://github.com/user-attachments/assets/17dddf9f-819d-4c6b-a7ea-417ec469d0b8)  
**Fig 10:** Spotlight Database File Collection (incl. Live Searches)  

![SystemInfo-1](https://github.com/user-attachments/assets/e4a3c93b-4dcb-42f4-9233-460fc500bb8a)  
**Fig 11:** System Information Collection &#8594; XProtect is up to date

![SystemInfo-2](https://github.com/user-attachments/assets/551dc86e-e0e3-4646-98d6-1ef6d19cdfba)  
**Fig 12:** System Information Collection &#8594; XProtect Update available

![Recent-Items](https://github.com/user-attachments/assets/81d8f279-68e0-4af5-ae18-4c06dddec8e7)  
**Fig 13:** Recent Items Collection  

![TrueTree](https://github.com/user-attachments/assets/78137d73-362f-4cbf-81c7-b66ea3b31549)  
**Fig 14:** TrueTree Snapshot Collection  

![Notifications](https://github.com/user-attachments/assets/502af79f-824e-47d6-ba4c-5cdbe57dca51)  
**Fig 15:** Notification Center Database File Collection  

## Dependencies
7-Zip v26.00 Console Version (2026-02-12)  
MD5: DCACF43BE9AC2034815CFEA7E8C89803  
SHA1: FC8C7FF0F197E7034C3005DF0F653DBFDCCC83EF  
SHA256: A00F6D085A82A95F6DFC69EA150E05234A12B6D5D134325DDDB964CAE6817488  
https://www.7-zip.org/download.html  

Aftermath v2.3.0 (2025-09-24)  
MD5: A0668EB91650513F40CE8753A277E0E0  
SHA1: 782077A3FE5351C72157142C437EA5D20BEF00E9  
SHA256: A58489ACC3E3BB7D5BC70B66DFF5897CBF93BFE38E66C119C4FF1013559D912A  
https://github.com/jamf/aftermath  

KnockKnock v4.0.3 (2025-12-18)  
MD5: 91582848022442C8A6D71ED28A10A11B  
SHA1: FDAEB856E44563E7C543F775A238D590A3A4B2EC  
SHA256: A7836AF427187D02511170606232E4509C3A41351F5BBC3BAFAFE2F0227CC2DE  
https://objective-see.com/products/knockknock.html  

TrueTree v0.8 (2024-08-23)  
MD5: 7D4ACAA589846B9D31FBC911D1E4898F
SHA1: BF701DABCFBD816425FB827B75B011773D9283AD
SHA256: C6CE708937EFAC833DA6A0B6F4FC1A91EB38F8D456317BCF68B27CF57CB581C6
https://github.com/themittenmac/TrueTree  

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.  

## Links
[Aftermath by Jamf Threat Labs](https://github.com/jamf/aftermath)  
[Aftermath - SOAR Playbooks](https://github.com/jamf/jamfprotect/tree/main/soar_playbooks/aftermath_collection)  
[TrueTree by Jaron Bradley](https://github.com/themittenmac/TrueTree)  
[The Mitten Mac - Incident Response and Threat Hunting Knowledge for macOs](https://themittenmac.com/)  
[What Happened?: Swiftly Investigating macOS Security Incidents with Aftermath | JNUC 2023](https://www.youtube.com/watch?v=lvfQMnkOZDM)  
[KnockKnock - Persistence Enumerator by Objective-See](https://objective-see.org/products/knockknock.html)  