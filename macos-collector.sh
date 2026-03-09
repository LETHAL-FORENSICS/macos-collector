#!/bin/bash
#
# macOS-Collector
#
# @author:      Martin Willing
# @copyright:   Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:     Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:         https://lethal-forensics.com/
# @date:        2026-03-09
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# README
# Automated Collection of macOS Forensic Artifacts for DFIR
#
# https://github.com/LETHAL-FORENSICS/macos-collector
# https://github.com/LETHAL-FORENSICS/MacOS-Analyzer-Suite
#
#
# Usage:
# sudo bash macos-collector.sh [OPTION]
#
# Help:
# sudo bash macos-collector.sh -h
#
# Example 1:
# sudo bash macos-collector.sh --collect
#
# Collect forensic artifacts from a compromised macOS endpoint using Aftermath.
#
# Example 2:
# sudo bash macos-collector.sh --analyze
#
# Analyze previous collected Aftermath archive file.
#
# Example 3:
# sudo bash macos-collector.sh --ds_store
#
# Collect .DS_Store files from a macOS endpoint.
#
# Example 4:
# sudo bash macos-collector.sh --fsevents
#
# Collect FSEvents Data from a macOS endpoint.
#
# Example 5:
# sudo bash macos-collector.sh --triage
#
# Collect ALL supported macOS Forensic Artifacts
#
#
# Dependencies:
#
# Aftermath v2.3.0 (2025-09-24)
# https://github.com/jamf/aftermath
# https://github.com/jamf/jamfprotect/tree/main/soar_playbooks/aftermath_collection
#
# KnockKnock v4.0.3 (2025-12-18)
# https://objective-see.com/products/knockknock.html
#
# TrueTree v0.8 (2024-08-23)
# https://github.com/themittenmac/TrueTree
#
#
# Tested on macOS Tahoe 26.3.1
#
#############################################################
#############################################################

# Declarations
SCRIPT_DIR=$( /usr/bin/cd "$( /usr/bin/dirname "${BASH_SOURCE[0]}" )" && /bin/pwd )
TIMESTAMP=$(/bin/date '+%FT%H%M%S') # YYYY-MM-DDThhmmss
OUTPUT="$SCRIPT_DIR/output/$(/bin/hostname)/$TIMESTAMP-macos-collector"

# Archive Passwords
ARCHIVE_PASSWORD="IncidentResponse"
PASSWORD="infected" # Quarantine Files

# Aftermath
AFTERMATH="$SCRIPT_DIR/tools/Aftermath/aftermath"
FILEHASH="A0668EB91650513F40CE8753A277E0E0" # MD5

# KnockKnock
KNOCKKNOCK="$SCRIPT_DIR/tools/KnockKnock/KnockKnock.app"

# TrueTree
TRUETREE="$SCRIPT_DIR/tools/TrueTree/TrueTree"

# VirusTotal API
# https://www.virustotal.com/#/join-us --> Join the community for free
VIRUSTOTAL="YOUR_API_KEY" # Insert your VirusTotal API key here (Default: YOUR_API_KEY)

#############################################################
#############################################################

Header() {
clear
echo "macOS-Collector - Automated Collection of macOS Forensic Artifacts for DFIR"
echo "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
echo ""

/bin/cat << "EOF"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
EOF

echo ""

}

#############################################################
#############################################################

Usage() {
Header
echo "Usage: $0 [OPTION]"
echo ""
echo "Options:"
echo "-c / --collect         Scan and collect forensic artifacts w/ Aftermath (Step #1)"
echo "-a / --analyze         Analyze previous collected Aftermath archive (Step #2)"
echo "-b / --btm             Collect BTM Dump File (Background Task Management)"
echo "-d / --ds_store        Collect .DS_Store Files"
echo "-f / --fsevents        Collect FSEvents Data"
echo "-i / --info            Collect System Information"
echo "-k / --knockknock      Scan Live System w/ KnockKnock (Persistence)"
echo "-l / --logs            Collect Apple Unified Logs (AUL)"
echo "-m / --metadata        Collect Spotlight Database (Desktop Search Engine)"
echo "-p / --processes       Collect Snapshot of Running Processes w/ TrueTree"
echo "-r / --recentitems     Collect Recent Items (MRU)"
echo "-s / --sysdiagnose     Collect Sysdiagnose Logs"
echo "-t / --triage          Collect ALL supported macOS Forensic Artifacts"
echo "-h / --help            Show this help message"
echo ""
exit 0
}

Usage2() {
echo "Usage: $0 [OPTION]"
echo ""
echo "Options:"
echo "-c / --collect         Scan and collect forensic artifacts w/ Aftermath (Step #1)"
echo "-a / --analyze         Analyze previous collected Aftermath archive (Step #2)"
echo "-b / --btm             Collect BTM Dump File (Background Task Management)"
echo "-d / --ds_store        Collect .DS_Store Files"
echo "-f / --fsevents        Collect FSEvents Data"
echo "-i / --info            Collect System Information"
echo "-k / --knockknock      Scan Live System w/ KnockKnock (Persistence)"
echo "-l / --logs            Collect Apple Unified Logs (AUL)"
echo "-m / --metadata        Collect Spotlight Database (Desktop Search Engine)"
echo "-p / --processes       Collect Snapshot of Running Processes w/ TrueTree"
echo "-r / --recentitems     Collect Recent Items (MRU)"
echo "-s / --sysdiagnose     Collect Sysdiagnose Logs"
echo "-t / --triage          Collect ALL supported macOS Forensic Artifacts"
echo "-h / --help            Show this help message"
echo ""
exit 0
}

#############################################################
#############################################################

Check_Admin() {
	# Check if the script is running with root privileges
	if [[ $EUID -ne 0 ]]; then 
		echo -e "\033[91m[Error] macos-collector.sh needs be run with root privileges.\033[0m"
		echo -e "\033[91m        sudo bash macos-collector.sh --collect\033[0m"
		echo ""
		exit 1
	fi
}

#############################################################
#############################################################

Check_FDA() {
	# Check if Terminal application has full disk access (FDA)
	if ! plutil -lint /Library/Preferences/com.apple.TimeMachine.plist > /dev/null; then
		echo -e "\033[91m[Error] Your Terminal application has no full disk access (FDA).\033[0m"
		echo
		echo "1. Add your Terminal application (temporarily) to the 'Full Disk Access' list: System Settings --> Privacy & Security --> Full Disk Access"
	  	echo "2. To add a new application to the list, click the (+) button below the right pane. This opens a file browser that allows you to select your Terminal application."
		echo "   Note: If your Terminal application is already listed, you can turn it on or off by using the toggle."
		echo "3. Quit & Reopen your Terminal application and re-run 'macos-collector.sh'"
		echo ""
		exit 1
	fi
}

#############################################################
#############################################################

Output() {

	# Time Duration
	START_TIME=$SECONDS

	# Check if output folder exists
	if [[ -d "$OUTPUT" ]]
		then
			/bin/rm -r "$OUTPUT"
		else
			/bin/mkdir -p "$OUTPUT"
	fi
}

#############################################################
#############################################################

BasicInfo() {

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Host Name
HostName=$(/bin/hostname)
echo "[Info]  Host Name: $HostName"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType 2> /dev/null)

# Model Name
ModelName=$(echo "$SPHardwareDataType" | /usr/bin/grep "Model Name:" | /usr/bin/sed -e 's/.*Model Name: //')
echo "[Info]  Model Name: $ModelName"

# Model Identifier
ModelIdentifier=$(echo "$SPHardwareDataType" | /usr/bin/grep "Model Identifier:" | /usr/bin/sed -e 's/.*Model Identifier: //')
echo "[Info]  Model Identifier: $ModelIdentifier"

# CPU
Chip=$(/usr/sbin/sysctl  -n machdep.cpu.brand_string)
echo "[Info]  Chip: $Chip"

# Physical Memory
RAM=$(echo "$SPHardwareDataType" | /usr/bin/grep "Memory:" | /usr/bin/sed -e 's/.*Memory: //')
echo "[Info]  Physical Memory: $RAM"

# Serial Number
SerialNumber=$(echo "$SPHardwareDataType" | /usr/bin/grep "Serial Number (system):" | /usr/bin/sed -e 's/.*Serial Number (system): //')
echo "[Info]  Serial Number: $SerialNumber"

# OS Codename
PRODUCTVERSION=$(/usr/bin/sw_vers -productVersion)

if echo "$PRODUCTVERSION" | /usr/bin/grep -q "^10\."
then
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{ print $2 }')
	os_codename=(
	["10"]="Yosemite"
	["11"]="El Capitan"
	["12"]="Sierra"
	["13"]="High Sierra"
	["14"]="Mojave"
	["15"]="Catalina"
	)
else
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{ print $1 }')
	os_codename=(
	["11"]="Big Sur"
	["12"]="Monterey"
	["13"]="Ventura"
	["14"]="Sonoma"
	["15"]="Sequoia"
	["26"]="Tahoe"
	)
fi

# Check if the number extracted is in array
if [[ -n "${os_codename[$os_num]}" ]]
then
	echo "[Info]  OS Codename: macOS "${os_codename[$os_num]}""
else
	echo "[Info]  OS Codename: Unknown"
fi

# OS Version
ProductVersion=$(/usr/bin/sw_vers -productVersion)
BuildVersion=$(/usr/bin/sw_vers -buildVersion)
echo "[Info]  OS Version: $ProductVersion ($BuildVersion)"

# Uptime
UPTIME=$(/usr/bin/uptime | /usr/bin/sed -E 's/^[^,]*up *//; s/mins/minutes/; s/hrs?/hours/;
s/([[:digit:]]+):0?([[:digit:]]+)/\1 hours, \2 minutes/;
s/^1 hours/1 hour/; s/ 1 hours/ 1 hour/;
s/min,/minutes,/; s/ 0 minutes,/ less than a minute,/; s/ 1 minutes/ 1 minute/;
s/  / /; s/, *[[:digit:]]* users?.*//')
echo "[Info]  Uptime: $UPTIME"

# BootTime (UTC)
BootTime=$(/usr/sbin/sysctl -n kern.boottime | /usr/bin/awk -F'[ ,]' '{print $4}')
echo -n "[Info]  Boot Time: "; /bin/date -ur $(($BootTime)) +"%Y-%m-%d %H:%M:%S UTC"

# Logged In User
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
echo "[Info]  LoggedInUser: $LoggedInUser"

# XProtect
FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	YARA=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($YARA YARA rules)"
fi

# sudo xprotect check
# sudo xprotect update

# XProtect Remediator (XPR)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	echo "[Info]  XProtect Remediator Version: $VERSION"
fi

# Malware Removal Tool (MRT)
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.")
	echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
fi

# Built-in macOS Security Tool --> How everything works together
# When a file is downloaded via browser or via application (e.g. Safari, Mail, Messages), it is marked with the quarantine flag (com.apple.quarantine).
# Gatekeeper checks if the file is signed and notarized. If it is not, the user receives a warning before execution.
# If execution is allowed, XProtect scans the file against its known malware signatures (from XProtect.plist, XProtect.yara, etc.).
# If malware is detected, the system prevents execution. If the malware is known and can be remediated, XProtect Remediator or MRT may delete or neutralize it.
# Apple updates XProtect, MRT, and XProtect Remediator silently in the background via the XProtectService process.

}

#############################################################
#############################################################

SystemInfo() {

# Stats
START_SYSTEMINFO=$(/bin/date +%s)

# System Information
echo "[Info]  Collecting System Information [approx. 5-10 min] ..."
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo"

# System Version
FILE="/System/Library/CoreServices/SystemVersion.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SystemVersion.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemVersion.txt"
fi

# Gatekeeper Status (System Policy Control)
GKStatus=$(/usr/sbin/spctl --status)

if [[ $GKStatus = "assessments enabled" ]]; then
	echo "[Info]  Gatekeeper is active, restricting apps to Apple Store and identified developers." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper_Status.txt"
elif [[ $GKStatus = "assessments disabled" ]]; then
	echo "[ALERT] Gatekeeper is NOT actively blocking apps." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/Gatekeeper_Status.txt"
	echo -e "\033[91m[ALERT] Gatekeeper is NOT actively blocking apps.\033[0m"
else
	echo "$GKStatus" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/Gatekeeper_Status.txt"
fi

# System Settings > Privacy & Security > Security
#
# Allow applications from:
# 1. App Store
# 2. App Store & Known Developers

# Gatekeeper Rules
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper"
/usr/bin/sudo /usr/sbin/spctl --list > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/Gatekeeper_Rules.txt" 2>&1

# Gatekeeper Database
GatekeeperDatabase="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/gk.db"
if [[ -f "$GatekeeperDatabase" ]]; then

	# Blocked Team IDs (Developer IDs)
	BlockedTeams=$(/usr/bin/sqlite3 "$GatekeeperDatabase" .dump | /usr/bin/grep "blocked_teams" | /usr/bin/cut -d "'" -f 2 | /usr/bin/grep -E "^[A-Z0-9]{10}$" | /usr/bin/sort -u)
	Count=$(echo "$BlockedTeams" | /usr/bin/grep -c ^)
	echo "$BlockedTeams" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/GateKeeper_BlockedTeams.txt"
	echo "[Info]  $Count Blocked Team Identifier found" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/GateKeeper_BlockedTeams_Count.txt"

	# Blocked CDHashes
	BlockedHashes=$(/usr/bin/sqlite3 "$GatekeeperDatabase" .dump | /usr/bin/grep "blocked_hashes" | /usr/bin/cut -d "'" -f 2 | /usr/bin/grep -E "^[0-9a-f]{40}$" | /usr/bin/sort -u)
	Count=$(echo "$BlockedHashes" | /usr/bin/grep -c ^)
	echo "$BlockedHashes" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/GateKeeper_BlockedHashes.txt"
	echo "[Info]  $Count Blocked Hash Value(s) found" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/GateKeeper_BlockedHashes_Count.txt"
fi

# XProtect Remediator (XPR) - Background Scan Settings
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR"

FILE="/Library/Apple/System/Library/LaunchAgents/com.apple.XProtect.agent.scan.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR/com.apple.XProtect.agent.scan.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR/com.apple.XProtect.agent.scan.txt"
fi

FILE="/Library/Apple/System/Library/LaunchAgents/com.apple.XProtect.agent.scan.startup.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR/com.apple.XProtect.agent.scan.startup.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR/com.apple.XProtect.agent.scan.startup.txt"
fi

FILE="/Library/Apple/System/Library/LaunchDaemons/com.apple.XProtect.daemon.scan.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR/com.apple.XProtect.daemon.scan.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XPR/com.apple.XProtect.daemon.scan.txt"
fi

# Fast Scan     --> Interval: 21600 (6 hours)  --> AllowBattery: true
# Standard Scan --> Interval: 86400 (24 hours) --> AllowBattery: false
# Slow Scan     --> Interval: 604800 (7 days)  --> AllowBattery: false

# System Integrity Protection (SIP)
# Note: Protected can be identified by looking for the com.apple.rootless extended attribute on a file or directory (xattr -l /System).
SIP=$(/usr/bin/csrutil status)

if [[ $SIP = "System Integrity Protection status: enabled." ]]; then
	echo "[Info]  System Integrity Protection (SIP) is on." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP_Status.txt"
elif [[ $SIP = "System Integrity Protection status: disabled." ]]; then	
	echo "[Info]  System Integrity Protection (SIP) is off." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP_Status.txt"
	echo -e "\033[91m[ALERT] System Integrity Protection (SIP) is off.\033[0m"
else
	echo "$SIP" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP_Status.txt"
fi

# Install Date(s)

# Original Install Date 
# Note: Time Zone = Cupertino, California --> PDT (Pacific Daylight Time) --> UTC -7
FILE="/private/var/db/.AppleSetupDone"
if [[ -f "$FILE" ]]; then
	/usr/bin/stat -x "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Original-InstallDate.txt"
fi

# install.log (System Local Time)
FILE="/var/log/install.log"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/install.log"
fi

# Timezone Information
Timezone=$(/usr/bin/sudo /usr/sbin/systemsetup -gettimezone | /usr/bin/sed -e 's/Time Zone: //g')
echo "[Info]  Timezone Information: $Timezone" > "$OUTPUT/SystemInfo/SystemInfo_Data/Timezone.txt"

# Preferred Languages
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
AppleLanguages=$(/usr/bin/sudo -u $LoggedInUser defaults read -g AppleLanguages)
echo "$AppleLanguages" | /usr/bin/grep -o '"[^"]\+"' | /usr/bin/tr -d '"' | /usr/bin/sort > "$OUTPUT"/SystemInfo/SystemInfo_Data/PreferredLanguages.txt

# System Language
/usr/libexec/PlistBuddy -c "Print AppleLanguages:0" "/Library/Preferences/.GlobalPreferences.plist" > "$OUTPUT"/SystemInfo/SystemInfo_Data/SystemLanguage.txt

# Default Browser
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	/usr/bin/defaults read "/Users/$UserName/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.secure.plist" | /usr/bin/awk -F'"' '/http;/{print window[(NR)-1]}{window[NR]=$2}' > "$OUTPUT/SystemInfo/SystemInfo_Data/DefaultBrowser_$UserName.txt"
done

# Firmware Password (Intel)
# Note: Apple Silicon Macs don't support the old firmwarepasswd utility (Firmware Password Utility).
PLATFORM=$(/usr/bin/uname -m)
if [[ $PLATFORM = "x86_64" ]]; then
	FirmwarePassword=$(/usr/bin/sudo /usr/sbin/firmwarepasswd -check 2 > "$OUTPUT/SystemInfo/SystemInfo_Data/Firmware-Password.txt")
	echo $FirmwarePassword >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Firmware-Password.txt
	if echo "$FirmwarePassword" | /usr/bin/grep -q "Password Enabled: Yes";then
		echo "[Info]  Firmware Password Enabled: Yes"
	else
		echo "[Info]  Firmware Password Enabled: No"
	fi
fi

# T2 Security Chip
# Apple Silicon (M-series) integrates all these functions, including advanced security, directly into the main system-on-a-chip (SoC), making a separate T2 chip obsolete.
PLATFORM=$(/usr/bin/uname -m)
if [[ $PLATFORM = "x86_64" ]]; then
	SPiBridgeDataType=$(/usr/sbin/system_profiler SPiBridgeDataType)
	if echo "$SPiBridgeDataType" | /usr/bin/grep -q "Apple T2";then
		echo "[Info]  Security Chip: Apple T2" > "$OUTPUT/SystemInfo/SystemInfo_Data/T2-Security-Chip.txt"
	fi
fi

# Software Update Tool (incl. Security Updates)
/usr/sbin/softwareupdate --list --include-config-data > "$OUTPUT/SystemInfo/SystemInfo_Data/softwareupdate_security.txt" 2>&1

# AirDrop Status (AirDrop Interface --> Apple Wireless Direct Link)
# Note: AirDrop lets you share instantly with people nearby. You can be discoverable in AirDrop to receive from everyone or only people in your contacts.
AirDrop=$(/usr/bin/sudo /sbin/ifconfig awdl0 | /usr/bin/awk '/status/{print $2}')

if [[ $AirDrop = "active" ]]; then
	echo "[Info]  AirDrop is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop_Status.txt"
elif [[ $AirDrop = "inactive" ]]; then
	echo "[Info]  AirDrop is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop_Status.txt"
else
	AirDrop=$(/usr/bin/sudo /sbin/ifconfig awdl0)
	echo "$AirDrop" > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop_Status.txt"
fi

# AirDrop Preferences
FILE="/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/com.apple.airport.preferences.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/com.apple.airport.preferences.txt" 
fi

# a) Finder > AirDrop > Allow me to be discovered by: ...
# b) System Settings > General > AirDrop & Handoff

# Use AirDrop as
# AirDrop lets you share instantly with people nearby.
# Allow me to be discovered by: Contacts Only
# 1. No One
# 2. Contacts Only
# 3. Everyone

# Bluetooth Status
SPBluetoothDataType=$(/usr/sbin/system_profiler SPBluetoothDataType)
echo "$SPBluetoothDataType" > "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth.txt"

if echo $SPBluetoothDataType | /usr/bin/grep -A 2 "Bluetooth Controller:" | /usr/bin/grep -q "State: On"; then
	echo "[Info]  Bluetooth is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth_Status.txt"
else
	echo "[Info]  Bluetooth is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth_Status.txt"
fi

# System Settings > Bluetooth

# Connect to accessories you can use for activities such as streaming music, typing, and gaming.

# My Devices
# Manage devices that were previously connected to your Mac and can automatically reconnect.

# Nearby Devices
# Connect a new wireless device to your Mac and see other discoverable wireless devices in the area.

# Wi-Fi Status
SPAirPortDataType=$(/usr/sbin/system_profiler SPAirPortDataType)
echo "$SPAirPortDataType" > "$OUTPUT/SystemInfo/SystemInfo_Data/SPAirPortDataType.txt"

if echo $SPAirPortDataType | /usr/bin/grep -q "State: Connected"; then
	echo "[Info]  Wi-Fi is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi_Status.txt" # Status: Connected
else
	echo "[Info]  Wi-Fi is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi_Status.txt" # Status: Off
fi

# Wireless Diagnostics
WirelessDiagnostics=$(/usr/bin/sudo /usr/bin/wdutil info)
echo "$WirelessDiagnostics" > "$OUTPUT/SystemInfo/SystemInfo_Data/Wireless-Diagnostics.txt"

# Application Layer Firewall (ALF)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall"

# Firewall Status
Firewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)

# Firewall is enabled. (State = 1)
# Firewall is disabled. (State = 0)

if echo "$Firewall" | grep -q "Firewall is enabled."; then # The firewall is turned on and set up to prevent unauthorized applications, programs, and services from accepting incoming connections.
	StealthMode=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode)
	echo "[Info]  $Firewall" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Firewall_Status.txt"
	echo "[Info]  $StealthMode" >> "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Firewall_Status.txt"
else
	echo -e "\033[91m[ALERT] This computer's firewall is currently turned off. All incoming connections to this computer are allowed.\033[0m"
fi

# System Settings > Network > Firewall

# Allowed Applications
AddedApps=$(/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps)
echo "$AddedApps" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Allowed-Applications.txt"

# Application Layer Firewall Configuration
FILE="/Library/Preferences/com.apple.alf.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/com.apple.alf.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/com.apple.alf.txt" 
fi

# Screen Sharing Preferences
ScreenSharing=$(/usr/bin/defaults read /System/Library/LaunchDaemons/com.apple.screensharing.plist)
echo "$ScreenSharing" > "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing-Preferences.txt"

# Screen Sharing Daemon
ScreenSharingDaemon=$(/usr/bin/sudo /bin/launchctl list com.apple.screensharing 2>&1)
echo "$ScreenSharingDaemon" > "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing-Daemon.txt"

# Network File Shares (NFS)
/sbin/nfsd status > "$OUTPUT/SystemInfo/SystemInfo_Data/Network-File-Shares.txt" 2>&1

# List Disks (including internal and external disks, whole disks and partitions, and various kinds of virtual or offline disks)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo"
Disks=$(/usr/sbin/diskutil list 2>&1)
echo "$Disks" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/Disks.txt"

# Data Volume
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/DataVolume"

# Data Volume - Name
VolumeName=$(/usr/sbin/diskutil info / | /usr/bin/grep "Volume Name" | /usr/bin/cut -c 31-9999)
echo "$VolumeName" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/DataVolume/VolumeName.txt"

# Data Volume - Identifier
Data_Volume_Id=$(/usr/sbin/diskutil list internal | /usr/bin/awk '/APFS Volume Data/{print $NF}')
echo "$Data_Volume_Id" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/DataVolume/Identifier.txt"

# Data Volume - Disk Space (Bytes)
Data_Volume_Total=$(/usr/sbin/diskutil info $Data_Volume_Id | /usr/bin/awk -F'[(|B]' '/Container Total Space:/{print $3}')
Data_Volume_Free=$(/usr/sbin/diskutil info $Data_Volume_Id | /usr/bin/awk -F'[(|B]' '/Container Free Space:/{print $3}')
Data_Volume_Used=$(/usr/sbin/diskutil info $Data_Volume_Id | /usr/bin/awk -F'[(|B]' '/Volume Used Space:/{print $3}')

Data_Volume_Free_Percentage=$(/bin/echo "scale=3; 100 - $Data_Volume_Used / $Data_Volume_Total * 100" | /usr/bin/bc)
FREEPERCENT=$(echo "$(printf "%.1f\\n" ${Data_Volume_Free_Percentage})%")

Data_Volume_Used_Percentage=$(/bin/echo "scale=3; 100 - $Data_Volume_Free / $Data_Volume_Total * 100" | /usr/bin/bc)
USEDPERCENT=$(echo "$(printf "%.1f\\n" ${Data_Volume_Used_Percentage})%")

# Data Volume - Total Space
TOTALSPACE=$(echo "$Data_Volume_Total" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "$TOTALSPACE" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/DataVolume/TotalSpace.txt"

# Data Volume - Free Space
FREESPACE=$(echo "$Data_Volume_Free" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "$FREESPACE ($FREEPERCENT)" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/DataVolume/FreeSpace.txt"

# Data Volume - Used Space
USEDSPACE=$(echo "$Data_Volume_Used" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "$USEDSPACE ($USEDPERCENT)" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/DataVolume/UsedSpace.txt"

# Show status of all current APFS Containers
APFS_Containers=$(/usr/sbin/diskutil apfs list 2>&1)
echo "$APFS_Containers" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/APFS_Containers.txt"

# Get information on a specific disk or partition (Data Volume)
DiskInfo=$(/usr/sbin/diskutil info / 2>&1)
echo "$DiskInfo" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/diskutil-info.txt"

# APFS Snapshots
/usr/sbin/diskutil apfs listsnapshots / > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/diskutil-apfs-listsnapshots.txt"
/usr/bin/tmutil listlocalsnapshots / > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/tmutil-listlocalsnapshots.txt"
/usr/bin/tmutil listlocalsnapshotdates / > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/tmutil-listlocalsnapshotdates.txt"
/usr/bin/tmutil version > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/tmutil-version.txt"

# List of currently mounted file systems
/sbin/mount > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/mount.txt"

# FileVault Status
FileVault=$(/usr/bin/sudo /usr/bin/fdesetup status)

if [[ $FileVault = "FileVault is On." ]]; then
	echo "[Info]  FileVault is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/FileVault_Status.txt"
elif [[ $FileVault = "FileVault is Off." ]]; then
	echo "[ALERT] FileVault is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/FileVault_Status.txt"
	echo -e "\033[91m[ALERT] FileVault is Off.\033[0m"
else
	echo "$FileVault" > "$OUTPUT/SystemInfo/SystemInfo_Data/DiskInfo/FileVault_Status.txt"
fi

# Sharing
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing"

# Remote Login
# Note: Remote Login lets users of other computers access this computer using SSH and SFTP.
RemoteLogin=$(/usr/bin/sudo /usr/sbin/systemsetup -getremotelogin)

if [[ $RemoteLogin = "Remote Login: On" ]]; then
	echo "[Info]  Remote Login is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/Remote-Login.txt"
elif [[ $RemoteLogin = "Remote Login: Off" ]]; then	
	echo "[Info]  Remote Login is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/Remote-Login.txt"
else
	echo "$RemoteLogin" > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/Remote-Login.txt"
fi

# System Settings > General > Sharing > Remote Login

# Remote Apple Events (RAE) aka Remote Application Scripting
# Note: Remote Application Scripting allows Apple events sent from other computers to control applications on this Mac.
RemoteAppleEvents=$(/usr/bin/sudo /usr/sbin/systemsetup -getremoteappleevents)
echo "$RemoteAppleEvents" > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/Remote-Apple-Scripting.txt"

# System Settings > General > Sharing > Remote Application Scripting

# Ensure Remote Apple Events Is Disabled
# /usr/bin/sudo /usr/sbin/systemsetup -setremoteappleevents off
if echo "$RemoteAppleEvents" | /usr/bin/grep -q "Remote Apple Events: On"; then
	echo -e "\033[91m[ALERT] Remote Apple Events (RAE) is ON.\033[0m"
fi

# Apple Remote Desktop (ARD) aka Remote Management
# Note: Remote Management allows other users to access this computer using Apple Remote Desktop.
RemoteManagement=$(/usr/bin/sudo /bin/launchctl print gui/501/com.apple.RemoteDesktop.agent | grep -A4 "gui/501/com.apple.RemoteDesktop.agent =")
if echo "$RemoteManagement" | /usr/bin/grep -q "state = running"; then
	echo "[Info]  Apple Remote Desktop (ARD) is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/Remote-Management.txt"
else
	echo "[Info]  Apple Remote Desktop (ARD) is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/Remote-Management.txt"
fi

# System Settings > General > Sharing > Remote Management

# Apple Remote Desktop (ARD) Agent - Preferences
FILE="/Library/Preferences/com.apple.ARDAgent.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/com.apple.ARDAgent.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/com.apple.ARDAgent.txt" 
fi

# Remote Management - Preferences
FILE="/Library/Preferences/com.apple.RemoteManagement.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/com.apple.RemoteManagement.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/com.apple.RemoteManagement.txt" 
fi

# RemoteDesktop - Preferences
FILE="/Library/Preferences/com.apple.RemoteDesktop.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/com.apple.RemoteDesktop.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/com.apple.RemoteDesktop.txt" 
fi

# Remote Management Database File (RMDB)
FILE="/private/var/db/RemoteManagement/RMDB/rmdb.sqlite3"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/rmdb.sqlite3"
fi

# Remote Management Configuration File
# The execution of the Apple Remote Desktop (ARD) kickstart command modifies the contents of the configuration file to contain the string "enabled".
# The Apple Remote Desktop kickstart command is a powerful utility located at /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart used to manage the ARD agent via Terminal. 
# It enables, configures, activates, and restarts the agent, often used for remote setup over SSH. 
FILE="/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/RemoteManagement.launchd"
fi

# Collecting Apple Remote Desktop Artifacts
SOURCE="/private/var/db/RemoteManagement/"
DESTINATION="$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/RemoteManagement_Data"
if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/RemoteManagement_Data"
	/usr/bin/sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" >> "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/RemoteManagement_Collection.txt"
fi

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/RemoteManagement_Data" ]]; then
	cd "$OUTPUT/SystemInfo/SystemInfo_Data/Sharing"
	/usr/bin/zip -q -r "RemoteManagement_$SerialNumber.zip" RemoteManagement_Data
	cd "$SCRIPT_DIR"
fi

# Cleaning up
FOLDER="$OUTPUT/SystemInfo/SystemInfo_Data/Sharing/RemoteManagement_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# I/O Statistics
/usr/sbin/iostat > "$OUTPUT/SystemInfo/SystemInfo_Data/IO_Statistics.txt" 2>&1

# Login History
/usr/bin/last > "$OUTPUT/SystemInfo/SystemInfo_Data/Login_History.txt" 2>&1

# Users
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo"
/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500' | /usr/bin/sort -k2 > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Users.txt" 2>&1

# Admin Users
Administrators=$(/usr/bin/dscl . -read /Groups/admin GroupMembership | /usr/bin/sed -e 's/GroupMembership: //g' | /usr/bin/tr " " "\n")
echo "$Administrators" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Administrators.txt"

# Local Admins
admin_list=()

for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	if [[ $(/usr/sbin/dseditgroup -o checkmember -m "$UserName" admin | /usr/bin/grep "^yes") ]]; then
		admin_list+=("${UserName}")
	fi
done

if [[ "${admin_list[@]}" != "" ]]; then
	echo "${admin_list[@]}" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Local-Administrators.txt"
else
	echo "None" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Local-Administrators.txt"
fi

# Guest User
FILE="/Library/Preferences/com.apple.loginwindow.plist"
if [[ -f "$FILE" ]]; then
	GuestUser=$(/usr/bin/defaults read "$FILE" GuestEnabled)
	if [[ $GuestUser = "0" ]]; then
		echo "[Info]  Guest User is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/GuestUser.txt"
	elif [[ $GuestUser = "1" ]]; then
		echo "[Info]  Guest User is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/GuestUser.txt"
	else
		echo "$GuestUser" > "$OUTPUT/SystemInfo/SystemInfo_Data/GuestUser.txt"
	fi
fi

# Apple Account(s)
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	if [ -e "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist" ]; then
		/bin/cp "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist" "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/MobileMeAccounts_$UserName.plist"
		/usr/libexec/PlistBuddy -c "print" "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/MobileMeAccounts_$UserName.txt"
		AccountID=$(/usr/libexec/PlistBuddy -c "print :Accounts:0:AccountID" "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist")
		EmailVerified=$(/usr/libexec/PlistBuddy -c "print :Accounts:0:primaryEmailVerified" "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist")
		IsManaged=$(/usr/libexec/PlistBuddy -c "print :Accounts:0:isManagedAppleID" "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist")
		MobileDocuments=$(/usr/libexec/PlistBuddy -c "print :Accounts:0:Services" "/Users/$UserName/Library/Preferences/MobileMeAccounts.plist" | grep -A1 -B6 "Name = MOBILE_DOCUMENTS")
		CloudDesktop=$(/usr/bin/sudo /usr/bin/xattr -p com.apple.icloud.desktop "/Users/$UserName/Desktop" 2> /dev/null)
		echo "Name:          $UserName" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		echo "AccountID:     $AccountID" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		echo "EmailVerified: $EmailVerified" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		echo "IsManaged:     $IsManaged" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"

		# iCloud Drive Sync
		if echo "$MobileDocuments" | grep -q "Enabled = false";then
			echo "iCloud Drive:  false" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		else
			echo "iCloud Drive:  true" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		fi

		# iCloud Desktop & Documents Folders Sync
		if [[ -z "$CloudDesktop" ]]; then
			echo "Desktop & Documents Folders: false" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		else
			echo "Desktop & Documents Folders: true" >> "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Accounts.txt"
		fi
	fi
done

# System Settings > [Apple Account] > iCloud > iCloud Drive

# Login Window
/usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.loginwindow > "$OUTPUT/SystemInfo/SystemInfo_Data/LoginWindow.txt"

# System Configuration / Network Settings
FILE="/Library/Preferences/SystemConfiguration/preferences.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/preferences.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/preferences.txt"
fi

# Network Interfaces
/sbin/ifconfig > "$OUTPUT/SystemInfo/SystemInfo_Data/Network-Interfaces.txt" 2>&1

# DNS Configuration
/usr/sbin/scutil --dns > "$OUTPUT/SystemInfo/SystemInfo_Data/DNS.txt" 2>&1

# List all Network Services
/usr/sbin/networksetup -listallnetworkservices > "$OUTPUT/SystemInfo/SystemInfo_Data/Network-Services.txt" 2>&1

# Installed Applications (Primary System Applications --> accessible to all users)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo"
InstalledApps=$(/usr/bin/mdfind -onlyin /Applications "kind:application" 2>&1 | /usr/bin/grep -v "UserQueryParser" | grep -v "\.app/Contents/" | /usr/bin/sort)
echo "$InstalledApps" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Installed-Apps.txt"

# Header
echo "\"Name\",\"FullPath\",\"MD5\",\"SHA1\",\"SHA256\",\"Filesize\",\"Bytes\",\"Version\",\"BundleIdentifier\",\"Copyright\",\"UseCount\",\"LastUsedDate\",\"DateAdded\",\"ContentCreationDate\",\"ContentModificationDate\",\"SignatureStatus\",\"SignatureOrigin\",\"SignatureSource\"" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Installed-Apps.csv"

# Data
while read Application
do
	Name=$(/usr/bin/basename "$Application")

	Executable=""

	# Check if Code Signature contains Executable Info
	if /usr/bin/codesign -dr - "$Application" 2>&1 | /usr/bin/grep -q "Executable="; then
		Executable=$(/usr/bin/codesign -dr - "$Application" 2>&1 | grep "Executable=" | head -1 | /usr/bin/sed -n 's/^.*Executable=//p')
	else
		# Check if Info.plist exists
		if [[ -f "$Application/Contents/Info.plist" ]]; then
			CFBundleExecutable=$(/usr/bin/defaults read "$Application/Contents/Info.plist" CFBundleExecutable 2> /dev/null)
			Executable=$(/usr/bin/find "$Application" -type f -name "$CFBundleExecutable")
		else
			# Guessing Binary Name
			BaseName="$Name"
			Binary=$(/usr/bin/basename ${BaseName%.*})
			Executable="$Application/$Binary"
		fi
	fi

	# Calculating File Hashes of Primary Executable --> VirusTotal
	if [[ -n "$Executable" ]]; then
		MD5=$(/sbin/md5sum "$Executable" 2> /dev/null | /usr/bin/awk '{print $1}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		SHA1=$(/usr/bin/shasum -a 1 "$Executable" 2> /dev/null | /usr/bin/awk '{print $1}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		SHA256=$(/usr/bin/shasum -a 256 "$Executable" 2> /dev/null | /usr/bin/awk '{print $1}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	else
		MD5="Not found."
		SHA1="Not found."
		SHA256="Not found."
	fi

	PhysicalSize=$(/usr/bin/mdls -name kMDItemPhysicalSize "$Application" | /usr/bin/sed -e 's/.*= //g')
	Filesize=$(echo "$PhysicalSize" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	LogicalSize=$(/usr/bin/mdls -name kMDItemLogicalSize "$Application" | /usr/bin/sed -e 's/.*= //g')
	Bytes=$(/usr/bin/printf "%'d\n" "$LogicalSize" 2> /dev/null | /usr/bin/tr -s "," ".")
	Version=$(/usr/bin/mdls -name kMDItemVersion "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/tr -d '"')
	BundleIdentifier=$(/usr/bin/mdls -name kMDItemCFBundleIdentifier "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/tr -d '"')
	Copyright=$(/usr/bin/mdls -name kMDItemCopyright "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/tr -d '"')
	UseCount=$(/usr/bin/mdls -name kMDItemUseCount "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g')
	LastUsedDate=$(/usr/bin/mdls -name kMDItemLastUsedDate "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC
	DateAdded=$(/usr/bin/mdls -name kMDItemDateAdded "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC
	ContentCreationDate=$(/usr/bin/mdls -name kMDItemContentCreationDate "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC
	ContentModificationDate=$(/usr/bin/mdls -name kMDItemContentModificationDate "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC

	# Signature Info
	Signature=$(/usr/sbin/spctl -a -t exec -vvvv "$Application" 2>&1)
	Status=$(echo "$Signature" | /usr/bin/grep "$Application" | /usr/bin/sed -e 's/.*: //g')
	Origin=$(echo "$Signature" | /usr/bin/grep "origin=" | /usr/bin/sed -e 's/origin=//g')
	Source=$(echo "$Signature" | /usr/bin/grep "source=" | /usr/bin/sed -e 's/source=//g')

	echo \"$Name\",\"$Application\",\"$MD5\",\"$SHA1\",\"$SHA256\",\"$Filesize\",\"$Bytes\",\"$Version\",\"$BundleIdentifier\",\"$Copyright\",\"$UseCount\",\"$LastUsedDate\",\"$DateAdded\",\"$ContentCreationDate\",\"$ContentModificationDate\",\"$Status\",\"$Origin\",\"$Source\" >> "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Installed-Apps.csv"

done < "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Installed-Apps.txt"

# Applications (Primary System Applications + User-Specific Applications + System Utility Applications + Alternative Locations)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo"
AllApps=$(/usr/bin/mdfind -onlyin "/Applications/" -onlyin "/Users/" -onlyin "/System/Applications/" -onlyin "/Library/Application Support/" "kind:application" 2>&1 | /usr/bin/grep -v "UserQueryParser" | grep -v "\.app/Contents/" | /usr/bin/sort)
echo "$AllApps" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Apps.txt"

# Header
echo "\"Name\",\"FullPath\",\"MD5\",\"SHA1\",\"SHA256\",\"Filesize\",\"Bytes\",\"Version\",\"BundleIdentifier\",\"Copyright\",\"UseCount\",\"LastUsedDate\",\"DateAdded\",\"ContentCreationDate\",\"ContentModificationDate\",\"SignatureStatus\",\"SignatureOrigin\",\"SignatureSource\"" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Apps.csv"

# Data
while read Application
do
	Name=$(/usr/bin/basename "$Application")

	Executable=""

	# Check if Code Signature contains Executable Info
	if /usr/bin/codesign -dr - "$Application" 2>&1 | /usr/bin/grep -q "Executable="; then
		Executable=$(/usr/bin/codesign -dr - "$Application" 2>&1 | grep "Executable=" | head -1 | /usr/bin/sed -n 's/^.*Executable=//p')
	else
		# Check if Info.plist exists
		if [[ -f "$Application/Contents/Info.plist" ]]; then
			CFBundleExecutable=$(/usr/bin/defaults read "$Application/Contents/Info.plist" CFBundleExecutable 2> /dev/null)
			Executable=$(/usr/bin/find "$Application" -type f -name "$CFBundleExecutable")
		else
			# Guessing Binary Name
			BaseName="$Name"
			Binary=$(/usr/bin/basename ${BaseName%.*})
			Executable="$Application/$Binary"
		fi
	fi

	# Calculating File Hashes of Primary Executable --> VirusTotal
	if [[ -n "$Executable" ]]; then
		MD5=$(/sbin/md5sum "$Executable" 2> /dev/null | /usr/bin/awk '{print $1}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		SHA1=$(/usr/bin/shasum -a 1 "$Executable" 2> /dev/null | /usr/bin/awk '{print $1}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		SHA256=$(/usr/bin/shasum -a 256 "$Executable" 2> /dev/null | /usr/bin/awk '{print $1}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	else
		MD5="Not found."
		SHA1="Not found."
		SHA256="Not found."
	fi

	# Physical Size
	PhysicalSize=$(/usr/bin/mdls -name kMDItemPhysicalSize "$Application" | /usr/bin/sed -e 's/.*= //g')
	Filesize=$(echo "$PhysicalSize" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	
	# Logical Size
	LogicalSize=$(/usr/bin/mdls -name kMDItemLogicalSize "$Application" | /usr/bin/sed -e 's/.*= //g')
	if [[ -z "$LogicalSize" ]]; then
		Bytes=$(/usr/bin/printf "%'d\n" "$LogicalSize" 2> /dev/null | /usr/bin/tr -s "," ".")
	else
		Bytes=$(/usr/bin/stat -f "%z" "$Application" 2> /dev/null)  
	fi

	Version=$(/usr/bin/mdls -name kMDItemVersion "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/tr -d '"')
	BundleIdentifier=$(/usr/bin/mdls -name kMDItemCFBundleIdentifier "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/tr -d '"')
	Copyright=$(/usr/bin/mdls -name kMDItemCopyright "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/tr -d '"')
	UseCount=$(/usr/bin/mdls -name kMDItemUseCount "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g')
	LastUsedDate=$(/usr/bin/mdls -name kMDItemLastUsedDate "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC
	DateAdded=$(/usr/bin/mdls -name kMDItemDateAdded "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC
	ContentCreationDate=$(/usr/bin/mdls -name kMDItemContentCreationDate "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC
	ContentModificationDate=$(/usr/bin/mdls -name kMDItemContentModificationDate "$Application" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/sed  's/(null)//g' | /usr/bin/sed  's/ +0000//g') # UTC

	# Signature Info
	Signature=$(/usr/sbin/spctl -a -t exec -vvvv "$Application" 2>&1)
	Status=$(echo "$Signature" | /usr/bin/grep "$Application" | /usr/bin/sed -e 's/.*: //g')
	Origin=$(echo "$Signature" | /usr/bin/grep "origin=" | /usr/bin/sed -e 's/origin=//g')
	Source=$(echo "$Signature" | /usr/bin/grep "source=" | /usr/bin/sed -e 's/source=//g')

	echo \"$Name\",\"$Application\",\"$MD5\",\"$SHA1\",\"$SHA256\",\"$Filesize\",\"$Bytes\",\"$Version\",\"$BundleIdentifier\",\"$Copyright\",\"$UseCount\",\"$LastUsedDate\",\"$DateAdded\",\"$ContentCreationDate\",\"$ContentModificationDate\",\"$Status\",\"$Origin\",\"$Source\" >> "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Apps.csv"

done < "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Apps.txt"

SPApplicationsDataType=$(/usr/sbin/system_profiler SPApplicationsDataType)
echo "$SPApplicationsDataType" > "$OUTPUT/SystemInfo/SystemInfo_Data/SPApplicationsDataType.txt"
/usr/sbin/system_profiler -json -nospawn SPApplicationsDataType -detailLevel full > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/SPApplicationsDataType.json"

# System Apps
SystemApps=$(/usr/bin/mdfind -onlyin /System/Applications/ "kind:application" 2>&1 | /usr/bin/grep -v "UserQueryParser" | /usr/bin/sort)
echo "$SystemApps" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/System-Apps.txt"

# List App Store Apps
/usr/bin/find /Applications -path '*Contents/_MASReceipt/receipt' -maxdepth 4 -print | /usr/bin/sed 's#.app/Contents/_MASReceipt/receipt#.app#g; s#/Applications/##' | /usr/bin/sort > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/AppStore-Apps.txt" 2>&1

# Recently Modified Applications (Last 7 Days)
#/usr/bin/find /Applications -type f -mtime -7 -ls > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Recently-Modified-Apps.txt" 2>&1

# List Apps and Processes connected to Internet
/usr/bin/sudo /usr/sbin/lsof -nPi | /usr/bin/cut -f 1 -d " " | /usr/bin/uniq | /usr/bin/tail -n +2 > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Internet-Connected-Apps.txt" 2>&1

# Active Processes
/bin/ps aux > "$OUTPUT/SystemInfo/SystemInfo_Data/Active-Processes.txt" 2>&1

# Recently Downloaded Files (Last 7 Days)
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	/usr/bin/find /Users/$UserName/Downloads -type f -mtime -7 -ls > "$OUTPUT/SystemInfo/SystemInfo_Data/Recently-Downloaded-Files_$UserName.txt" 2>&1
done

# List All Active Network Connections
/usr/bin/sudo /usr/sbin/lsof -i > "$OUTPUT/SystemInfo/SystemInfo_Data/Active-Network-Connections.txt" 2>&1

# List Open Files
/usr/bin/sudo /usr/sbin/lsof -n > "$OUTPUT/SystemInfo/SystemInfo_Data/Open-Files.txt" 2>&1

# Install History
# https://github.com/BigMacAdmin/macOS-Stuff/blob/main/installerHistory.sh
FILE="/Library/Receipts/InstallHistory.plist"
if [[ -f "$FILE" ]]; then
	/usr/libexec/PlistBuddy -c "print" "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/InstallHistory.txt"
fi

# Dock Information
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/DockInfo/raw"
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Preferences/com.apple.dock.plist"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/DockInfo/raw/DockItems_$UserName.plist"
		/usr/bin/defaults read "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/DockInfo/DockItems_$UserName.txt"
	fi
done

# Connected iDevices
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Preferences/com.apple.iPod.plist"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/iDevices/raw"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/iDevices/raw/iDevices_$UserName.plist"
		/usr/bin/defaults read "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/iDevices/iDevices_$UserName.txt"
	fi
done

# Mounted Volumes
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
if [[ -f "/Users/$LoggedInUser/Library/Preferences/com.apple.finder.plist" ]]; then
	/usr/bin/defaults read "/Users/$LoggedInUser/Library/Preferences/com.apple.finder.plist" FXDesktopVolumePositions > "$OUTPUT/SystemInfo/SystemInfo_Data/Mounted-Volumes.txt"
fi

# Find My Mac
FMM=$(/usr/sbin/nvram -x -p | /usr/bin/grep fmm-mobileme-token-FMM)
if [[ -z "$fmmToken" ]]; then
	echo "[Info]  Find My Mac is disabled." > "$OUTPUT/SystemInfo/SystemInfo_Data/FindMyMac_Status.txt"
else
	echo "[Info]  Find my Mac is enabled." > "$OUTPUT/SystemInfo/SystemInfo_Data/FindMyMac_Status.txt"
fi

# Supervision / Device Enrollment (MDM)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/MDM"
/usr/bin/sudo /usr/bin/profiles show > "$OUTPUT/SystemInfo/SystemInfo_Data/MDM/Profiles.txt" 2>&1
/usr/bin/sudo /usr/bin/profiles status -type enrollment > "$OUTPUT/SystemInfo/SystemInfo_Data/MDM/DeviceEnrollment_Status.txt" 2>&1

# System Settings > General > Device Management

# Jamf Pro (Apple Device Management)
# https://learn.jamf.com/en-US/bundle/jamf-pro-documentation-current/page/Components_Installed_on_Managed_Computers.html
FILE="/usr/local/jamf/bin/jamf"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro"
	/usr/local/jamf/bin/jamf about > "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro/About.txt" 2>&1
	/usr/local/jamf/bin/jamf version > "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro/Version.txt" 2>&1
	/usr/local/jamf/bin/jamf help > "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro/Help.txt" 2>&1
fi

# Jamf Pro - Preferences
FILE="/Library/Preferences/com.jamfsoftware.jamf.plist"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro/com.jamfsoftware.jamf.plist" 
fi

# Jamf Pro  - Client Logging
FILE="/var/log/jamf.log"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Pro/jamf.log"
fi

# Jamf Protect
# https://learn.jamf.com/en-US/bundle/jamf-protect-documentation/page/Command-Line_Tool.html
FILE="/usr/local/bin/protectctl"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Protect"
	/usr/local/bin/protectctl version > "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Protect/Version.txt" 2>&1
	/usr/local/bin/protectctl info -v > "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Protect/Info.txt" 2>&1
	/usr/local/bin/protectctl help > "$OUTPUT/SystemInfo/SystemInfo_Data/Jamf-Protect/Help.txt" 2>&1
fi

# Microsoft Intune (MDM)
APPLICATION="/Library/Intune/Microsoft Intune Agent.app"
if [[ -d "$APPLICATION" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Intune"
	echo "[Info] Microsoft Intune Agent found" > "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/Intune.txt"

	# Collecting Microsoft Intune Logs

	# Intune MDM Daemon Logs
	/usr/bin/sudo /usr/bin/find "/Library/Logs/Microsoft/Intune" -name "IntuneMDMDaemon*.log" -type f > "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/IntuneMDMDaemonLogs.txt" 2> /dev/null
	if [[ -s "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/IntuneMDMDaemonLogs.txt" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/Logs/Daemon"
		/usr/bin/sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/SystemInfo/SystemInfo_Data/Intune/IntuneMDMDaemonLogs.txt" / "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/Logs/Daemon" > /dev/null
	fi

	# Intune MDM Agent Logs
	/usr/bin/sudo /usr/bin/find "/Library/Logs/Microsoft/Intune" -name "IntuneMDMAgent*.log" -type f > "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/IntuneMDMAgentLogs.txt" 2> /dev/null
	if [[ -s "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/IntuneMDMAgentLogs.txt" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/Logs/Agent"
		/usr/bin/sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/SystemInfo/SystemInfo_Data/Intune/IntuneMDMAgentLogs.txt" / "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/Logs/Agent" > /dev/null
	fi

	# Intune MDM Daemon Configuration
	FILE="/Library/LaunchDaemons/com.microsoft.intuneMDMAgent.daemon.plist"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/com.microsoft.intuneMDMAgent.daemon.plist"
		/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/com.microsoft.intuneMDMAgent.daemon.txt"
	fi

	# Intune MDM Agent Configuration
	FILE="/Library/LaunchAgents/com.microsoft.intuneMDMAgent.plist"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/com.microsoft.intuneMDMAgent.plist"
		/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Intune/com.microsoft.intuneMDMAgent.txt"
	fi
fi

# Microsoft Defender for Endpoint (MDE)
FILE="/Library/Managed Preferences/com.microsoft.wdav.plist"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/MDE"

	# MDE Configuration
	/usr/bin/plutil -lint "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/MDE-Configuration-Validation.txt"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/com.microsoft.wdav.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/MDE-Configuration.txt"

	# MDE Attach
	FILE="/Library/Preferences/com.microsoft.mdeattach.plist"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/com.microsoft.mdeattach.plist"
		/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/com.microsoft.mdeattach.txt"
	fi

	# Onboarding Status / Settings / Health Status
	# https://learn.microsoft.com/en-us/defender-endpoint/mac-health-status
	/usr/local/bin/mdatp health > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/MDE-Health.txt" 2>&1
	/usr/local/bin/mdatp health --output json > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/MDE-Health.json" 2>&1

	# Install
	FILE="/Library/Logs/Microsoft/mdatp/install.log"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/install.log"
	fi

	# Current Scan Schedule
	/usr/local/bin/mdatp scan list > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Scan-List.txt" 2>&1

	# Protection History
	/usr/local/bin/mdatp threat list > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Protection-History.txt" 2>&1

	# Exclusions
	/usr/local/bin/mdatp exclusion list > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Exclusions.txt" 2>&1

	# Quarantine Files
	/usr/local/bin/mdatp threat quarantine list > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Quarantine-Files.txt" 2>&1

	# Quarantine Folder
	QUARANTINE_FOLDER="/Library/Application Support/Microsoft/Defender/quarantine"
	if [[ -n "$(/bin/ls -A "$QUARANTINE_FOLDER")" ]]; then

		# Count Quarantine Files
		COUNT=$(ls -1 "$QUARANTINE_FOLDER" | /usr/bin/grep -c ^)
		if [[ $COUNT -ge 1 ]];then
			echo -e "\033[91m[ALERT] $COUNT Quarantine File(s) found\033[0m"
			echo "[ALERT] $COUNT Quarantine File(s) found" >> "$LOGFILE"
		fi

		# Collect Quarantine Files
		if [[ $COUNT -ge 1 ]];then
			cd "$OUTPUT/SystemInfo/SystemInfo_Data/MDE"
			/usr/bin/zip -q -e -r -P "$PASSWORD" "Quarantine.zip" "$QUARANTINE_FOLDER/*"
			cd "$SCRIPT_DIR"
		fi
	fi

	# Diagnostic Logs
	DIAGNOSTIC_LOGS="/Library/Application Support/Microsoft/Defender/wdavdiag"
	DESTINATION="$OUTPUT/SystemInfo/SystemInfo_Data/MDE/DiagnosticLogs"
	if [[ -d "$DIAGNOSTIC_LOGS" ]] && [[ -n "$(/bin/ls -A "$DIAGNOSTIC_LOGS")" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/DiagnosticLogs"
		/usr/bin/rsync -av "$DIAGNOSTIC_LOGS" "$DESTINATION" > /dev/null
	fi

	# Network Connectivity
	/usr/local/bin/mdatp connectivity test > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Network-Connectivity.txt" 2>&1

	# Microsoft AutoUpdate (MAU)
	FILE="/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS/msupdate"
	if [[ -f "$FILE" ]]; then
		cd "/Library/Application Support/Microsoft/MAU2.0/Microsoft AutoUpdate.app/Contents/MacOS"
		
		# Show usage information
		./msupdate --help > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Microsoft-AutoUpdate_Help.txt" 2>&1

		# List available updates for installed Microsoft applications
		./msupdate --list > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/Microsoft-AutoUpdate_Available-Updates.txt" 2>&1

		# Application Identifier:
		# IMCP01 - Intune Company Portal
		# MSau04 - Microsoft AutoUpdate (MAU)
		# WDAV00 - Microsoft Defender for Endpoint (MDE)

		# Display current AutoUpdate configuration
		./msupdate --config > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/AutoUpdate-Configuration.txt" 2>&1
		./msupdate --config --format plist > "$OUTPUT/SystemInfo/SystemInfo_Data/MDE/AutoUpdate-Configuration.plist" 2>&1
		cd "$SCRIPT_DIR"
	fi
fi

# CrowdStrike Falcon
FILE="/Library/CS/falconctl"
if [ -f "$FILE" ]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/CrowdStrike"

	# CrowdStrike Agent Version
	AgentVersion=$(/usr/sbin/sysctl cs.version | /usr/bin/awk '{ print $2 }')
	echo "[Info]  CrowdStrike Agent Version: $AgentVersion" > "$OUTPUT/SystemInfo/SystemInfo_Data/CrowdStrike/Agent-Version.txt"

	# CrowdStrike Agent-ID
	AgentID=$(/usr/sbin/sysctl cs.sensorid | /usr/bin/awk '{ print $2 }')
	echo "[Info]  CrowdStrike Agent-ID: $AgentID" > "$OUTPUT/SystemInfo/SystemInfo_Data/CrowdStrike/Agent-ID.txt"

	# CrowdStrike InstallGuard
	InstallGuard=$(/usr/sbin/sysctl cs.control.installguard | /usr/bin/awk '{ print $2 }')
	echo "[Info]  CrowdStrike InstallGuard: $InstallGuard" > "$OUTPUT/SystemInfo/SystemInfo_Data/CrowdStrike/InstallGuard.txt"
fi

# Creating Archive File
if [[ -d "$OUTPUT/SystemInfo/SystemInfo_Data" ]]; then
	echo "[Info]  Compressing System Information (.zip) ..."
	cd "$OUTPUT/SystemInfo"
	/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "SystemInfo_$SerialNumber.zip" SystemInfo_Data
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/SystemInfo" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^SystemInfo_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/SystemInfo/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of SystemInfo Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/SystemInfo/SystemInfo_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# Stats
END_SYSTEMINFO=$(/bin/date +%s)
ELAPSED_TIME_SYSTEMINFO=$(($END_SYSTEMINFO - $START_SYSTEMINFO))
echo "System Information Collection: $(($ELAPSED_TIME_SYSTEMINFO/60)) min $(($ELAPSED_TIME_SYSTEMINFO%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

Aftermath_Collection_DeepScan() {

# Aftermath
# https://github.com/jamf/aftermath

# Note: Aftermath needs to be root, as well as have full disk access (FDA) in order to run. FDA can be granted to the Terminal application (or iTerm2) in which it is running.

# Check if Terminal application (or iTerm2) has full disk access (FDA)
# System Settings --> Privacy & Security --> Full Disk Access

# Stats
START_COLLECTION=$(/bin/date +%s)

# Verify File Integrity
if [[ -s $(/bin/ls -A "$AFTERMATH") ]]; then
	MD5=$(/sbin/md5 "$AFTERMATH" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	if [[ "$MD5" = "$FILEHASH" ]]; then

		# Check if Aftermath is executable
		if [[ ! -x "$AFTERMATH" ]]; then
			/bin/chmod +x "$AFTERMATH"
		fi

		# Check for Quarantine attribute
		if /usr/bin/xattr "$AFTERMATH" | /usr/bin/grep -q "com.apple.quarantine"; then
			/usr/bin/xattr -d com.apple.quarantine "$AFTERMATH"
		fi

		# Aftermath Version
		Version=$(/usr/bin/sudo "$AFTERMATH" --version)
		echo "[Info]  Aftermath Version: $Version"

		echo "[Info]  File Integrity: OK"
	else
		echo -e "\033[91m[ALERT] File Integrity: FAILURE\033[0m"
		exit 1
	fi
fi

# Aftermath Collection
/bin/mkdir -p "$OUTPUT"/Aftermath_Collection

# Default Collection + Deep Scan
echo "[Info]  Aftermath Collection w/ Deep Scan is running [approx. 3-20 min] ..."
/usr/bin/sudo "$AFTERMATH" -o "$OUTPUT"/Aftermath_Collection --deep --pretty > "$OUTPUT"/Aftermath_Collection/Aftermath-colored.txt 2> /dev/null

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/Aftermath_Collection | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Aftermath_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/Aftermath_Collection/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Aftermath Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Remove Aftermath folders from default locations ("/tmp", "/var/folders/zz/) 
echo "[Info]  Cleaning up ..."
/usr/bin/sudo "$AFTERMATH" --cleanup > "$OUTPUT"/Aftermath_Collection/Cleanup.txt 2> /dev/null

# Cleaning Aftermath Logfile
/bin/cat -v "$OUTPUT"/Aftermath_Collection/Aftermath-colored.txt | /usr/bin/sed -e 's/\^\[//g' | /usr/bin/sed -e 's/\[0;[0-9]*m//g' > "$OUTPUT"/Aftermath_Collection/Aftermath.txt

# Stats
END_COLLECTION=$(/bin/date +%s)
ELAPSED_TIME_COLLECTION=$(($END_COLLECTION - $START_COLLECTION))
echo "Aftermath Collection w/ Deep Scan: $(($ELAPSED_TIME_COLLECTION/60)) min $(($ELAPSED_TIME_COLLECTION%60)) sec" > "$OUTPUT"/Stats.txt

}

#############################################################

Aftermath_Analysis() {

# Aftermath
# https://github.com/jamf/aftermath

# Analysis date (ISO 8601)
echo -n "Analysis date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Stats
START_ANALYSIS=$(/bin/date +%s)

# Where is your previous collected Aftermath Archive stored?
read -e -p "Enter Aftermath Archive Path (Aftermath_<SERIAL_NUMBER>.zip): `echo $'\n> '`" ARCHIVE_FILE
echo ""

# Check if Aftermath Archive exists
if [[ -s $(/bin/ls -A "$ARCHIVE_FILE") ]]
then
	# Verify File Integrity
	if [[ -s $(/bin/ls -A "$AFTERMATH") ]]; then
		MD5=$(/sbin/md5 "$AFTERMATH" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		if [[ "$MD5" = "$FILEHASH" ]]; then

			# Check if Aftermath is executable
			if [[ ! -x "$AFTERMATH" ]]; then
				/bin/chmod +x "$AFTERMATH"
			fi

			# Check for Quarantine attribute
			if /usr/bin/xattr "$AFTERMATH" | /usr/bin/grep -q "com.apple.quarantine"; then
				/usr/bin/xattr -d com.apple.quarantine "$AFTERMATH"
			fi

			# Aftermath Version
			Version=$(/usr/bin/sudo "$AFTERMATH" --version)
			echo "[Info]  Aftermath Version: $Version"

			echo "[Info]  File Integrity: OK"
		else
			echo -e "\033[91m[ALERT] File Integrity: FAILURE\033[0m"
			exit 1
		fi
	fi

	# Analyze Aftermath Archive
	echo "[Info]  Analyzing Aftermath Archive [approx. 1-10 min] ..."
	/bin/mkdir -p "$OUTPUT"/Aftermath_Analysis/
	/usr/bin/sudo "$AFTERMATH" --analyze "$ARCHIVE_FILE" --pretty -o "$OUTPUT"/Aftermath_Analysis > "$OUTPUT"/Aftermath_Analysis/Aftermath-colored.txt 2> /dev/null

	# Archive Name
	ARCHIVE=$(/bin/ls -l "$OUTPUT"/Aftermath_Analysis | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Aftermath_Analysis_.*.zip$")
	echo "[Info]  Archive Name: $ARCHIVE"

	# Archive Size
	FILE="$OUTPUT/Aftermath_Analysis/$ARCHIVE"
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "[Info]  Archive Size: $FILESIZE"

	# MD5 Calculation
	if [[ -s $(/bin/ls -A "$FILE") ]]; then
		echo "[Info]  Calculating MD5 checksum of Aftermath Archive ..."
		MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		echo "[Info]  MD5 Hash: $MD5"
	fi

	# Create Time
	BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
	echo "[Info]  Create Time: $BIRTH UTC"

	# Last Modified Time
	MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
	echo "[Info]  Last Modified Time: $MODIFY UTC"
	
	# Cleaning Aftermath Logfile
	/bin/cat -v "$OUTPUT"/Aftermath_Analysis/Aftermath-colored.txt | /usr/bin/sed -e 's/\^\[//g' | /usr/bin/sed -e 's/\[0;[0-9]*m//g' > "$OUTPUT"/Aftermath_Analysis/Aftermath.txt
else
	echo "[Error] Aftermath Archive NOT found."
	exit 1
fi

# Stats
END_ANALYSIS=$(/bin/date +%s)
ELAPSED_TIME_ANALYSIS=$(($END_ANALYSIS - $START_ANALYSIS))
echo "Aftermath Analysis: $(($ELAPSED_TIME_ANALYSIS/60)) min $(($ELAPSED_TIME_ANALYSIS%60)) sec" >> "$OUTPUT"/Stats.txt
	
}

#############################################################
#############################################################

BTM_Dump() {

# Background Task Management (BTM)

# Stats
START_BTM=$(/bin/date +%s)

# Collecting BTM Dump File (via Shared File List Tool)
echo "[Info]  Collecting BTM Dump File ..."
/bin/mkdir -p "$OUTPUT/BTM"
/usr/bin/sudo /usr/bin/sfltool dumpbtm > "$OUTPUT/BTM/btm.txt"

# File Size
FILE="$OUTPUT/BTM/btm.txt"
if [[ -s "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.0f %s", $1, v[s] }')
	echo "[Info]  File Size (TXT): $FILESIZE ( $BYTES bytes )"
fi

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of BTM Dump File ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Count User IDs
COUNT=$(/bin/cat $FILE | /usr/bin/grep -c "Records for UID")
echo "[Info]  $COUNT User ID's found"

# Count Background Items (Item Records)
TOTAL=$(/bin/cat $FILE | /usr/bin/grep -E -c "^ #\d+:")
echo "[Info]  $TOTAL Background Item(s) found"

# Collecting BTM Database File(s)
/usr/bin/sudo /usr/bin/find "/private/var/db/com.apple.backgroundtaskmanagement" -name "BackgroundItems-v*.btm" -type f > "$OUTPUT/BTM/Files.txt" 2> /dev/null
if [[ -s "$OUTPUT/BTM/Files.txt" ]]; then
	echo "[Info]  Collecting BTM Database File(s) ..."
	/bin/mkdir -p "$OUTPUT/BTM/BTM_Data"
	/usr/bin/sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/BTM/Files.txt" / "$OUTPUT/BTM/BTM_Data" >> "$OUTPUT/BTM/Collection.txt" 2>&1
fi

# Creating read-only Disk Image (APFS)
SRCFOLDER="/private/var/db/com.apple.backgroundtaskmanagement"
if [[ -d "$SRCFOLDER" ]]; then
	if [[ -n "$( ls -A "$SRCFOLDER" )" ]]; then
		/usr/bin/hdiutil create -fs APFS -srcfolder "$SRCFOLDER" -volname "BTM_Data" -format UDRO "$OUTPUT/BTM/BTM_$SerialNumber.dmg" > /dev/null
	fi
fi

# Disk Info (DMG)
FILE="$OUTPUT/BTM/BTM_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "BTM_$SerialNumber.dmg ($FILESIZE)" > "$OUTPUT/BTM/DiskInfo.txt"
	echo "MD5: $(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/BTM/DiskInfo.txt"
	echo "SHA1: $(/usr/bin/openssl sha1 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/BTM/DiskInfo.txt"
	echo "SHA256: $(/usr/bin/openssl dgst -sha256 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/BTM/DiskInfo.txt"
fi

# Count BTM Database File(s)
COUNT=$(/bin/cat "$OUTPUT/BTM/Files.txt" | /usr/bin/grep -c ^)
echo "[Info]  $COUNT BTM Database File(s) found"

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/BTM/BTM_Data" ]]; then
	cd "$OUTPUT/BTM"
	/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "BTM_$SerialNumber.zip" BTM_Data
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/BTM" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^BTM_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/BTM/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of BTM Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/BTM/BTM_Data"
if [[ -d "$FOLDER" ]]; then
/bin/rm -rf "$FOLDER"
fi

# Stats
END_BTM=$(/bin/date +%s)
ELAPSED_TIME_BTM=$(($END_BTM - $START_BTM))
echo "BTM Dump File Collection: $(($ELAPSED_TIME_BTM/60)) min $(($ELAPSED_TIME_BTM%60)) sec" >> "$OUTPUT"/Stats.txt

}

# T1543.001 - Launch Agent
# T1543.004 - Launch Daemons

#############################################################
#############################################################

DS_Store() {

# Desktop Service Store Files (.DS_Store)

# Stats
START_DSStore=$(/bin/date +%s)

# System Integrity Protection (SIP)
if /usr/bin/csrutil status | /usr/bin/grep -q "System Integrity Protection status: enabled."; then
	echo "[Info]  System Integrity Protection (SIP) is enabled."
fi

# Desktop Service Store Files
/bin/mkdir -p "$OUTPUT/DS_Store/DSStore_Data"

# Find all .DS_Store Files in the root directory
echo "[Info]  Enumerating Desktop Service Store Files [approx. 1-2 min] ..."
/usr/bin/sudo /usr/bin/find / -name ".DS_Store" -type f > "$OUTPUT/DS_Store/Files.txt" 2> "$OUTPUT/DS_Store/Error.txt"

# Count Desktop Service Store Files w/ thousands separator
FILES=$(/bin/cat "$OUTPUT/DS_Store/Files.txt" | /usr/bin/grep -c ^)
COUNT=$(/usr/bin/printf "%'d\n" $FILES | /usr/bin/tr -s "," ".")
echo "[Info]  $COUNT DS_Store Files found"

# Copy and preserve Apple Extended Attributes w/ Rsync (Archive Mode)
echo "[Info]  Collecting Desktop Service Store Files ..."
if [[ -s "$OUTPUT/DS_Store/Files.txt" ]]; then
	/usr/bin/sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/DS_Store/Files.txt" / "$OUTPUT/DS_Store/DSStore_Data" >> "$OUTPUT/DS_Store/Collection.txt" 2>&1
fi

# Creating read-only Disk Image (APFS)
SRCFOLDER="$OUTPUT/DS_Store/DSStore_Data"
if [[ -d "$SRCFOLDER" ]]; then
	if [[ -n "$( ls -A "$SRCFOLDER" )" ]]; then
		/usr/bin/hdiutil create -fs APFS -srcfolder "$SRCFOLDER" -volname "DSStore_Data" -format UDRO "$OUTPUT/DS_Store/DSStore_$SerialNumber.dmg" > /dev/null
	fi
fi

# Disk Info (DMG)
FILE="$OUTPUT/DS_Store/DSStore_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "DSStore_$SerialNumber.dmg ($FILESIZE)" > "$OUTPUT/DS_Store/DiskInfo.txt"
	echo "MD5: $(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/DS_Store/DiskInfo.txt"
	echo "SHA1: $(/usr/bin/openssl sha1 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/DS_Store/DiskInfo.txt"
	echo "SHA256: $(/usr/bin/openssl dgst -sha256 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/DS_Store/DiskInfo.txt"
fi

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/DS_Store/DSStore_Data" ]]; then
	cd "$OUTPUT/DS_Store"
	/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "DSStore_$SerialNumber.zip" DSStore_Data
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/DS_Store" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^DSStore_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/DS_Store/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of DS_Store Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/DS_Store/DSStore_Data"
if [[ -d "$FOLDER" ]]; then
/bin/rm -rf "$FOLDER"
fi

# Stats
END_DSStore=$(/bin/date +%s)
ELAPSED_TIME_DSStore=$(($END_DSStore - $START_DSStore))
echo ".DS_Store Collection: $(($ELAPSED_TIME_DSStore/60)) min $(($ELAPSED_TIME_DSStore%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

FSEvents() {

# File System Events (FSEvents)

# Stats
START_FSEVENTS=$(/bin/date +%s)

# FSEvents
echo "[Info]  Collecting File System Events ..."
/bin/mkdir -p "$OUTPUT/FSEvents/FSEvents_Data"

# Count GZIP Files w/ thousands separator
Total=$(/usr/bin/sudo /usr/bin/find "/System/Volumes/Data/.fseventsd/" -type f ! -name 'fseventsd-uuid' | wc -l | awk '{ print $1 }')
Count=$(/usr/bin/printf "%'d\n" $Total | /usr/bin/tr -s "," ".")
echo "[Info]  $Count FSEvent Files found"

# Collecting FSEvents
SOURCE="/System/Volumes/Data/.fseventsd/"
DESTINATION="$OUTPUT/FSEvents/FSEvents_Data"
if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
	/usr/bin/sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" >> "$OUTPUT/FSEvents/Collection.txt"
fi

# Creating read-only Disk Image (APFS)
SRCFOLDER="$OUTPUT/FSEvents/FSEvents_Data"
if [[ -d "$SRCFOLDER" ]]; then
	if [[ -n "$( ls -A "$SRCFOLDER" )" ]]; then
		/usr/bin/hdiutil create -fs APFS -srcfolder "$SRCFOLDER" -volname "FSEvents_Data" -format UDRO "$OUTPUT/FSEvents/FSEvents_$SerialNumber.dmg" > /dev/null
	fi
fi

# Disk Info (DMG)
FILE="$OUTPUT/FSEvents/FSEvents_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "FSEvents_$SerialNumber.dmg ($FILESIZE)" > "$OUTPUT/FSEvents/DiskInfo.txt"
	echo "MD5: $(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/FSEvents/DiskInfo.txt"
	echo "SHA1: $(/usr/bin/openssl sha1 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/FSEvents/DiskInfo.txt"
	echo "SHA256: $(/usr/bin/openssl dgst -sha256 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/FSEvents/DiskInfo.txt"
fi

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/FSEvents/FSEvents_Data" ]]; then
	cd "$OUTPUT/FSEvents"
	/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "FSEvents_$SerialNumber.zip" FSEvents_Data
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/FSEvents | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^FSEvents_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/FSEvents/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of FSEvents Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/FSEvents/FSEvents_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# Stats
END_FSEVENTS=$(/bin/date +%s)
ELAPSED_TIME_FSEVENTS=$(($END_FSEVENTS - $START_FSEVENTS))
echo "FSEvents Collection: $(($ELAPSED_TIME_FSEVENTS/60)) min $(($ELAPSED_TIME_FSEVENTS%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

UnifiedLogs() {

# Apple Unified Logs (AUL)

# Stats
START_AUL=$(/bin/date +%s)

# Gather system logs into a log archive (.logarchive)
echo "[Info]  Collecting Unified Logs (.logarchive) ..."
/bin/mkdir -p "$OUTPUT/UnifiedLogs/"
LOGARCHIVE="$OUTPUT/UnifiedLogs/system_logs.logarchive"
/usr/bin/sudo /usr/bin/log collect --output "$LOGARCHIVE" > /dev/null 2>&1

# Creating Archive File
if [[ -d "$LOGARCHIVE" ]]; then
	echo "[Info]  Compressing Unified Logs (.zip) ..."
	cd "$OUTPUT/UnifiedLogs"
	/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "UnifiedLogs_$SerialNumber.zip" system_logs.logarchive
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/UnifiedLogs | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^UnifiedLogs_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/UnifiedLogs/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Unified Logs Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Show System Logging Statistics
if [[ -d "$LOGARCHIVE" ]]; then
	echo "[Info]  Creating System Logging Statistics ..."
	/usr/bin/sudo /usr/bin/log stats --archive "$LOGARCHIVE" > "$OUTPUT"/UnifiedLogs/Statistics.txt
fi

# Cleaning up
if [[ -d "$LOGARCHIVE" ]]; then
	/bin/rm -r "$LOGARCHIVE"
fi

# Stats
END_AUL=$(/bin/date +%s)
ELAPSED_TIME_AUL=$(($END_AUL - $START_AUL))
echo "Unified Logs Collection: $(($ELAPSED_TIME_AUL/60)) min $(($ELAPSED_TIME_AUL%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

Sysdiagnose() {

# Sysdiagnose Logs Generation

# Stats
START_SYSDIAGNOSE=$(/bin/date +%s)

# Collecting Sysdiagnose Logs (System Diagnostic Information)
echo "[Info]  Collecting Sysdiagnose Logs [approx. 1-5 min] ..."
/bin/mkdir -p "$OUTPUT/Sysdiagnose/Sysdiagnose_Data"
/usr/bin/sudo /usr/bin/sysdiagnose -f "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" -nbSu > "$OUTPUT/Sysdiagnose/Sysdiagnose.txt" 2>&1

# -f   results_directory
# -n   Do not tar the resulting sysdiagnose directory.
# -b   Do not show a Finder window upon completion.
# -S   Disable streaming to tarball.
# -u   Disable UI feedback.

# Creating Archive File
if [[ -d "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" )" ]]; then
		echo "[Info]  Compressing Sysdiagnose Logs (.zip) ..."
		cd "$OUTPUT/Sysdiagnose"
		/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "Sysdiagnose_$SerialNumber.zip" Sysdiagnose_Data
		cd "$SCRIPT_DIR"
	else
		echo "Sysdiagnose_Data is empty."
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/Sysdiagnose" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Sysdiagnose_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/Sysdiagnose/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Sysdiagnose Logs Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
if [[ -d "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" ]]; then
	/bin/rm -r "$OUTPUT/Sysdiagnose/Sysdiagnose_Data"
fi

# Stats
END_SYSDIAGNOSE=$(/bin/date +%s)
ELAPSED_TIME_SYSDIAGNOSE=$(($END_SYSDIAGNOSE - $START_SYSDIAGNOSE))
echo "Sysdiagnose Logs Collection: $(($ELAPSED_TIME_SYSDIAGNOSE/60)) min $(($ELAPSED_TIME_SYSDIAGNOSE%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

KnockKnock() {

# Who's there? See what's persistently installed on your Mac. Like AutoRuns ...but for macOS!

# KnockKnock tells you who's there, querying your system for any software that leverages many of the myriad of persistence mechanisms (Persistence Enumerator).

# https://attack.mitre.org/tactics/TA0003/

# Stats
START_KNOCK=$(/bin/date +%s)

# Verify File Integrity
ExpectedTeamID="VBG97UB4TA" # Objective-See, LLC (VBG97UB4TA)
Application="$KNOCKKNOCK"
if [[ -d "$Application" ]]; then

	TeamID=$(/usr/sbin/spctl --assess --type execute -vv "$Application" 2>&1 | awk '/origin=/ {print $NF }' | /usr/bin/tr -d '()')

	if [[ "$TeamID" = "$ExpectedTeamID" ]]; then

		# Check if KnockKnock.app is executable
		if [[ ! -x "$Application" ]]; then
			/bin/chmod +x "$Application"
		fi

		# Check for Quarantine attribute
		if /usr/bin/xattr "$Application" | /usr/bin/grep -q "com.apple.quarantine"; then
			/usr/bin/xattr -dr com.apple.quarantine "$Application"
		fi

		# KnockKnock Version
		FILE="$KNOCKKNOCK/Contents/MacOS/KnockKnock"
		if [[ -f "$FILE" ]]; then
			VERSION=$(/usr/bin/sudo "$FILE" -version | /usr/bin/sed -e 's/KnockKnock Version: //g')
			echo "[Info]  KnockKnock Version: $VERSION"
			echo "[Info]  File Integrity: OK"
		fi
	else
		echo -e "\033[91m[ALERT] File Integrity: FAILURE\033[0m"
		exit 1
	fi
else
	echo "[Error] KnockKnock.app NOT found."
	exit 1
fi

# KnockKnock
FILE="$KNOCKKNOCK/Contents/MacOS/KnockKnock"
if [[ -f "$FILE" ]]; then
	echo "[Info]  Scanning Live System w/ KnockKnock ..."
	/bin/mkdir -p "$OUTPUT/KnockKnock/KnockKnock_Data"
	cd "$SCRIPT_DIR/tools/KnockKnock/"
	DATE=$(/bin/date -u +"%Y-%m-%d")

	# Check if VirusTotal API Key exists
	if [[ $VIRUSTOTAL == "YOUR_API_KEY" ]]; then

		# Launch KnockKnock /wo VirusTotal
		/usr/bin/sudo ./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere -verbose > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-draft.json"

	else

		# Check if virustotal.com is reachable
		/sbin/ping -c 1 -W 5 virustotal.com > /dev/null 2>&1
		if ! [[ $? -eq 0 ]]; then
			echo "[Error] virustotal.com is NOT reachable!"
			echo "" && exit 1
		fi

		# Launch KnockKnock /w VirusTotal
		echo "[Info]  Scanning Live System w/ KnockKnock [approx. 1-2 min] ..."
		/usr/bin/sudo ./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere -verbose -key "$VIRUSTOTAL" > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-draft.json"
	fi

	cd $SCRIPT_DIR

else
	echo "[Error] KnockKnock NOT found."
fi

# Output
if [[ -s "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-draft.json" ]]; then

	# JSON
	/bin/cat "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-draft.json" | /usr/bin/tail -n 1 > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE.json"

	# TXT
	/bin/cat "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-draft.json" | /usr/bin/sed '$d' > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock.txt"
fi

# File Size
FILE="$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE.json"
if [[ -s "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.0f %s", $1, v[s] }')
	echo "[Info]  File Size (JSON): $FILESIZE ( $BYTES bytes )"
fi

# Results
FILE="$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock.txt"
if [[ -s "$FILE" ]]; then
	if /bin/cat "$FILE" | /usr/bin/grep -q "RESULTS:"; then
		COUNT=$(/bin/cat "$FILE" | /usr/bin/grep "persistent items" | /usr/bin/awk '{ print $1 }')
		echo "[Info]  $COUNT Persistent Item(s) found"
		if /bin/cat "$FILE" | /usr/bin/grep -q "(VT) flagged items"; then
			DETECTIONS=$(/bin/cat "$FILE" | /usr/bin/grep "(VT) flagged items" | /usr/bin/awk '{ print $1 }')
			if [[ ! $DETECTIONS = 0 ]]; then
				echo -e "\033[91m[ALERT] $DETECTIONS (VT) flagged items\033[0m"
			else
				echo -e "\033[32m[Info]  $DETECTIONS (VT) flagged items\033[0m"
			fi
		fi
	else
		echo "[Error] No Results found."
	fi
fi

# Creating Archive File
if [[ -d "$OUTPUT/KnockKnock/KnockKnock_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/KnockKnock/KnockKnock_Data" )" ]]; then
		echo "[Info]  Compressing KnockKnock Results (.zip) ..."
		cd "$OUTPUT/KnockKnock"
		/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "KnockKnock_$SerialNumber.zip" KnockKnock_Data
		cd "$SCRIPT_DIR"
	else
		echo "KnockKnock_Data is empty."
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/KnockKnock" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^KnockKnock_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/KnockKnock/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of KnockKnock Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
if [[ -d "$OUTPUT/KnockKnock/KnockKnock_Data" ]]; then
	/bin/rm -r "$OUTPUT/KnockKnock/KnockKnock_Data"
fi

# Stats
END_KNOCK=$(/bin/date +%s)
ELAPSED_TIME_KNOCK=$(($END_KNOCK - $START_KNOCK))
echo "KnockKnock Scan: $(($ELAPSED_TIME_KNOCK/60)) min $(($ELAPSED_TIME_KNOCK%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

Spotlight() {

# Spotlight Database (Desktop Search Engine)

# Spotlight indexes the system to allow the user to search for files quickly. Indexing includes file metadata, extended attributes, and content of some file types.

# The Spotlight-V100 directory is located in the root of the volume contains the Spotlight store (.store.db and store.db). Its presence indicates that the volume has been indexed. 

# Stats
START_SPOTLIGHT=$(/bin/date +%s)

# Collecting Volume Configuration (VolumeConfiguration.plist --> contains indexing exclusions and other Spotlight configuration data)
FILE="/System/Volumes/Data/.Spotlight-V100/VolumeConfiguration.plist"
if [[ -f "$FILE" ]]; then
	
	# Volume Configuration (Data Volume)
	/bin/mkdir -p "$OUTPUT/Spotlight"
	/usr/bin/sudo /usr/bin/defaults read "$FILE" > "$OUTPUT/Spotlight/VolumeConfiguration.txt"

	# Universal Unique Identifier (Data Volume)
	UUID=$(/usr/bin/sudo /usr/bin/defaults read "$FILE" ConfigurationVolumeUUID)
	echo "[Info]  Data Volume: $UUID"
fi

# Spotlight Indexing Status (Data Volume)
Status=$(/usr/bin/mdutil -s -v "/System/Volumes/Data")
echo "$Status" > "$OUTPUT/Spotlight/Status.txt"
if echo "$Status" | /usr/bin/grep -q "Indexing enabled."; then
	echo "[Info]  Spotlight Indexing: Enabled"
else
	echo -e "\033[91m[ALERT] Spotlight Indexing: Disabled\033[0m"
fi

# Collecting Spotlight Configuration Files (com.apple.Spotlight.plist --> contains user-specific settings and preferences for the Spotlight search feature)
UserList=$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 >= 500 { print $1; }')
for User in $UserList; do
	/usr/bin/defaults read "/Users/$User/Library/Preferences/com.apple.Spotlight.plist" > "$OUTPUT/Spotlight/UserConfiguration_$User.txt"
done

# Collecting Spotlight Database (.Spotlight-V100 Directory on Data Volume --> contains Spotlight index database file(s) and database dependencies)
echo "[Info]  Collecting Spotlight Database [approx. 1-3 min] ..."
/bin/mkdir -p "$OUTPUT/Spotlight/Spotlight_Data"
SOURCE="/System/Volumes/Data/.Spotlight-V100/"
DESTINATION="$OUTPUT/Spotlight/Spotlight_Data"
if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
	/usr/bin/sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" >> "$OUTPUT/Spotlight/LogFile.txt"
fi

# Creating read-only Disk Image (APFS)
SRCFOLDER="/System/Volumes/Data/.Spotlight-V100/"
if [[ -d "$SRCFOLDER" ]]; then
	/usr/bin/hdiutil create -fs APFS -srcfolder "$SRCFOLDER" -volname "Spotlight_Data" -format UDRO "$OUTPUT/Spotlight/Spotlight_$SerialNumber.dmg" > /dev/null
fi

# Disk Info (DMG) --> You can open these files in macOS only.
# Note: It seems that specific system files stored in the .Spotlight-V100 directory are compressed and not supported by the "APFS for Windows" driver by Paragon Software.
FILE="$OUTPUT/Spotlight/Spotlight_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "Spotlight_$SerialNumber.dmg ($FILESIZE)" > "$OUTPUT/Spotlight/DiskInfo.txt"
	echo "MD5: $(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/Spotlight/DiskInfo.txt"
	echo "SHA1: $(/usr/bin/openssl sha1 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/Spotlight/DiskInfo.txt"
	echo "SHA256: $(/usr/bin/openssl dgst -sha256 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/Spotlight/DiskInfo.txt"
fi

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/Spotlight/Spotlight_Data" ]]; then
	if [[ -n "$( /bin/ls -A "$OUTPUT/Spotlight/Spotlight_Data" )" ]]; then
		echo "[Info]  Compressing Spotlight Database (.zip) ..."
		cd "$OUTPUT/Spotlight"
		/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "Spotlight_$SerialNumber.zip" Spotlight_Data
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/Spotlight | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Spotlight_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/Spotlight/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Spotlight Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/Spotlight/Spotlight_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# Spotlight Live Searches (Apple Extended Metadata)
echo "[Info]  Performing Native Spotlight Searches ..."
/bin/mkdir -p "$OUTPUT/Spotlight/Searches"

# MDItemWhereFroms
# Describes where the item was obtained from. For example, a downloaded file may refer to the URL, files received by email may indicate the sender’s email address, message subject, etc.
/usr/bin/sudo /usr/bin/mdfind -onlyin / -name "kMDItemWhereFroms == *" > "$OUTPUT/Spotlight/Searches/kMDItemWhereFroms.txt"

# Count files with 'kMDItemWhereFroms' attribute
FILE="$OUTPUT/Spotlight/Searches/kMDItemWhereFroms.txt"
if [[ -s "$FILE" ]]; then
	LINES=$(/bin/cat "$FILE" | /usr/bin/grep -c ^)
	COUNT=$(/usr/bin/printf "%'d\n" $LINES | /usr/bin/tr -s "," ".")
	echo "[Info]  $COUNT Downloaded File(s) found (kMDItemWhereFroms)" # Downloaded from the Internet or transferred from an external source
fi

# Creating CSV Report(s)
OUTPUT_FOLDER="$OUTPUT/Spotlight/Searches/CSV"

echo "[Info]  Creating CSV Report(s) ..."
/bin/mkdir -p "$OUTPUT_FOLDER"

# MDItemWhereFroms

# Header
echo "\"kMDItemDateAdded\",\"FilePath\",\"FileName\",\"kMDItemKind\",\"MD5\",\"SHA1\",\"SHA256\",\"kMDItemWhereFroms\",\"_kMDItemOwnerUserID\",\"UserName\",\"kMDItemLastUsedDate\",\"kMDItemUseCount\",\"QuarantineFlag\",\"QuarantineTimestamp\",\"Origin\",\"FileIdentifier\"" > "$OUTPUT_FOLDER/kMDItemWhereFroms.csv"

# Data
while read FILEPATH
do
	kMDItemDateAdded=$(/usr/bin/mdls -name kMDItemDateAdded "$FILEPATH" | /usr/bin/sed -e 's/.*= //g')
	FileName=$(/usr/bin/basename "$FILEPATH")
	kMDItemKind=$(/usr/bin/mdls -name kMDItemKind "$FILEPATH" | /usr/bin/grep -o '"[^"]\+"' | /usr/bin/tr -d '"')
	MD5=$(/sbin/md5 "$FILEPATH" | /usr/bin/sed -e 's/.*= //g')
	SHA1=$(/usr/bin/openssl sha1 "$FILEPATH" | /usr/bin/sed -e 's/.*= //g')
	SHA256=$(/usr/bin/openssl dgst -sha256 "$FILEPATH" | /usr/bin/sed -e 's/.*= //g')
	kMDItemWhereFroms=$(/usr/bin/mdls -name kMDItemWhereFroms "$FILEPATH" | /usr/bin/grep -o '"[^"]\+"' | /usr/bin/tr -d '"' | uniq)
	_kMDItemOwnerUserID=$(/usr/bin/mdls -name _kMDItemOwnerUserID "$FILEPATH" | /usr/bin/sed -e 's/.*= //g')
	UserName=$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/grep  "$_kMDItemOwnerUserID" | /usr/bin/awk  '{ print $1 }')
	kMDItemLastUsedDate=$(/usr/bin/mdls -name kMDItemLastUsedDate "$FILEPATH" | /usr/bin/sed -e 's/.*= //g' | sed 's/(null)//g')
	kMDItemUseCount=$(/usr/bin/mdls -name kMDItemUseCount "$FILEPATH" | /usr/bin/sed -e 's/.*= //g' | sed 's/(null)//g')
	Quarantine=$(/usr/bin/xattr -p com.apple.quarantine "$FILEPATH" 2> /dev/null)
	QuarantineFlag=$(echo $Quarantine | /usr/bin/awk -F";" '{ print $1 }')
	if [[ ! -z "$Quarantine" ]]; then
		Timestamp=$(echo $Quarantine | /usr/bin/awk -F";" '{ print $2 }')
		EpochTimestamp=$(echo $((0x$Timestamp)))
		QuarantineTimestamp=$(date -r $EpochTimestamp '+%F %H:%M:%S')
	fi
	Origin=$(echo $Quarantine | /usr/bin/awk -F";" '{ print $3 }')
	FileIdentifier=$(echo $Quarantine | /usr/bin/awk -F";" '{ print $4 }')
	echo \"$kMDItemDateAdded\",\"$FileName\",\"$FILEPATH\",\"$kMDItemKind\",\"$MD5\",\"$SHA1\",\"$SHA256\",\"$kMDItemWhereFroms\",\"$_kMDItemOwnerUserID\",\"$UserName\",\"$kMDItemLastUsedDate\",\"$kMDItemUseCount\",\"$QuarantineFlag\",\"$QuarantineTimestamp\",\"$Origin\",\"$FileIdentifier\" >> "$OUTPUT_FOLDER/kMDItemWhereFroms.csv"
done < "$OUTPUT/Spotlight/Searches/kMDItemWhereFroms.txt"

# Stats
END_SPOTLIGHT=$(/bin/date +%s)
ELAPSED_TIME_SPOTLIGHT=$(($END_SPOTLIGHT - $START_SPOTLIGHT))
echo "Spotlight Database Collection: $(($ELAPSED_TIME_SPOTLIGHT/60)) min $(($ELAPSED_TIME_SPOTLIGHT%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

RecentItems() {

# Stats
START_RECENT=$(/bin/date +%s)

# Recent Items aka Most Recently Used Files (MRU)
# Recent documents, applications, and servers (Default: 10)
echo "[Info]  Collecting Recent Items (MRU) ..."
/bin/mkdir -p "$OUTPUT/RecentItems/Finder"
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	# Finder Preferences
	FILE="/Users/$UserName/Library/Preferences/com.apple.finder.plist"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/RecentItems/Finder/com.apple.finder_$UserName.plist"
		/usr/bin/plutil -p "$FILE" > "$OUTPUT/RecentItems/Finder/com.apple.finder_$UserName.txt"
	fi

	# Keys of Interest:
	# RecentMoveAndCopyDestinations
	# GoToFieldHistory
	# FXRecentFolders
	# RecentSearches
	# FXDesktopVolumePositions

	# Collecting Shared File Lists (SFL)
	/bin/mkdir -p "$OUTPUT/RecentItems/RecentItems_Data/$UserName/"
	SOURCE="/Users/$UserName/Library/Application Support/com.apple.sharedfilelist"
	DESTINATION="$OUTPUT/RecentItems/RecentItems_Data/$UserName"
	if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
		/usr/bin/sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" > /dev/null
	fi
done

# Creating read-only Disk Image (APFS)
SRCFOLDER="$OUTPUT/RecentItems/RecentItems_Data"
DMG="$OUTPUT/RecentItems/RecentItems_$SerialNumber.dmg"
if [[ -d "$SRCFOLDER" ]]; then
	if [[ -n "$( ls -A "$SRCFOLDER" )" ]]; then
		/usr/bin/hdiutil create -fs APFS -srcfolder "$SRCFOLDER" -volname "RecentItems" -format UDRO "$DMG" > /dev/null
	fi
fi

# Disk Info (DMG)
FILE="$OUTPUT/RecentItems/RecentItems_Data/RecentItems_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "RecentItems_$SerialNumber.dmg ($FILESIZE)" > "$OUTPUT/RecentItems/DiskInfo.txt"
	echo "MD5: $(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/RecentItems/DiskInfo.txt"
	echo "SHA1: $(/usr/bin/openssl sha1 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/RecentItems/DiskInfo.txt"
	echo "SHA256: $(/usr/bin/openssl dgst -sha256 "$FILE" | /usr/bin/awk '{ print $2 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')" >> "$OUTPUT/RecentItems/DiskInfo.txt"
fi

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/RecentItems/RecentItems_Data" ]]; then
	if [[ -n "$( /bin/ls -A "$OUTPUT/RecentItems/RecentItems_Data" )" ]]; then
		echo "[Info]  Compressing Recents Items (.zip) ..."
		cd "$OUTPUT/RecentItems"
		/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "RecentItems_$SerialNumber.zip" RecentItems_Data
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/RecentItems" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^RecentItems_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/RecentItems/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of RecentItems Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/RecentItems/RecentItems_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# Stats
END_RECENT=$(/bin/date +%s)
ELAPSED_TIME_RECENT=$(($END_RECENT - $START_RECENT))
echo "Recent Items Collection: $(($ELAPSED_TIME_RECENT/60)) min $(($ELAPSED_TIME_RECENT%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

TrueTree() {

# Stats
START_TRUETREE=$(/bin/date +%s)

# Verify File Integrity
ExpectedTeamID="C793NB2B2B" # Jaron Bradley (C793NB2B2B)
if [[ -f "$TRUETREE" ]]; then

	TeamID=$(/usr/sbin/spctl --assess --type execute -vv "$TRUETREE" 2>&1 | awk '/origin=/ {print $NF }' | /usr/bin/tr -d '()')

	if [[ "$TeamID" = "$ExpectedTeamID" ]]; then

		# Check if TrueTree is executable
		if [[ ! -x "$TRUETREE" ]]; then
			/bin/chmod +x "$TRUETREE"
		fi

		# Check for Quarantine attribute
		if /usr/bin/xattr "$TRUETREE" | /usr/bin/grep -q "com.apple.quarantine"; then
			/usr/bin/xattr -d com.apple.quarantine "$TRUETREE"
		fi

		# TrueTree Version Number
		/bin/mkdir -p "$OUTPUT/TrueTree/TrueTree_Data"
		VERSION=$(/usr/bin/sudo "$TRUETREE" --version)
		echo "$VERSION" > "$OUTPUT/TrueTree/TrueTree_Data/Version.txt"
		echo "[Info]  TrueTree v$VERSION"
		echo "[Info]  File Integrity: OK"
	else
		echo -e "\033[91m[ALERT] File Integrity: FAILURE\033[0m"
		exit 1
	fi
else
	echo "[Error] TrueTree NOT found."
	exit 1
fi

# TrueTree
if [[ -f "$TRUETREE" ]]; then
	echo "[Info]  Collecting Snapshot of Running Processes w/ TrueTree ..."
	/bin/mkdir -p "$OUTPUT/TrueTree/TrueTree_Data/Colored"

	# Timeline (Non-Tree Mode)
	# Note: Does not collect a tree. Instead just prints processes sorted by creation time
	/usr/bin/sudo "$TRUETREE" --timeline > "$OUTPUT/TrueTree/TrueTree_Data/TrueTree-Timeline.txt" 2> /dev/null

	# Timestamps (including process timestamps)
	# Note: For output in either format with process create time added use the --timestamps option
	/usr/bin/sudo "$TRUETREE" --timestamps --nocolor -o "$OUTPUT/TrueTree/TrueTree_Data/TrueTree-with-Timestamps.txt" > /dev/null 2>&1
	/usr/bin/sudo "$TRUETREE" --timestamps -o "$OUTPUT/TrueTree/TrueTree_Data/Colored/TrueTree-with-Timestamps-colored.txt" > /dev/null 2>&1

	# Standard - Print the standard Unix tree instead of TrueTree
	# Note: For tree output based on standard pids and ppids use --standard
	/usr/bin/sudo "$TRUETREE" --standard --nocolor -o "$OUTPUT/TrueTree/TrueTree_Data/StandardTree.txt" > /dev/null 2>&1
	/usr/bin/sudo "$TRUETREE" --standard -o "$OUTPUT/TrueTree/TrueTree_Data/Colored/StandardTree-colored.txt" > /dev/null 2>&1

	# TrueTree (Default)
	# Note: Displays an enhanced process tree using the TrueTree concept
	/usr/bin/sudo "$TRUETREE" --nocolor -o "$OUTPUT/TrueTree/TrueTree_Data/TrueTree.txt" > /dev/null 2>&1
	/usr/bin/sudo "$TRUETREE" -o "$OUTPUT/TrueTree/TrueTree_Data/Colored/TrueTree-colored.txt" > /dev/null 2>&1

	# TrueTree (including sources of where each process parent came from)
	# Note: To show where each parent pid was aquired from use the --sources option
	/usr/bin/sudo "$TRUETREE" --sources --nocolor -o "$OUTPUT/TrueTree/TrueTree_Data/TrueTree-Sources.txt" > /dev/null 2>&1
	/usr/bin/sudo "$TRUETREE" --sources -o "$OUTPUT/TrueTree/TrueTree_Data/Colored/TrueTree-Sources-colored.txt" > /dev/null 2>&1
fi

# Creating Archive File (ZIP)
if [[ -d "$OUTPUT/TrueTree/TrueTree_Data" ]]; then
	if [[ -n "$( /bin/ls -A "$OUTPUT/TrueTree/TrueTree_Data" )" ]]; then
		echo "[Info]  Compressing TrueTree Database (.zip) ..."
		cd "$OUTPUT/TrueTree"
		/usr/bin/zip -q -e -r -P "$ARCHIVE_PASSWORD" "TrueTree_$SerialNumber.zip" TrueTree_Data
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/TrueTree" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^TrueTree_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/TrueTree/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of TrueTree Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Cleaning up
FOLDER="$OUTPUT/TrueTree/TrueTree_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# Stats
END_TRUETREE=$(/bin/date +%s)
ELAPSED_TIME_TRUETREE=$(($END_TRUETREE - $START_TRUETREE))
echo "TrueTree Snapshot Collection: $(($ELAPSED_TIME_TRUETREE/60)) min $(($ELAPSED_TIME_TRUETREE%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

Footer() {

echo ""
echo "FINISHED!"

# Time Duration
ELAPSED_TIME=$(($SECONDS - $START_TIME))
echo "Overall analysis duration: $(($ELAPSED_TIME/60)) min $(($ELAPSED_TIME%60)) sec"

# screenlog.txt
/bin/cp "$SCRIPT_DIR"/screenlog-draft.txt "$OUTPUT"/
/bin/cat "$OUTPUT"/screenlog-draft.txt > "$OUTPUT"/screenlog-colored.txt
/bin/cat "$OUTPUT"/screenlog-draft.txt | /usr/bin/sed -e $'s/\x1b//g' | /usr/bin/sed -e $'s/\x07//g' | /usr/bin/sed -e 's/\[3J//g' | /usr/bin/sed -e 's/\[H//g' | /usr/bin/sed -e 's/\[2J//g' | /usr/bin/sed -e 's/\[91m//g' | /usr/bin/sed -e 's/\[0m//g' | /usr/bin/sed -e 's/\[?1034h//g' > "$OUTPUT"/screenlog.txt 2> /dev/null
/bin/rm "$SCRIPT_DIR"/screenlog-draft.txt
/bin/rm "$OUTPUT"/screenlog-draft.txt

# Change permissions of output files
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
/usr/bin/sudo /usr/sbin/chown -R $LoggedInUser "$SCRIPT_DIR/output/"

}

#############################################################
#############################################################

# Main

case "${1}" in
	-a|--analyze)
	{
	Header
	Check_Admin
	Output
	Aftermath_Analysis
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-b|--btm)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	BTM_Dump
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-c|--collect)
	{
	Header
	Check_Admin
	Check_FDA
	Output
	BasicInfo
	Aftermath_Collection_DeepScan
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-d|--ds_store)
	{
	Header
	Check_Admin
	Check_FDA
	Output
	BasicInfo
	DS_Store
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-f|--fsevents)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	FSEvents
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-i|--info)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	SystemInfo
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-k|--knockknock)
	{
	Header
	Check_Admin
	Check_FDA
	Output
	BasicInfo
	KnockKnock
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-l|--logs)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	UnifiedLogs
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-m|--metadata)
	{
	Header
	Check_Admin
	Check_FDA
	Output
	BasicInfo
	Spotlight
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-p|--processes)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	TrueTree
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-r|--recentitems)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	RecentItems
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-s|--sysdiagnose)
	{
	Header
	Check_Admin
	Output
	BasicInfo
	Sysdiagnose
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-t|--triage)
	{
	Header
	Check_Admin
	Check_FDA
	Output
	BasicInfo
	SystemInfo
	Aftermath_Collection_DeepScan
	DS_Store
	FSEvents
	KnockKnock
	UnifiedLogs
	RecentItems
	Sysdiagnose
	Spotlight
	TrueTree
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-h|--help|\?)
	Usage
	;;
	"")
	Header
	echo "[Error] You must specify something to do (try -h)"
	echo ""
	;;
	*)
	Header
	echo "[Error] No such option: $1"
	echo ""
	Usage2
	;;
esac
exit 0

#############################################################
#############################################################