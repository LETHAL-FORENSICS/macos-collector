#!/bin/bash
#
# macOS-Collector
#
# @author:      Martin Willing
# @copyright:   Copyright (c) 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:     Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:         https://lethal-forensics.com/
# @date:        2026-04-11
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
# 7-Zip v26.00 Console Version (2026-02-12)
# https://www.7-zip.org/download.html
#
# Aftermath v2.3.0 (2025-09-24)
# https://github.com/jamf/aftermath
#
# KnockKnock v4.0.3 (2025-12-18)
# https://objective-see.com/products/knockknock.html
#
# TrueTree v0.8 (2024-08-23)
# https://github.com/themittenmac/TrueTree
#
#
# Tested on macOS Tahoe 26.4
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

# 7-Zip
SEVENZIP="$SCRIPT_DIR/tools/7-Zip/7zz"
MD5_7ZZ="DCACF43BE9AC2034815CFEA7E8C89803"

# Aftermath
AFTERMATH="$SCRIPT_DIR/tools/Aftermath/aftermath"
MD5_AFTERMATH="A0668EB91650513F40CE8753A277E0E0"

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
echo "-n / --notifications   Collect Notification Center Database Files"
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

Verify_7zz() {

	# Verify File Integrity
	if [[ -f "$SEVENZIP" ]]; then

		MD5=$(/sbin/md5 "$SEVENZIP" | /usr/bin/sed -e 's/.*= //g' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		if [[ "$MD5" = "$MD5_7ZZ" ]]; then

			# Check if 7zz is executable
			if [[ ! -x "$SEVENZIP" ]]; then
				/bin/chmod +x "$SEVENZIP"
			fi

			# Check for Quarantine attribute
			if /usr/bin/xattr "$SEVENZIP" | /usr/bin/grep -q "com.apple.quarantine"; then
				/usr/bin/xattr -d com.apple.quarantine "$SEVENZIP"
			fi
		else
			echo -e "\033[91m[ALERT] File Integrity (7zz): FAILURE\033[0m"
			echo ""
			exit 1
		fi
	else
		echo "[Error] '7zz' NOT found."
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

# XProtect (Primary Location)
FILE="/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist" # macOS Sequoia (2024)
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	RULES=$(/bin/cat "/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	OSASCRIPT=$(/bin/cat "/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/XPScripts.yr" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($RULES YARA rules, $OSASCRIPT OSASCRIPT rules)"
fi

# XProtect (Secondary Location)
FILE="/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist" # macOS Sequoia (2024)
if [[ ! -f "$FILE" ]]; then	
	FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
	if [[ -f "$FILE" ]]; then
		VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
		RULES=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
		OSASCRIPT=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XPScripts.yr" | /usr/bin/grep -c "^rule")
		echo "[Info]  XProtect Version: $VERSION ($RULES YARA rules, $OSASCRIPT OSASCRIPT rules)"
	fi
fi

# XProtect Remediator (XPR)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	echo "[Info]  XProtect Remediator Version: $VERSION"
fi

# Malware Removal Tool (MRT)
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"
if [[ -f "$FILE" ]]; then
	# Command Line Tools for Xcode
	if /usr/sbin/pkgutil --pkgs=com.apple.pkg.CLTools_Executables > /dev/null; then
		VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
		COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.") # string requires the command line developer tools
		echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
	else
		VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
		echo "[Info]  MRT Version: $VERSION"
	fi
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

# System Profiler
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler"

# Available Datatypes
DATATYPES=$(/usr/sbin/system_profiler -listDataTypes)
COUNT=$(echo "$DATATYPES" | /usr/bin/grep -c ^)
echo "$DATATYPES" > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler/DataTypes.txt"
echo "$COUNT" > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler/DataTypes_Count.txt"

# Basic Report
/usr/sbin/system_profiler -detailLevel basic > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler/Basic-Report.txt" 2> /dev/null

# Full Report
#/usr/sbin/system_profiler -detailLevel full > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler/Full-Report.txt" 2> /dev/null
#/usr/sbin/system_profiler -detailLevel full -json > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler/Full-Report.json" 2> /dev/null
/usr/sbin/system_profiler -detailLevel full -xml > "$OUTPUT/SystemInfo/SystemInfo_Data/SystemProfiler/SystemInformation.spx" 2> /dev/null # System Information App (macOS)

# System Integrity Protection (SIP)
# System Integrity Protection (SIP) is used to limit the capability to change important system files. This is part of the security of the system.
# Note: Protected can be identified by looking for the com.apple.rootless extended attribute on a file or directory (xattr -l /System).
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP"
SIP=$(/usr/bin/csrutil status)

if [[ $SIP = "System Integrity Protection status: enabled." ]]; then
	echo "[Info]  System Integrity Protection (SIP) is on." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP/SIP_Status.txt"
elif [[ $SIP = "System Integrity Protection status: disabled." ]]; then	
	echo "[Info]  System Integrity Protection (SIP) is off." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP/SIP_Status.txt"
	echo -e "\033[91m[ALERT] System Integrity Protection (SIP) is OFF.\033[0m"
else
	echo "$SIP" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/SIP/SIP_Status.txt"
fi

# OS Information
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/OS"

# System Version
FILE="/System/Library/CoreServices/SystemVersion.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/OS/SystemVersion.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/SystemVersion.txt"
fi

# Gatekeeper Status (System Policy Control)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper"
GKStatus=$(/usr/sbin/spctl --status)

if [[ $GKStatus = "assessments enabled" ]]; then
	echo "[Info]  Gatekeeper is active, restricting apps to Apple Store and identified developers." > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Gatekeeper/Gatekeeper_Status.txt"
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

# Gatekeeper Database (Primary Location)
GatekeeperDatabase="/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/gk.db" # macOS Sequoia (2024)
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

# Gatekeeper Database (Secondary Location)
GatekeeperDatabase="/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/gk.db" # macOS Sequoia (2024)
if [[ ! -f "$GatekeeperDatabase" ]]; then
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
fi

# XProtect
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect"

# Prints the version of the currently installed XProtect assets
XProtectVersion=$(/usr/bin/sudo /usr/bin/xprotect version)
echo "$XProtectVersion" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XProtect_Version.txt" 2>&1

# Prints the current status of XProtect
XProtectStatus=$(/usr/bin/sudo /usr/bin/xprotect status)
echo "$XProtectStatus" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XProtect_Status.txt" 2>&1

# Prints the currently online available update version in iCloud
XProtectCheck=$(/usr/bin/sudo /usr/bin/xprotect check)
echo "$XProtectCheck" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XProtect_Check.txt" 2>&1

# XProtect Version Check (Current macOS Version only --> Check 'SystemInfo/SystemInfo_Data/SoftwareUpdate/softwareupdate_security.txt' for recommended OS updates (incl. XProtectPlistConfigData)
InstalledVersion=$(echo "$XProtectVersion" | /usr/bin/sed -e 's/Version: //g' | /usr/bin/sed -e 's/ Installed: .*//g')
OnlineVersion=$(echo "$XProtectCheck" | /usr/bin/sed -e 's/.*version: //g')
if [[ $XProtectVersion < $OnlineVersion ]]; then
	echo -e "\033[93m[ALERT] XProtect Update available! (XProtect Version: $OnlineVersion)\033[0m"
	echo -e "\033[93m        You may want to update your XProtect assets: sudo xprotect update\033[0m"
else
	echo -e "\033[32m[Info]  XProtect is up to date. No new version is available (for your current system).\033[0m"
fi

# Performs an update of XProtect assets
# /usr/bin/sudo /usr/bin/xprotect update

# Display XProtect Logs
/usr/bin/sudo /usr/bin/xprotect logs > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XProtect_Logs.txt"

# XProtect (Primary Location)
FILE="/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist" # macOS Sequoia (2024)
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	RULES=$(/bin/cat "/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	OSASCRIPT=$(/bin/cat "/private/var/protected/xprotect/XProtect.bundle/Contents/Resources/XPScripts.yr" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($RULES YARA rules, $OSASCRIPT OSASCRIPT rules)" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XProtect_PrimaryLocation.txt"
fi

# XProtect (Secondary Location)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	RULES=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	OSASCRIPT=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XPScripts.yr" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($RULES YARA rules, $OSASCRIPT OSASCRIPT rules)" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XProtect_SecondaryLocation.txt"
fi

# XProtect Behaviour Service (XBS) Database
# Note: Disabling System Integrity Protection (SIP) temporarily is required --> SIP-protected directory
SIP=$(/usr/bin/csrutil status)
if [[ $SIP = "System Integrity Protection status: disabled." ]]; then	

	# XPdb
	FILE="/private/var/protected/xprotect/db/XPdb"
	if [[ -f "$FILE" ]]; then
		/usr/bin/sudo /bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XPdb"
	fi

	# XPdb-shm
	FILE="/private/var/protected/xprotect/db/XPdb-shm"
	if [[ -f "$FILE" ]]; then
		/usr/bin/sudo /bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XPdb-shm"
	fi

	# XPdb-wal
	FILE="/private/var/protected/xprotect/db/XPdb-wal"
	if [[ -f "$FILE" ]]; then
		/usr/bin/sudo /bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/XPdb-wal"
	fi
fi

# XProtect Remediator (XPR) - Background Scan Settings
FILE="/Library/Apple/System/Library/LaunchAgents/com.apple.XProtect.agent.scan.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/com.apple.XProtect.agent.scan.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/com.apple.XProtect.agent.scan.txt"
fi

FILE="/Library/Apple/System/Library/LaunchAgents/com.apple.XProtect.agent.scan.startup.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/com.apple.XProtect.agent.scan.startup.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/com.apple.XProtect.agent.scan.startup.txt"
fi

FILE="/Library/Apple/System/Library/LaunchDaemons/com.apple.XProtect.daemon.scan.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/com.apple.XProtect.daemon.scan.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/XProtect/com.apple.XProtect.daemon.scan.txt"
fi

# Fast Scan     --> Interval: 21600 (6 hours)  --> AllowBattery: true
# Standard Scan --> Interval: 86400 (24 hours) --> AllowBattery: false
# Slow Scan     --> Interval: 604800 (7 days)  --> AllowBattery: false

# Install Date(s)

# Original Install Date 
# Note: Time Zone = Cupertino, California --> PDT (Pacific Daylight Time) --> UTC -7
FILE="/private/var/db/.AppleSetupDone"
if [[ -f "$FILE" ]]; then
	/usr/bin/stat -x "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Original-InstallDate.txt"
fi

# install.log (System Local Time)
FILE="/var/log/install.log"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/OS/install.log"
fi

# Timezone Information
Timezone=$(/usr/bin/sudo /usr/sbin/systemsetup -gettimezone | /usr/bin/sed -e 's/Time Zone: //g')
echo "$Timezone" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Timezone.txt"

# Automatic Timezone Detection (based on the current device location --> Location Services)
FILE="/Library/Preferences/com.apple.timezone.auto.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/OS/com.apple.timezone.auto.plist"

	AutomaticTimezone=$(/usr/bin/defaults read "$FILE" Active)
	if [[ $AutomaticTimezone = "0" ]]; then
		echo "[Info]  Automatic Timezone Feature is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Automatic-Zimezone.txt"
	elif [[ $AutomaticTimezone = "1" ]]; then
		echo "[Info]  Automatic Timezone Feature is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Automatic-Zimezone.txt"
	else
		echo "$AutomaticTimezone" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Automatic-Zimezone.txt"
	fi
fi

# System Settings > General > Date & Time > Set time and date automatically
# System Settings > General > Date & Time > Set time zone automatically using your current location

# Timezone Name
TimezoneName=$(/bin/date +"%Y-%m-%d %H:%M:%S %Z" | /usr/bin/awk '{ print $3 }')
echo "$TimezoneName" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Timezone-Name.txt"

# Timezone Offset
TimezoneOffset=$(/bin/date +"%Y-%m-%d %H:%M:%S %z" | /usr/bin/awk '{ print $3 }')
echo "$TimezoneOffset" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Timezone-Offset.txt"

# Timestamp
LocalSystemTimeFormatted=$(/bin/date +"%Y-%m-%d %H:%M:%S %z")
UtcFormatted=$(/bin/date -u +"%Y-%m-%d %H:%M:%S %z")
echo "$LocalSystemTimeFormatted" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Timestamp.txt"
echo "$UtcFormatted" >> "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Timestamp.txt"

# Preferred Languages
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
AppleLanguages=$(/usr/bin/sudo -u $LoggedInUser defaults read -g AppleLanguages)
echo "$AppleLanguages" | /usr/bin/grep -o '"[^"]\+"' | /usr/bin/tr -d '"' | /usr/bin/sort > "$OUTPUT"/SystemInfo/SystemInfo_Data/OS/PreferredLanguages.txt

# System Language
FILE="/Library/Preferences/.GlobalPreferences.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/OS/GlobalPreferences.plist"
	/usr/libexec/PlistBuddy -c "Print AppleLanguages:0" "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/SystemLanguage.txt"
fi

# Terminal --> ClickFix Attacks: Terminal Paste Protection
# Note: The "Possible malware, Paste blocked" message is a new, proactive security feature introduced in macOS 26.4 designed to stop a rapidly growing social engineering attack known as ClickFix. This technique tricks users into pasting and executing dangerous code directly into the Terminal.app.
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Preferences/com.apple.Terminal.plist"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Terminal/$UserName"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Terminal/$UserName/com.apple.Terminal.plist"
		/usr/bin/defaults read "$FILE" LastTerminalStartTime > "$OUTPUT/SystemInfo/SystemInfo_Data/Terminal/$UserName/LastTerminalStartTime.txt"
		/usr/bin/defaults read "$FILE" UserAcknowledgedPasteWarning > "$OUTPUT/SystemInfo/SystemInfo_Data/Terminal/$UserName/UserAcknowledgedPasteWarning.txt" 2>&1

		# UserAcknowledgedPasteWarning
		if [ "$(/usr/bin/defaults read "$FILE" UserAcknowledgedPasteWarning 2> /dev/null)" = "1" ]; then
		    echo -e "\033[91m[ALERT] Terminal.app ($UserName): User Acknowledged Paste Warning\033[0m" # Paste Anyway
		fi
	fi
done

# Browser Information
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Browsers"

# Default Browser
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	/usr/bin/defaults read "/Users/$UserName/Library/Preferences/com.apple.LaunchServices/com.apple.LaunchServices.secure.plist" | /usr/bin/awk -F'"' '/http;/{print window[(NR)-1]}{window[NR]=$2}' > "$OUTPUT/SystemInfo/SystemInfo_Data/Browsers/DefaultBrowser_$UserName.txt"
done

# Installed Browsers

# Arc
FILE="/Applications/Arc.app/Contents/Info.plist" # Default Location
if [[ -f "$FILE" ]]; then
	DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleDisplayName 2> /dev/null)
	if [[ -z "$DisplayName" ]]; then
		DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleName 2> /dev/null)
	fi
	Version=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString 2> /dev/null)
	Build=$(/usr/bin/defaults read "$FILE" CFBundleVersion 2> /dev/null)
	echo "[Info]  $DisplayName $Version ($Build)" >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Browsers/Installed-Browsers.txt
fi

# Brave Browser
FILE="/Applications/Brave Browser.app/Contents/Info.plist" # Default Location
if [[ -f "$FILE" ]]; then
	DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleDisplayName 2> /dev/null)
	if [[ -z "$DisplayName" ]]; then
		DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleName 2> /dev/null)
	fi
	Version=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString 2> /dev/null)
	if [[ -z "$Version" ]]; then
		Version=$(/usr/bin/defaults read "$FILE" CFBundleVersion 2> /dev/null)
	fi
	echo "[Info]  $DisplayName $Version" >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Browsers/Installed-Browsers.txt
fi

# Firefox
FILE="/Applications/Firefox.app/Contents/Info.plist" # Default Location
if [[ -f "$FILE" ]]; then
	DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleDisplayName 2> /dev/null)
	if [[ -z "$DisplayName" ]]; then
		DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleName 2> /dev/null)
	fi
	Version=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString 2> /dev/null)
	if [[ -z "$Version" ]]; then
		Version=$(/usr/bin/defaults read "$FILE" CFBundleVersion 2> /dev/null)
	fi
	echo "[Info]  $DisplayName $Version" >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Browsers/Installed-Browsers.txt
fi

# Google Chrome
FILE="/Applications/Google Chrome.app/Contents/Info.plist" # Default Location
if [[ -f "$FILE" ]]; then
	DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleDisplayName 2> /dev/null)
	if [[ -z "$DisplayName" ]]; then
		DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleName 2> /dev/null)
	fi
	Version=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString 2> /dev/null)
	if [[ -z "$Version" ]]; then
		Version=$(/usr/bin/defaults read "$FILE" CFBundleVersion 2> /dev/null)
	fi
	echo "[Info]  $DisplayName $Version" >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Browsers/Installed-Browsers.txt
fi

# Microsoft Edge
FILE="/Applications/Microsoft Edge.app/Contents/Info.plist" # Default Location
if [[ -f "$FILE" ]]; then
	DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleDisplayName 2> /dev/null)
	if [[ -z "$DisplayName" ]]; then
		DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleName 2> /dev/null)
	fi
	Version=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString 2> /dev/null)
	if [[ -z "$Version" ]]; then
		Version=$(/usr/bin/defaults read "$FILE" CFBundleVersion 2> /dev/null)
	fi
	echo "[Info]  $DisplayName $Version" >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Browsers/Installed-Browsers.txt
fi

# Safari
FILE="/Applications/Safari.app/Contents/Info.plist" # Default Location
if [[ -f "$FILE" ]]; then
	DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleDisplayName 2> /dev/null)
	if [[ -z "$DisplayName" ]]; then
		DisplayName=$(/usr/bin/defaults read "$FILE" CFBundleName 2> /dev/null)
	fi
	Version=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString 2> /dev/null)
	Build=$(/usr/bin/defaults read "$FILE" CFBundleVersion 2> /dev/null)
	echo "[Info]  $DisplayName $Version ($Build)" >> "$OUTPUT"/SystemInfo/SystemInfo_Data/Browsers/Installed-Browsers.txt
fi

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

# Software Update
FILE="/Library/Preferences/com.apple.SoftwareUpdate.plist"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SoftwareUpdate"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SoftwareUpdate/com.apple.SoftwareUpdate.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SoftwareUpdate/com.apple.SoftwareUpdate.txt"
fi

# Last Successful Update Check (or Installation)
LastFullSuccessfulDate=$(/usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate LastFullSuccessfulDate)
echo "$LastFullSuccessfulDate" > "$OUTPUT/SystemInfo/SystemInfo_Data/SoftwareUpdate/LastFullSuccessfulDate.txt"

# Software Update Tool (incl. Security Updates) --> Verify what packages need to be installed
SoftwareUpdate=$(/usr/sbin/softwareupdate --list --include-config-data 2>&1)
echo "$SoftwareUpdate" > "$OUTPUT/SystemInfo/SystemInfo_Data/SoftwareUpdate/softwareupdate_security.txt"

# System Settings > General > Software Update

# Available Software Updates
if echo "$SoftwareUpdate" | /usr/bin/grep -q "Software Update found"; then

	# macOS
	if echo "$SoftwareUpdate" | /usr/bin/grep -q "Title: macOS"; then
		Version=$(echo "$SoftwareUpdate" | /usr/bin/grep "Title: macOS" | /usr/bin/sed -e 's/.*Title: //g' | /usr/bin/sed -e 's/, .*//g')
		echo -e "\033[93m[ALERT] Updates are available for your Mac! ($Version)\033[0m"
	fi

	# XProtectPlistConfigData
	if echo "$SoftwareUpdate" | /usr/bin/grep -q "Title: XProtectPlistConfigData"; then
		Version=$(echo "$SoftwareUpdate" | /usr/bin/grep "Title: XProtectPlistConfigData" | /usr/bin/sed -e 's/.*Version: //g' | /usr/bin/sed -e 's/, .*//g')
		echo -e "\033[93m[ALERT] XProtect Update available! (XProtect Version: $Version)\033[0m"
	fi
fi

# To install all updates run the command:
# /usr/bin/sudo /usr/sbin/softwareupdate -i -a --agree-to-license

# Or run the following command to install individual packages:
# /usr/bin/sudo /usr/sbin/softwareupdate -i '<package name>' --agree-to-license

# Installed Software Updates (System Software)
FILE="/private/var/db/softwareupdate/journal.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SoftwareUpdate/journal.plist"
fi

# Apple Intelligence
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Preferences/com.apple.CloudSubscriptionFeatures.optIn.plist"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Apple-Intelligence/$UserName"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Apple-Intelligence/$UserName/com.apple.CloudSubscriptionFeatures.optIn.plist"
		/usr/bin/defaults read "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Apple-Intelligence/$UserName/com.apple.CloudSubscriptionFeatures.optIn.txt"
	fi
done

# System Settings > Apple Intelligence & Siri > Apple Intelligence

# Time Machine
FILE="/Library/Preferences/com.apple.TimeMachine.plist"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/TimeMachine"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/TimeMachine/com.apple.TimeMachine.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/TimeMachine/com.apple.TimeMachine.txt" 
fi

# AirDrop Status (AirDrop Interface --> Apple Wireless Direct Link)
# Note: AirDrop lets you share instantly with people nearby. You can be discoverable in AirDrop to receive from everyone or only people in your contacts.
if /usr/bin/sudo /sbin/ifconfig -l | /usr/bin/grep  -q "awdl0"; then

	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop"

	AirDrop=$(/usr/bin/sudo /sbin/ifconfig awdl0 | /usr/bin/awk '/status/{print $2}')

	if [[ $AirDrop = "active" ]]; then
		echo "[Info]  AirDrop is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop/AirDrop_Status.txt"
	elif [[ $AirDrop = "inactive" ]]; then
		echo "[Info]  AirDrop is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop/AirDrop_Status.txt"
	else
		AirDrop=$(/usr/bin/sudo /sbin/ifconfig awdl0)
		echo "$AirDrop" > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop/AirDrop_Status.txt"
	fi
else
	echo "[Info]  Interface awdl0 does NOT exist." > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop/awdl0.txt"
fi

# AirDrop Preferences
FILE="/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop/com.apple.airport.preferences.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/AirDrop/com.apple.airport.preferences.txt" 
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
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth"

SPBluetoothDataType=$(/usr/sbin/system_profiler SPBluetoothDataType)

echo "$SPBluetoothDataType" > "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth/Bluetooth.txt"

if echo $SPBluetoothDataType | /usr/bin/grep -A 2 "Bluetooth Controller:" | /usr/bin/grep -q "State: On"; then
	echo "[Info]  Bluetooth is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth/Bluetooth_Status.txt"
else
	echo "[Info]  Bluetooth is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Bluetooth/Bluetooth_Status.txt"
fi

# System Settings > Bluetooth

# Connect to accessories you can use for activities such as streaming music, typing, and gaming.

# My Devices
# Manage devices that were previously connected to your Mac and can automatically reconnect.

# Nearby Devices
# Connect a new wireless device to your Mac and see other discoverable wireless devices in the area.

# Wi-Fi
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi"

# Wi-Fi Status
SPAirPortDataType=$(/usr/sbin/system_profiler SPAirPortDataType)
echo "$SPAirPortDataType" > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi/SPAirPortDataType.txt"

if echo $SPAirPortDataType | /usr/bin/grep -q "State: Connected"; then
	echo "[Info]  Wi-Fi is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi/Wi-Fi_Status.txt" # Status: Connected
else
	echo "[Info]  Wi-Fi is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi/Wi-Fi_Status.txt" # Status: Off
fi

# Wireless Diagnostics
WirelessDiagnostics=$(/usr/bin/sudo /usr/bin/wdutil info)
echo "$WirelessDiagnostics" > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi/Wireless-Diagnostics.txt"

# Known Wi-Fi Networks
FILE="/Library/Preferences/com.apple.wifi.known-networks.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi/com.apple.wifi.known-networks.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Wi-Fi/com.apple.wifi.known-networks.txt" 
fi

# Application Layer Firewall (ALF) --> allows or blocks incoming connections at the app level
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Application-Layer"

# Firewall Status
Firewall=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate)

# Firewall is enabled. (State = 1)
# Firewall is disabled. (State = 0)

if echo "$Firewall" | /usr/bin/grep -q "Firewall is enabled."; then # The firewall is turned on and set up to prevent unauthorized applications, programs, and services from accepting incoming connections.
	StealthMode=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode) # Your Mac will not respond to ping or port scans when enabled.
	echo "[Info]  $Firewall" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Application-Layer/Firewall_Status.txt"
	echo "[Info]  $StealthMode" >> "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Application-Layer/Firewall_Status.txt"
else
	echo -e "\033[91m[ALERT] This computer's firewall is currently turned off. All incoming connections to this computer are allowed.\033[0m"
fi

# System Settings > Network > Firewall

# Allowed Applications
AddedApps=$(/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --listapps)
echo "$AddedApps" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Application-Layer/Allowed-Applications.txt"

# Application Layer Firewall Configuration
FILE="/Library/Preferences/com.apple.alf.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Application-Layer/com.apple.alf.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Application-Layer/com.apple.alf.txt" 
fi

# Packet Filter (PF) Firewall --> network firewall that lets you define custom filtering rules
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Packet-Filter"

# Packet Filter - Status
STATUS=$(/usr/bin/sudo /sbin/pfctl -s info 2> /dev/null)
echo "$STATUS" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Packet-Filter/PacketFilter-Status.txt"

# Packet Filter - Firewall Rules
RULES=$(/usr/bin/sudo /sbin/pfctl -sr 2> /dev/null)
echo "$RULES" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Packet-Filter/PacketFilter-Rules.txt"

# Packet Filter - Firewall Configuration
FILE="/System/Library/LaunchDaemons/com.apple.pfctl.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Packet-Filter/com.apple.pfctl.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/SecurityInfo/Firewall/Packet-Filter/com.apple.pfctl.txt" 
fi

# Screen Sharing Preferences
# Note: Remote Login allows a user to remotely log in to the system via the SSH (Secure Shell) protocol.
FILE="/System/Library/LaunchDaemons/com.apple.screensharing.plist"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/com.apple.screensharing.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/com.apple.screensharing.txt"

	# Disabled
	ScreenSharing=$(/usr/bin/defaults read "$FILE" Disabled)
	if [[ $ScreenSharing = "0" ]]; then
		echo "[Info]  Screen Sharing is ON." > "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/Screen-Sharing.txt"
	fi

	# Enabled
	if [[ $ScreenSharing = "1" ]]; then
		echo "[Info]  Screen Sharing is OFF." > "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/Screen-Sharing.txt"
	fi
fi

# VNC Settings (Virtual Network Computing)
FILE="/Library/Preferences/com.apple.VNCSettings.txt"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/com.apple.VNCSettings.txt"
fi

# Service Configuration Files (launchd --> Service Management Framework)
# Note: It contains a list of services that have been explicitly disabled or enabled via launchctl.
SRCFOLDER="/private/var/db/com.apple.xpc.launchd"
DSTFOLDER="$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/Service-Configuration-Files"
if [[ -d "$SRCFOLDER" ]]; then
	COUNT=$(/usr/bin/find "$SRCFOLDER" -maxdepth 1 -type f -name "disabled*.plist" | /usr/bin/grep -c ^)
	if [[ $COUNT -ge 1 ]]; then
		/bin/mkdir -p "$DSTFOLDER"
		/usr/bin/find "$SRCFOLDER" -maxdepth 1 -type f -name "disabled*.plist" -exec /bin/cp -p {} "$DSTFOLDER" \;
	fi
fi

# disabled.plist --> Contains a list of globally disabled system-level services.
# disabled.501.plist --> Contains services disabled for a specific user (identified by their User ID, e.g., 501).

# com.openssh.sshd = Remote Login
# com.apple.screensharing = Screen Sharing (VNC protocol)

# Screen Sharing Daemon
ScreenSharingDaemon=$(/usr/bin/sudo /bin/launchctl list com.apple.screensharing 2>&1)
echo "$ScreenSharingDaemon" > "$OUTPUT/SystemInfo/SystemInfo_Data/Screen-Sharing/Screen-Sharing-Daemon.txt"

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

# Trust Settings
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/TrustSettings"
/usr/bin/security dump-trust-settings > "$OUTPUT/SystemInfo/SystemInfo_Data/TrustSettings/Trusted-User-Certs.txt" 2>&1
/usr/bin/security dump-trust-settings -d > "$OUTPUT/SystemInfo/SystemInfo_Data/TrustSettings/Trusted-Admin-Certs.txt" 2>&1
/usr/bin/security dump-trust-settings -s > "$OUTPUT/SystemInfo/SystemInfo_Data/TrustSettings/Trusted-System-Certs.txt" 2>&1

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

# Login Information --> Current Logged-In Users
/usr/bin/who -a > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Login-Information.txt" 2>&1

# Login History
/usr/bin/last > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Login_History.txt" 2>&1

# Active Users --> who is logged in and what they are doing
/usr/bin/w > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/Active-Users.txt" 2>&1

# Users
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo"
/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500' | /usr/bin/sort -k2 > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Users.txt" 2>&1

# User Details (Attributes)
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	/usr/bin/dscl . -read /Users/$UserName > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/UserDetails_$UserName.txt" 2>&1
done

# User Accounts
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/private/var/db/dslocal/nodes/Default/users/$UserName.plist"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/UserAccounts"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/UserAccounts/$UserName.plist"
		/usr/bin/defaults read "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/UserAccounts/UserAccount_$UserName.txt"
	fi
done

# Admin Users
Administrators=$(/usr/bin/dscl . -read /Groups/admin GroupMembership | /usr/bin/sed -e 's/GroupMembership: //g' | /usr/bin/tr " " "\n")
echo "$Administrators" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Administrators.txt"

# User Privileges
FILE="/private/etc/sudoers"
if [[ -f "$FILE" ]]; then
	/bin/cat "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/sudoers.txt" 2>&1
fi

# Service Accounts
ServiceAccounts=$(/usr/bin/dscl . list /Users UniqueID | /usr/bin/grep "^_")
echo "$ServiceAccounts" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/Service-Accounts.txt"

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
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/com.apple.loginwindow.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/UserInfo/com.apple.loginwindow.txt"
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
/usr/bin/sudo /usr/bin/defaults read /Library/Preferences/com.apple.loginwindow > "$OUTPUT/SystemInfo/SystemInfo_Data/OS/LoginWindow.txt"

# Collecting Shell History and Profile Information
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	# Zsh

	# Execution Order: .zshenv --> .zprofile --> .zshrc --> .zlogin

	# Terminal History (Zsh)
	FILE="/Users/$UserName/.zsh_history"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_.zsh_history"
		/bin/cat "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_history.txt"
	fi

	# Terminal Sessions (Zsh)
	SESSION_DIR="/Users/$UserName/.zsh_sessions"
	DESTINATION="$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/Sessions"
	if [[ -d "$SESSION_DIR" ]]; then
		/usr/bin/rsync -av "$SESSION_DIR" "$DESTINATION" > /dev/null
	fi

	# .zshenv --> Environment Variables
	FILE="/Users/$UserName/.zshenv"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_.zshenv"
	fi

	# .zprofile (Login Shells only) --> Zsh Profile
	FILE="/Users/$UserName/.zprofile"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_.zprofile"
	fi

	# .zshrc (Interactive Shells only) --> Zsh Profile
	FILE="/Users/$UserName/.zshrc"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_.zshrc"
	fi

	# .zlogin --> Login Shell
	FILE="/Users/$UserName/.zlogin"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_.zlogin"
	fi

	# .zlogout --> when the shell exits
	FILE="/Users/$UserName/.zlogout"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Zsh/"$UserName"_.zlogout"
	fi

	# Bash

	# Terminal History (Bash)
	FILE="/Users/$UserName/.bash_history"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash/"$UserName"_.bash_history"
	fi

	# .bash_profile --> Bash Profile
	FILE="/Users/$UserName/.bash_profile"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash/"$UserName"_.bash_profile"
	fi

	# .bashrc (Interactive Shells only) --> Bash Profile
	FILE="/Users/$UserName/.bashrc"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash/"$UserName"_.bashrc"
	fi

	# .bash_logout --> when the shell exits
	FILE="/Users/$UserName/.bash_logout"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/$UserName/Bash/"$UserName"_.bash_logout"
	fi
done

# root

# Zsh

# Terminal History (Zsh)
FILE="/var/root/.zsh_history"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Zsh"
	/usr/bin/sudo /bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Zsh/root_.zsh_history"
fi

# Terminal Sessions (Zsh)
SESSION_DIR="/var/root/.zsh_sessions"
	DESTINATION="$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Zsh/Sessions"
	if [[ -d "$SESSION_DIR" ]]; then
		/usr/bin/rsync -av "$SESSION_DIR" "$DESTINATION" > /dev/null
	fi

# .zshrc (Interactive Shells only) --> Zsh Profile
FILE="/var/root/.zshrc"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Zsh"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Zsh/root_.zshrc"
fi

# Bash

# Terminal History (Bash)
FILE="/var/root/.bash_history"
if [[ -f "$FILE" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Bash"
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Shell/root/Bash/root_.bash_history"
fi

# Important: When a shell script runs with sudo, it operates as the root user, not your user, and often in a non-interactive shell.

# Shell Built-In Commands
# fc -li 1
# history -i 1

# System Configuration / Network Settings
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Network"

# Internet Connectivity Check
if /usr/bin/nc -z mensura.cdn-apple.com 80 -G1 > /dev/null 2>&1; then
	echo "[Info]  This Mac is connected to the Internet." > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Internet-Connectivity.txt"
else
	echo "[Info]  This Mac is NOT connected to the Internet." > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Internet-Connectivity.txt"
fi

# Network Configuration
FILE="/Library/Preferences/SystemConfiguration/preferences.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Network/preferences.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/preferences.txt"
fi

# Network Interfaces
FILE="/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist"
if [[ -f "$FILE" ]]; then
	/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/Network/NetworkInterfaces.plist"
	/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/NetworkInterfaces.txt"
fi

# ifconfig --> Network Interfaces
/sbin/ifconfig > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/ifconfig.txt" 2>&1

# Collecting DHCP Network Artifacts
SOURCE="/private/var/db/dhcpclient/leases/"
DESTINATION="$OUTPUT/SystemInfo/SystemInfo_Data/Network/DHCP"
if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
	/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Network/DHCP"
	/usr/bin/sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" > /dev/null
fi

# DNS Configuration
/usr/sbin/scutil --dns > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/DNS.txt" 2>&1

# List all Network Services
/usr/sbin/networksetup -listallnetworkservices > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Network-Services.txt" 2>&1

# Routing Table Information
/usr/sbin/netstat -rn > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Routing-Table.txt" 2>&1

# Show IPv4 Routes Only
/usr/sbin/netstat -nr -f inet > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Routing-Table_IPv4.txt" 2>&1

# Show IPv6 Routes Only
/usr/sbin/netstat -nr -f inet6 > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Routing-Table_IPv6.txt" 2>&1

# Default Gateway
Gateway=$(/sbin/route -n get default | /usr/bin/grep "gateway:" | /usr/bin/awk '{ print $2 }')
echo "$Gateway" > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Default-Gateway.txt" 2>&1

# Address Resolution Protocol (ARP) Table
/usr/sbin/arp -an > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/ARP-Table.txt" 2>&1 # IPv4

# Neighbor Discovery Protocol (NDP) Table
/usr/sbin/ndp -an > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/NDP-Table.txt" 2>&1 # IPv6

# List All Active Network Connections
/usr/bin/sudo /usr/sbin/lsof -i > "$OUTPUT/SystemInfo/SystemInfo_Data/Network/Active-Network-Connections.txt" 2>&1

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

# SPApplicationsDataType
SPApplicationsDataType=$(/usr/sbin/system_profiler SPApplicationsDataType)
echo "$SPApplicationsDataType" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/SPApplicationsDataType.txt"
/usr/sbin/system_profiler -json -nospawn SPApplicationsDataType -detailLevel full > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/SPApplicationsDataType.json"

# System Apps
SystemApps=$(/usr/bin/mdfind -onlyin /System/Applications/ "kind:application" 2>&1 | /usr/bin/grep -v "UserQueryParser" | /usr/bin/sort)
echo "$SystemApps" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/System-Apps.txt"

# List App Store Apps
/usr/bin/find /Applications -path '*Contents/_MASReceipt/receipt' -maxdepth 4 -print | /usr/bin/sed 's#.app/Contents/_MASReceipt/receipt#.app#g; s#/Applications/##' | /usr/bin/sort > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/AppStore-Apps.txt" 2>&1

# App Store Downloads (Third-Party Updates)
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Caches/com.apple.appstoreagent/storeSystem.db"
	if [[ -f "$FILE" ]]; then
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/storeSystem_$UserName.db"
	fi
done

# Install History (AppStore Downloads)
FILE="/Library/Receipts/InstallHistory.plist"
if [[ -f "$FILE" ]]; then
	/usr/libexec/PlistBuddy -c "print" "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/InstallHistory.txt"
fi

# processName
# macOS Installer or bootinstalld      = System OS Installer/Updater
# softwareupdated or "Software Update" = System/Security Updates
# storedownloadd or appstoreagent      = App Store Installs
# Installer or installer               = External Installers

# Recently Modified Applications (Last 7 Days)
#/usr/bin/find /Applications -type f -mtime -7 -ls > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Recently-Modified-Apps.txt" 2>&1

# List Apps and Processes connected to Internet
/usr/bin/sudo /usr/sbin/lsof -nPi | /usr/bin/cut -f 1 -d " " | /usr/bin/uniq | /usr/bin/tail -n +2 > "$OUTPUT/SystemInfo/SystemInfo_Data/AppInfo/Internet-Connected-Apps.txt" 2>&1

# Active Processes
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Processes"
/bin/ps aux > "$OUTPUT/SystemInfo/SystemInfo_Data/Processes/Active-Processes.txt" 2>&1

# Recently Downloaded Files (Last 7 Days)
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	/usr/bin/find /Users/$UserName/Downloads -type f -mtime -7 -ls > "$OUTPUT/SystemInfo/SystemInfo_Data/Recently-Downloaded-Files_$UserName.txt" 2>&1
done

# List Open Files
/usr/bin/sudo /usr/sbin/lsof -n > "$OUTPUT/SystemInfo/SystemInfo_Data/Open-Files.txt" 2>&1

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
# Note: The 'open:128:Last Connect' key contains a hex representation of a macOS timestamp of the last device connection time in local system time.
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Preferences/com.apple.iPod.plist"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/iDevices/raw"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/iDevices/raw/iDevices_$UserName.plist"
		/usr/bin/defaults read "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/iDevices/iDevices_$UserName.txt"
	fi
done

# Device List
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	FILE="/Users/$UserName/Library/Application Support/com.apple.akd/devicelist.db"
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/DeviceList/$Username"
		/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/DeviceList/$Username/devicelist_$UserName.db"
	fi
done

# Mounted Volumes
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
if [[ -f "/Users/$LoggedInUser/Library/Preferences/com.apple.finder.plist" ]]; then
	/usr/bin/defaults read "/Users/$LoggedInUser/Library/Preferences/com.apple.finder.plist" FXDesktopVolumePositions > "$OUTPUT/SystemInfo/SystemInfo_Data/Mounted-Volumes.txt"
fi

# Loaded Extensions (Kernel and System)
/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Extensions/"

# System Extensions
SystemExtensions=$(/usr/bin/systemextensionsctl list 2> /dev/null)
echo "$SystemExtensions" > "$OUTPUT/SystemInfo/SystemInfo_Data/Extensions/System-Extensions.txt"

# Kernel Extensions (Kexts)
/usr/bin/kmutil showloaded > "$OUTPUT/SystemInfo/SystemInfo_Data/Extensions/Kernel-Extensions.txt" 2> /dev/null

# Third-Party Kernel Extensions
/usr/bin/kmutil showloaded 2> /dev/null | /usr/bin/grep -v "com.apple" > "$OUTPUT/SystemInfo/SystemInfo_Data/Extensions/Kernel-Extensions_3rd-Party.txt"

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
/usr/bin/sudo /usr/bin/profiles show -P -v -o stdout-xml > "$OUTPUT/SystemInfo/SystemInfo_Data/MDM/Profiles.xml"

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
		if [[ $COUNT -ge 1 ]]; then
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

# Lockdown Files (Pairing Records)
# Note: Disabling System Integrity Protection (SIP) temporarily is required --> SIP-protected directory
if [[ -d "/private/var/db/lockdown" ]]; then
	COUNT=$(/usr/bin/sudo /usr/bin/find /private/var/db/lockdown -type f -name '*.plist' 2> /dev/null | /usr/bin/grep -v "SystemConfiguration.plist" | /usr/bin/grep -c ^) # <UDID>.plist
	if [[ "$COUNT" -ge 1 ]]; then
		echo "[Info]  $COUNT Lockdown File(s) found"

		# Collecting Lockdown File(s)
		/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/Lockdown"
		/usr/bin/sudo /usr/bin/find /private/var/db/lockdown -type f -name '*.plist' | /usr/bin/grep -v "SystemConfiguration.plist" > "$OUTPUT/SystemInfo/SystemInfo_Data/Lockdown/Files.txt"
		if [[ -s "$OUTPUT/SystemInfo/SystemInfo_Data/Lockdown/Files.txt" ]]; then
			echo "[Info]  Collecting Lockdown File(s) ..."
			/usr/bin/sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/SystemInfo/SystemInfo_Data/Lockdown/Files.txt" / "$OUTPUT/SystemInfo/SystemInfo_Data/Lockdown" >> "$OUTPUT/SystemInfo/SystemInfo_Data/Lockdown/Collection.txt" 2>&1
		fi
	fi
fi

# iOS Backups
UserList=$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 >= 500 { print $1; }')
for User in $UserList; do
	if [[ -d "/Users/$User/Library/Application Support/MobileSync/Backup" ]]; then
		COUNT=$(/usr/bin/find "/Users/$User/Library/Application Support/MobileSync/Backup" -mindepth 1 -maxdepth 1 -type d | grep -c ^)
		if [[ "$COUNT" -ge 1 ]]; then
			/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User"
			/usr/bin/find "/Users/$User/Library/Application Support/MobileSync/Backup" -mindepth 1 -maxdepth 1 -type d > "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/iOS-Backups.txt"

			while read FOLDER
			do
				UDID=$(/usr/bin/basename "$FOLDER")
				/bin/mkdir -p "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID"
				BYTES=$(/usr/bin/find "$FOLDER" -ls | /usr/bin/awk '{sum += $7} END {print sum}')
				FOLDERSIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
				echo "[Info]  Backup Size: $FOLDERSIZE" > "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/FolderSize.txt"

				# Info.plist
				FILE="$FOLDER/Info.plist"
				if [[ -f "$FILE" ]]; then
					/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/Info.plist"
					/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/Info.txt"
				fi

				# Manifest.plist
				FILE="$FOLDER/Manifest.plist"
				if [[ -f "$FILE" ]]; then
					/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/Manifest.plist"
					/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/Manifest.txt"
				fi

				# Status.plist
				FILE="$FOLDER/Status.plist"
				if [[ -f "$FILE" ]]; then
					/bin/cp "$FILE" "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/Status.plist"
					/usr/bin/plutil -p "$FILE" > "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/Status.txt"
				fi

				# Collect iOS Backups (Disabled by default)
				#cd "/Users/$User/Library/Application Support/MobileSync/Backup"
				#"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/$UDID/$UDID.7z" "$UDID/*" > /dev/null 2>&1
				#cd "$SCRIPT_DIR"

			done < "$OUTPUT/SystemInfo/SystemInfo_Data/iOS-Backups/$User/iOS-Backups.txt"
		fi
	fi
done

# Creating Secure Archive
if [[ -d "$OUTPUT/SystemInfo/SystemInfo_Data" ]]; then
	echo "[Info]  Preparing Secure Archive Container ..."
	cd "$OUTPUT/SystemInfo"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "SystemInfo_$SerialNumber.7z" "SystemInfo_Data/*" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/SystemInfo" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^SystemInfo_.*.7z$")
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
	if [[ "$MD5" = "$MD5_AFTERMATH" ]]; then

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

		echo "[Info]  File Integrity (aftermath): OK"
	else
		echo -e "\033[91m[ALERT] File Integrity (aftermath): FAILURE\033[0m"
		exit 1
	fi
fi

# Aftermath Collection
/bin/mkdir -p "$OUTPUT"/Aftermath_Collection

# Default Collection + Deep Scan
echo "[Info]  Aftermath Collection w/ Deep Scan is running [approx. 3-20 min] ..."
/usr/bin/sudo "$AFTERMATH" -o "$OUTPUT"/Aftermath_Collection --deep --pretty > "$OUTPUT"/Aftermath_Collection/Aftermath-colored.txt 2> /dev/null

# Remove Aftermath folders from default locations ("/tmp", "/var/folders/zz/) 
echo "[Info]  Cleaning up ..."
/usr/bin/sudo "$AFTERMATH" --cleanup > "$OUTPUT"/Aftermath_Collection/Cleanup.txt 2> /dev/null

# Cleaning Aftermath Logfile
/bin/cat -v "$OUTPUT"/Aftermath_Collection/Aftermath-colored.txt | /usr/bin/sed -e 's/\^\[//g' | /usr/bin/sed -e 's/\[0;[0-9]*m//g' > "$OUTPUT"/Aftermath_Collection/Aftermath.txt

# Creating Secure Archive
if [[ -d "$OUTPUT/Aftermath_Collection" ]]; then
	echo "[Info]  Preparing Secure Archive Container ..."
	cd "$OUTPUT"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "Aftermath_$SerialNumber.7z" "Aftermath_Collection/*" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Aftermath_.*.7z$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/$ARCHIVE"
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

# Cleaning up
FOLDER="$OUTPUT/Aftermath_Collection"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

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
		if [[ "$MD5" = "$MD5_AFTERMATH" ]]; then

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

			echo "[Info]  File Integrity (aftermath): OK"
		else
			echo -e "\033[91m[ALERT] File Integrity (aftermath): FAILURE\033[0m"
			exit 1
		fi
	fi

	# Analyze Aftermath Archive
	echo "[Info]  Analyzing Aftermath Archive [approx. 1-10 min] ..."
	/bin/mkdir -p "$OUTPUT"/Aftermath_Analysis/
	/usr/bin/sudo "$AFTERMATH" --analyze "$ARCHIVE_FILE" --pretty -o "$OUTPUT/Aftermath_Analysis" > "$OUTPUT/Aftermath_Analysis/Aftermath-colored.txt" 2> /dev/null

	# Cleaning Aftermath Logfile
	if [[ -f "$OUTPUT/Aftermath_Analysis/Aftermath-colored.txt" ]]; then
		/bin/cat -v "$OUTPUT/Aftermath_Analysis/Aftermath-colored.txt" | /usr/bin/sed -e 's/\^\[//g' | /usr/bin/sed -e 's/\[0;[0-9]*m//g' > "$OUTPUT/Aftermath_Analysis/Aftermath.txt"
	fi

	# Creating Secure Archive
	if [[ -d "$OUTPUT/Aftermath_Analysis" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT"
		SerialNumber=$(/usr/bin/basename "$ARCHIVE_FILE" | /usr/bin/cut -d. -f1 | /usr/bin/sed -e 's/Aftermath_//g')
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "Aftermath_Analysis_$SerialNumber.7z" "Aftermath_Analysis/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	fi

	# Archive Name
	ARCHIVE=$(/bin/ls -l "$OUTPUT" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Aftermath_Analysis.*.7z$")
	echo "[Info]  Archive Name: $ARCHIVE"

	# Archive Size
	FILE="$OUTPUT/$ARCHIVE"
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
	#/bin/cat -v "$OUTPUT/Aftermath_Analysis/Aftermath-colored.txt" | /usr/bin/sed -e 's/\^\[//g' | /usr/bin/sed -e 's/\[0;[0-9]*m//g' > "$OUTPUT/Aftermath_Analysis/Aftermath.txt"

	# Cleaning up
	FOLDER="$OUTPUT/Aftermath_Analysis"
	if [[ -d "$FOLDER" ]]; then
		/bin/rm -rf "$FOLDER"
	fi

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
COUNT=$(/bin/cat "$FILE" | /usr/bin/grep -c "Records for UID")
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

# Directory Service Attributes (Open Directory) --> User Properties
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/grep -v "^_" | /usr/bin/grep -v "daemon" | /usr/bin/sort -k2 | /usr/bin/awk '{ print $1 }')
do
	echo "Name: $UserName" >> "$OUTPUT/BTM/Users.txt"
	/usr/bin/dscl . read /Users/$UserName UniqueID >> "$OUTPUT/BTM/Users.txt"
	/usr/bin/dscl . read /Users/$UserName generateduid | /usr/bin/sed -e "s/dsAttrTypeNative:generateduid:/UUID:/g" >> "$OUTPUT/BTM/Users.txt"
	/usr/bin/dscl . read /Users/$UserName NFSHomeDirectory | /usr/bin/sed -e "s/NFSHomeDirectory:/Home Directory:/g" >> "$OUTPUT/BTM/Users.txt"
	/usr/bin/dscl . read /Users/$UserName RealName| /usr/bin/xargs | /usr/bin/sed -e "s/RealName:/Real Name:/g" >> "$OUTPUT/BTM/Users.txt"
	echo "" >> "$OUTPUT/BTM/Users.txt"
done

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

# Image Info (DMG)
FILE="$OUTPUT/BTM/BTM_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	/usr/bin/hdiutil imageinfo "$FILE" > "$OUTPUT/BTM/ImageInfo.txt"
fi

# Creating Secure Archive (DMG)
FILE="$OUTPUT/BTM/BTM_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	cd "$OUTPUT/BTM"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "BTM_$SerialNumber.dmg.7z" "$FILE" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
	
	# Cleaning up 
	/bin/rm -rf "$FILE"
fi

# Count BTM Database File(s)
COUNT=$(/bin/cat "$OUTPUT/BTM/Files.txt" | /usr/bin/grep -c ^)
echo "[Info]  $COUNT BTM Database File(s) found"

# Creating Secure Archive
if [[ -d "$OUTPUT/BTM/BTM_Data" ]]; then
	echo "[Info]  Preparing Secure Archive Container ..."
	cd "$OUTPUT/BTM"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "BTM_$SerialNumber.7z" "BTM_Data/*" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/BTM" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^BTM_$SerialNumber.7z$")
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

# Image Info (DMG)
FILE="$OUTPUT/DS_Store/DSStore_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	/usr/bin/hdiutil imageinfo "$FILE" > "$OUTPUT/DS_Store/ImageInfo.txt"
fi

# Creating Secure Archive (DMG)
FILE="$OUTPUT/DS_Store/DSStore_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	cd "$OUTPUT/DS_Store"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "DSStore_$SerialNumber.dmg.7z" "$FILE" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
	
	# Cleaning up 
	/bin/rm -rf "$FILE"
fi

# Creating Secure Archive
if [[ -d "$OUTPUT/DS_Store/DSStore_Data" ]]; then
	echo "[Info]  Preparing Secure Archive Container ..."
	cd "$OUTPUT/DS_Store"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "DSStore_$SerialNumber.7z" "DSStore_Data/*" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/DS_Store" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^DSStore_$SerialNumber.7z$")
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

# Image Info (DMG)
FILE="$OUTPUT/FSEvents/FSEvents_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	/usr/bin/hdiutil imageinfo "$FILE" > "$OUTPUT/FSEvents/ImageInfo.txt"
fi

# Creating Secure Archive (DMG)
FILE="$OUTPUT/FSEvents/FSEvents_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	cd "$OUTPUT/FSEvents"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "FSEvents_$SerialNumber.dmg.7z" "$FILE" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
	
	# Cleaning up 
	/bin/rm -rf "$FILE"
fi

# Creating Secure Archive
if [[ -d "$OUTPUT/FSEvents/FSEvents_Data" ]]; then
	echo "[Info]  Preparing Secure Archive Container ..."
	cd "$OUTPUT/FSEvents"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "FSEvents_$SerialNumber.7z" "FSEvents_Data/*" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/FSEvents" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^FSEvents_$SerialNumber.7z$")
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

# Creating Secure Archive
if [[ -d "$LOGARCHIVE" ]]; then
	echo "[Info]  Preparing Secure Archive Container ..."
	cd "$OUTPUT/UnifiedLogs"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "UnifiedLogs_$SerialNumber.7z" "system_logs.logarchive/*" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/UnifiedLogs" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^UnifiedLogs_.*.7z$")
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

# Creating Secure Archive
if [[ -d "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" )" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT/Sysdiagnose"
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "Sysdiagnose_$SerialNumber.7z" "Sysdiagnose_Data/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/Sysdiagnose" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Sysdiagnose_.*.7z$")
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
	/bin/mkdir -p "$OUTPUT/KnockKnock/KnockKnock_Data"
	cd "$SCRIPT_DIR/tools/KnockKnock/"
	DATE=$(/bin/date -u +"%Y-%m-%d")

	# Check if VirusTotal API Key exists
	if [[ $VIRUSTOTAL == "YOUR_API_KEY" ]]; then

		# Launch KnockKnock /wo VirusTotal
		echo "[Info]  Scanning Live System w/ KnockKnock ..."
		/usr/bin/sudo ./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere -verbose > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-verbose.json"

	else

		# Check if virustotal.com is reachable
		#/sbin/ping -c 1 -W 5 virustotal.com > /dev/null 2>&1 # ICMP
		/usr/bin/nc -z virustotal.com 443 -G1 > /dev/null 2>&1 # TCP
		if ! [[ $? -eq 0 ]]; then
			echo -e "\033[91m[Error] virustotal.com is NOT reachable!\033[0m"
			echo "" && exit 1
		fi

		# Launch KnockKnock /w VirusTotal
		echo "[Info]  Scanning Live System w/ KnockKnock [approx. 1-2 min] ..."
		/usr/bin/sudo ./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere -verbose -key "$VIRUSTOTAL" > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-verbose.json"
	fi

	cd $SCRIPT_DIR

else
	echo "[Error] KnockKnock NOT found."
fi

# Output
if [[ -s "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-verbose.json" ]]; then

	# JSON
	/bin/cat "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-verbose.json" | /usr/bin/tail -n 1 > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE.json"

	# TXT
	/bin/cat "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock_Results_$DATE-verbose.json" | /usr/bin/sed '$d' > "$OUTPUT/KnockKnock/KnockKnock_Data/KnockKnock.txt"
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

# Creating Secure Archive
if [[ -d "$OUTPUT/KnockKnock/KnockKnock_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/KnockKnock/KnockKnock_Data" )" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT/KnockKnock"
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "KnockKnock_$SerialNumber.7z" "KnockKnock_Data/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	else
		echo "KnockKnock_Data is empty."
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/KnockKnock" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^KnockKnock_.*.7z$")
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

# Image Info (DMG)
FILE="$OUTPUT/Spotlight/Spotlight_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	/usr/bin/hdiutil imageinfo "$FILE" > "$OUTPUT/Spotlight/ImageInfo.txt"
fi

# Creating Secure Archive (DMG)
FILE="$OUTPUT/Spotlight/Spotlight_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	cd "$OUTPUT/Spotlight"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "Spotlight_$SerialNumber.dmg.7z" "$FILE" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
	
	# Cleaning up 
	/bin/rm -rf "$FILE"
fi

# Creating Secure Archive
if [[ -d "$OUTPUT/Spotlight/Spotlight_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/Spotlight/Spotlight_Data" )" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT/Spotlight"
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "Spotlight_$SerialNumber.7z" "Spotlight_Data/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/Spotlight" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Spotlight_$SerialNumber.7z$")
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

Notifications() {

# Notification Center shows your notifications in the right-top corner of your screen. 

# Stats
START_NOTIFICATIONS=$(/bin/date +%s)

# Collecting Notification Center Database Files (Application Notifications)
echo "[Info]  Collecting Notification Center Database Files ..."

for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	# db
	FILE="/Users/$UserName/Library/Group Containers/group.com.apple.usernoted/db2/db" # macOS Sequoia (2024)
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/Notifications/Notifications_Data/$UserName/Database"
		/bin/cp "$FILE" "$OUTPUT/Notifications/Notifications_Data/$UserName/Database/db"
	fi

	# db-shm
	FILE="/Users/$UserName/Library/Group Containers/group.com.apple.usernoted/db2/db-shm" # Sequoia (2024)
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/Notifications/Notifications_Data/$UserName/Database"
		/bin/cp "$FILE" "$OUTPUT/Notifications/Notifications_Data/$UserName/Database/db-shm"
	fi

	# db-wal
	FILE="/Users/$UserName/Library/Group Containers/group.com.apple.usernoted/db2/db-wal" # Sequoia (2024)
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/Notifications/Notifications_Data/$UserName/Database"
		/bin/cp "$FILE" "$OUTPUT/Notifications/Notifications_Data/$UserName/Database/db-wal"
	fi
done

# GUI: System Settings > Notifications
# CLI: open "x-apple.systempreferences:com.apple.preference.notifications"

# Notification Center Preferences
# https://support.apple.com/en-my/guide/mac-help/mh40583/mac
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	# com.apple.ncprefs.plist
	FILE="/Users/$UserName/Library/Preferences/com.apple.ncprefs.plist" # Apple Binary Property List
	if [[ -f "$FILE" ]]; then
		/bin/mkdir -p "$OUTPUT/Notifications/Notifications_Data/$UserName/Preferences/Binary"
		/bin/mkdir -p "$OUTPUT/Notifications/Notifications_Data/$UserName/Preferences/XML"
		/bin/cp "$FILE" "$OUTPUT/Notifications/Notifications_Data/$UserName/Preferences/Binary/com.apple.ncprefs.plist"
		/usr/bin/plutil -convert xml1 "$FILE" -o "$OUTPUT/Notifications/Notifications_Data/$UserName/Preferences/XML/com.apple.ncprefs.plist"
		/usr/bin/plutil -p "$FILE" > "$OUTPUT/Notifications/Notifications_Data/$UserName/Preferences/com.apple.ncprefs.txt"
		COUNT=$(/usr/libexec/PlistBuddy -c "Print :apps" "$FILE" | /usr/bin/grep -c "bundle-id")
		echo "[Info]  $COUNT Bundle Identifier found" > "$OUTPUT/Notifications/Notifications_Data/$UserName/Preferences/Bundle-Identifier.txt"
	fi
done

# XML
for UserName in $(/usr/bin/dscl . list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}')
do
	# Notification Center Database
	DB_PATH="/Users/$UserName/Library/Group Containers/group.com.apple.usernoted/db2/db" # macOS Sequoia (2024)

	if [[ -f "$DB_PATH" ]]; then

		/bin/mkdir -p "$OUTPUT/Notifications/Notifications_Data/$UserName/Database/XML"

		# Version
		VERSION=$(/usr/bin/sqlite3 -readonly "$DB_PATH" "SELECT value FROM 'dbinfo' WHERE key LIKE 'version'")
		BUILD=$(/usr/bin/sqlite3 -readonly "$DB_PATH" "SELECT value FROM 'dbinfo' WHERE key LIKE 'build'")
		echo "[Info]  Notification Center Database v$VERSION (Build: $BUILD)" > "$OUTPUT/Notifications/Notifications_Data/$UserName/Version.txt"

		# Compatible Version
		CompatibleVersion=$(/usr/bin/sqlite3 -readonly "$DB_PATH" "SELECT value FROM 'dbinfo' WHERE key LIKE 'compatibleVersion'")
		echo "[Info]  Compatible Version: $CompatibleVersion" > "$OUTPUT/Notifications/Notifications_Data/$UserName/CompatibleVersion.txt"

		# Count
		COUNT=$(/usr/bin/sqlite3 -readonly "$DB_PATH" "SELECT count(*) FROM 'record'")
		echo "[Info]  $COUNT Notification(s) found ($UserName)"

		# Extract Data (Binary Blob Data as Hex)
		if [[ $COUNT -gt 0 ]]; then
			SQL_QUERY="SELECT rec_id, hex(data) FROM record;"
			SQL_DATA=$(/usr/bin/sqlite3 -readonly "$DB_PATH" "$SQL_QUERY")

			# Convert Hex to Binary and then to Plist format
			echo "$SQL_DATA" | while read -r DATA; do
				RECORD_ID=$(echo "$DATA" | /usr/bin/awk -F '|' '{ print $1 }')
				HEX_DATA=$(echo "$DATA" | /usr/bin/awk -F '|' '{ print $2 }')
				echo "$HEX_DATA" | /usr/bin/xxd -r -p - | /usr/bin/plutil -convert xml1 - -o "$OUTPUT/Notifications/Notifications_Data/$UserName/Database/XML/$RECORD_ID.plist"
			done
		fi
	fi
done

# Creating Secure Archive
if [[ -d "$OUTPUT/Notifications/Notifications_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/Notifications/Notifications_Data" )" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT/Notifications"
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "Notifications_$SerialNumber.7z" "Notifications_Data/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/Notifications" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Notifications_.*.7z$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/Notifications/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Notifications Archive ..."
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
FOLDER="$OUTPUT/Notifications/Notifications_Data"
if [[ -d "$FOLDER" ]]; then
	/bin/rm -rf "$FOLDER"
fi

# Stats
END_NOTIFICATIONS=$(/bin/date +%s)
ELAPSED_TIME_NOTIFICATIONS=$(($END_NOTIFICATIONS - $START_NOTIFICATIONS))
echo "Notification Center Database Collection: $(($ELAPSED_TIME_NOTIFICATIONS/60)) min $(($ELAPSED_TIME_NOTIFICATIONS%60)) sec" >> "$OUTPUT"/Stats.txt

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
DMG="$OUTPUT/RecentItems/RecentItems_Data/RecentItems_$SerialNumber.dmg"
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

# Image Info (DMG)
FILE="$OUTPUT/RecentItems/RecentItems_Data/RecentItems_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	/usr/bin/hdiutil imageinfo "$FILE" > "$OUTPUT/RecentItems/ImageInfo.txt"
fi

# Creating Secure Archive (DMG)
FILE="$OUTPUT/RecentItems/RecentItems_Data/RecentItems_$SerialNumber.dmg"
if [[ -f "$FILE" ]]; then
	cd "$OUTPUT/RecentItems"
	"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "RecentItems_$SerialNumber.dmg.7z" "$FILE" > /dev/null 2>&1
	cd "$SCRIPT_DIR"
	
	# Cleaning up 
	/bin/rm -rf "$FILE"
fi

# Creating Secure Archive
if [[ -d "$OUTPUT/RecentItems/RecentItems_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/RecentItems/RecentItems_Data" )" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT/RecentItems"
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "RecentItems_$SerialNumber.7z" "RecentItems_Data/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/RecentItems" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^RecentItems_$SerialNumber.7z$")
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
		echo "[Info]  File Integrity (TrueTree): OK"
	else
		echo -e "\033[91m[ALERT] File Integrity (TrueTree): FAILURE\033[0m"
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

# Creating Secure Archive
if [[ -d "$OUTPUT/TrueTree/TrueTree_Data" ]]; then
	if [[ -n "$( ls -A "$OUTPUT/TrueTree/TrueTree_Data" )" ]]; then
		echo "[Info]  Preparing Secure Archive Container ..."
		cd "$OUTPUT/TrueTree"
		"$SEVENZIP" a -mx5 -mhe=on "-p$ARCHIVE_PASSWORD" -t7z "TrueTree_$SerialNumber.7z" "TrueTree_Data/*" > /dev/null 2>&1
		cd "$SCRIPT_DIR"
	fi
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/TrueTree" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^TrueTree_.*.7z$")
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
/bin/cat "$OUTPUT"/screenlog-draft.txt | /usr/bin/sed -e $'s/\x1b//g' | /usr/bin/sed -e $'s/\x07//g' | /usr/bin/sed -e 's/\[3J//g' | /usr/bin/sed -e 's/\[H//g' | /usr/bin/sed -e 's/\[2J//g' | /usr/bin/sed -e 's/\[32m//g' | /usr/bin/sed -e 's/\[91m//g' | /usr/bin/sed -e 's/\[93m//g' | /usr/bin/sed -e 's/\[0m//g' | /usr/bin/sed -e 's/\[?1034h//g' > "$OUTPUT"/screenlog.txt 2> /dev/null
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
	Verify_7zz
	Output
	Aftermath_Analysis
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-b|--btm)
	{
	Header
	Check_Admin
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
	Output
	BasicInfo
	Spotlight
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-n|--notifications)
	{
	Header
	Check_Admin
	Verify_7zz
	Output
	BasicInfo
	Notifications
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-p|--processes)
	{
	Header
	Check_Admin
	Verify_7zz
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
	Verify_7zz
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
	Verify_7zz
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
	Notifications
	TrueTree
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-h|--help|\?)
	Header
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
	Usage
	;;
esac
exit 0

#############################################################
#############################################################
