#!/bin/bash
#
# macOS-Collector
#
# @author: 		Martin Willing
# @copyright: 	Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact: 	Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url: 		https://lethal-forensics.com/
# @date: 		2025-11-16
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
#
# Usage:
# sudo bash macos-collector.sh [OPTION]
#
# Example:
# sudo bash macos-collector.sh --collect
#
# Collect forensic artifacts from a compromised macOS endpoint using Aftermath.
#
# Example:
# sudo bash macos-collector.sh --analyze
#
# Analyze previous collected Aftermath archive file.
#
# Example:
# sudo bash macos-collector.sh --ds_store
#
# Collect .DS_Store files from a macOS endpoint.
#
# Example:
# sudo bash macos-collector.sh --fsevents
#
# Collect FSEvents Data from a macOS endpoint.
#
#
# Dependencies:
#
# Aftermath v2.3.0 (2025-09-24)
# https://github.com/jamf/aftermath
# https://github.com/stuartjash/aftermath
# https://github.com/jamf/jamfprotect/tree/main/soar_playbooks/aftermath_collection
#
#
# Tested on macOS Sequoia 26.1.0
#
#############################################################
#############################################################

# Declarations
SCRIPT_DIR=$( /usr/bin/cd "$( /usr/bin/dirname "${BASH_SOURCE[0]}" )" && /bin/pwd )
TIMESTAMP=$(/bin/date '+%FT%H%M%S') # YYYY-MM-DDThhmmss

# Aftermath Binary
AFTERMATH="$SCRIPT_DIR/tools/Aftermath/aftermath"
FILEHASH="A0668EB91650513F40CE8753A277E0E0"

#############################################################
#############################################################

Header()

{
clear
echo "macOS-Collector - Automated Collection of macOS Forensic Artifacts for DFIR"
echo "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
echo ""

/bin/cat << "EOF"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
EOF

echo "$LOGO"

START_TIME=$SECONDS

}

#############################################################
#############################################################

Usage() 

{
Header
echo "Usage: $0 [OPTION]"
echo ""
echo "Options:"
echo "-c / --collect         Scan and collect forensic artifacts w/ Aftermath (Step #1)"
echo "-a / --analyze         Analyze previous collected Aftermath archive (Step #2)"
echo "-d / --ds_store        Collect .DS_Store Files"
echo "-f / --fsevents        Collect FSEvents Data"
echo "-l / --logs            Collecting Apple Unified Logs (AUL)"
echo "-h / --help            Show this help message"
echo ""
exit 0
}

Usage2() 

{
echo "Usage: $0 [OPTION]"
echo ""
echo "Options:"
echo "-c / --collect         Scan and collect forensic artifacts w/ Aftermath (Step #1)"
echo "-a / --analyze         Analyze previous collected Aftermath archive (Step #2)"
echo "-d / --ds_store        Collect .DS_Store Files"
echo "-f / --fsevents        Collect FSEvents Data"
echo "-l / --logs            Collecting Apple Unified Logs (AUL)"
echo "-h / --help            Show this help message"
echo ""
exit 0
}

#############################################################
#############################################################

Check()

{
	# Check if the script is running with root privileges
	if [[ $EUID -ne 0 ]]; then 
		echo -e "\033[91m[Error] macos-collector.sh needs be run with root privileges.\033[0m"
		echo -e "\033[91m        sudo bash macos-collector.sh --collect\033[0m"
		echo ""
		exit 1
	fi

	# Check if Terminal application has full disk access (FDA)
	if ! plutil -lint /Library/Preferences/com.apple.TimeMachine.plist >/dev/null ; then
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

Output()

{

# Check if output folder exists
OUTPUT="$SCRIPT_DIR/output/$(/bin/hostname)/$TIMESTAMP-macos-collector"
if [ -d "$OUTPUT" ]
	then
		/bin/rm -r "$OUTPUT"
	else
		/bin/mkdir -p "$OUTPUT"
fi

}

#############################################################
#############################################################

Aftermath_Collection_DeepScan()

{

# Aftermath
# https://github.com/jamf/aftermath

# Note: Aftermath needs to be root, as well as have full disk access (FDA) in order to run. FDA can be granted to the Terminal application (or iTerm2) in which it is running.

# Check if Terminal application (or iTerm2) has full disk access (FDA)
# System Settings --> Privacy & Security --> Full Disk Access

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Stats
START_COLLECTION=$(/bin/date +%s)

# Host Name
HostName=$(/bin/hostname)
echo "[Info]  Host Name: $HostName"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType)

# Model Name
ModelName=$(echo "$SPHardwareDataType" | /usr/bin/grep "Model Name:" | /usr/bin/sed -e 's/.*Model Name: //')
echo "[Info]  Model Name: $ModelName"

# Model Identifier
ModelIdentifier=$(echo "$SPHardwareDataType" | /usr/bin/grep "Model Identifier:" | /usr/bin/sed -e 's/.*Model Identifier: //')
echo "[Info]  Model Identifier: $ModelIdentifier"

# CPU
Chip=$(/usr/sbin/sysctl  -n machdep.cpu.brand_string)
echo "[Info]  Chip: $Chip"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType)

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
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $2}')
	os_codename=(
	["10"]="Yosemite"
	["11"]="El Capitan"
	["12"]="Sierra"
	["13"]="High Sierra"
	["14"]="Mojave"
	["15"]="Catalina"
	)
else
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $1}')
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
# /usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.meta.plist" Version
FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" CFBundleShortVersionString)
	YARA=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($YARA YARA rules)"
fi

# sudo xprotect check
# sudo xprotect update

# XProtect Remediator (XPR)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist" CFBundleShortVersionString)
	echo "[Info]  XProtect Remediator Version: $VERSION"
fi

# Malware Removal Tool (MRT)
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" CFBundleShortVersionString)
	COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.")
	echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
fi

# Verify File Integrity
if [[ -s $(/bin/ls -A "$AFTERMATH") ]]; then
	MD5=$(/sbin/md5 "$AFTERMATH" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	if [ "$MD5" = "$FILEHASH" ]; then

		# Aftermath Version
		Version=$(sudo "$AFTERMATH" --version)
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
sudo "$AFTERMATH" -o "$OUTPUT"/Aftermath_Collection --deep --pretty > "$OUTPUT"/Aftermath_Collection/Aftermath-colored.txt 2> /dev/null

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/Aftermath_Collection | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Aftermath_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/Aftermath_Collection/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{print $5}')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Aftermath Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
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
sudo "$AFTERMATH" --cleanup > "$OUTPUT"/Aftermath_Collection/Cleanup.txt 2> /dev/null

# Cleaning Aftermath Logfile
/bin/cat -v "$OUTPUT"/Aftermath_Collection/Aftermath-colored.txt | /usr/bin/sed -e 's/\^\[//g' | /usr/bin/sed -e 's/\[0;[0-9]*m//g' > "$OUTPUT"/Aftermath_Collection/Aftermath.txt

# Stats
END_COLLECTION=$(/bin/date +%s)
ELAPSED_TIME_COLLECTION=$(($END_COLLECTION - $START_COLLECTION))
echo "Aftermath Collection w/ Deep Scan: $(($ELAPSED_TIME_COLLECTION/60)) min $(($ELAPSED_TIME_COLLECTION%60)) sec" > "$OUTPUT"/Stats.txt

}

#############################################################

Aftermath_Analysis()

{

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
		MD5=$(/sbin/md5 "$AFTERMATH" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		if [ "$MD5" = "$FILEHASH" ]; then

			# Aftermath Version
			Version=$(sudo "$AFTERMATH" --version)
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
	sudo "$AFTERMATH" --analyze "$ARCHIVE_FILE" --pretty -o "$OUTPUT"/Aftermath_Analysis > "$OUTPUT"/Aftermath_Analysis/Aftermath-colored.txt 2> /dev/null

	# Archive Name
	ARCHIVE=$(/bin/ls -l "$OUTPUT"/Aftermath_Analysis | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^Aftermath_Analysis_.*.zip$")
	echo "[Info]  Archive Name: $ARCHIVE"

	# Archive Size
	FILE="$OUTPUT/Aftermath_Analysis/$ARCHIVE"
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{print $5}')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
	echo "[Info]  Archive Size: $FILESIZE"

	# MD5 Calculation
	if [[ -s $(/bin/ls -A "$FILE") ]]; then
		echo "[Info]  Calculating MD5 checksum of Aftermath Archive ..."
		MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
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

DS_Store()

{

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Stats
START_DSStore=$(/bin/date +%s)

# Host Name
HostName=$(/bin/hostname)
echo "[Info]  Host Name: $HostName"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType)

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
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $2}')
	os_codename=(
	["10"]="Yosemite"
	["11"]="El Capitan"
	["12"]="Sierra"
	["13"]="High Sierra"
	["14"]="Mojave"
	["15"]="Catalina"
	)
else
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $1}')
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
FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" CFBundleShortVersionString)
	YARA=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($YARA YARA rules)"
fi

# XProtect Remediator (XPR)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist" CFBundleShortVersionString)
	echo "[Info]  XProtect Remediator Version: $VERSION"
fi

# Malware Removal Tool (MRT)
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" CFBundleShortVersionString)
	COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.")
	echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
fi

# System Integrity Protection (SIP)
if /usr/bin/csrutil status | /usr/bin/grep -q "System Integrity Protection status: enabled.";then
	echo "[Info]  System Integrity Protection (SIP) is enabled."
fi

# Desktop Service Store Files
/bin/mkdir -p "$OUTPUT/DS_Store/DSStore_Data"

# Find all .DS_Store Files in the root directory
echo "[Info]  Enumerating Desktop Service Store Files [approx. 1-2 min] ..."
sudo /usr/bin/find / -name ".DS_Store" -type f > "$OUTPUT/DS_Store/Files.txt" 2> "$OUTPUT/DS_Store/Error.txt"

# Count Desktop Service Store Files (which can be collected)
FILES=$(/bin/cat "$OUTPUT/DS_Store/Files.txt" | /usr/bin/grep -c ^)
echo "[Info]  $FILES DS_Store Files found"

# Copy and preserve Apple Extended Attributes w/ Rsync (Archive Mode)
echo "[Info]  Collecting Desktop Service Store Files ..."
if [ -s "$OUTPUT/DS_Store/Files.txt" ];then
	while /usr/bin/read FILE
	do
		sudo /usr/bin/rsync -avR "$FILE" "$OUTPUT/DS_Store/DSStore_Data/" >> "$OUTPUT/DS_Store/Collection.txt"
	done < "$OUTPUT/DS_Store/Files.txt"
fi

# Creating Archive File
if [ -d "$OUTPUT/DS_Store/DSStore_Data" ];then
	cd "$OUTPUT/DS_Store"
	/usr/bin/zip -q -r "DSStore_$SerialNumber.zip" DSStore_Data
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT/DS_Store" | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^DSStore_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/DS_Store/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{print $5}')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of DS_Store Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
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
if [ -d "$FOLDER" ];then
/bin/rm -rf "$FOLDER"
fi

# Stats
END_DSStore=$(/bin/date +%s)
ELAPSED_TIME_DSStore=$(($END_DSStore - $START_DSStore))
echo ".DS_Store Collection: $(($ELAPSED_TIME_DSStore/60)) min $(($ELAPSED_TIME_DSStore%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

FSEvents()

{

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Stats
START_FSEVENTS=$(/bin/date +%s)

# Host Name
HostName=$(/bin/hostname)
echo "[Info]  Host Name: $HostName"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType)

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
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $2}')
	os_codename=(
	["10"]="Yosemite"
	["11"]="El Capitan"
	["12"]="Sierra"
	["13"]="High Sierra"
	["14"]="Mojave"
	["15"]="Catalina"
	)
else
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $1}')
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
FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" CFBundleShortVersionString)
	YARA=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($YARA YARA rules)"
fi

# XProtect Remediator (XPR)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist" CFBundleShortVersionString)
	echo "[Info]  XProtect Remediator Version: $VERSION"
fi

# Malware Removal Tool (MRT)
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" CFBundleShortVersionString)
	COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.")
	echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
fi

# FSEvents
echo "[Info]  Collecting File System Events ..."
/bin/mkdir -p "$OUTPUT/FSEvents/FSEvents_Data"

# Count GZIP Files w/ thousands separator
Total=$(sudo /usr/bin/find "/System/Volumes/Data/.fseventsd/" -type f ! -name 'fseventsd-uuid' | wc -l | awk '{print $1}')
Count=$(/usr/bin/printf "%'d\n" $Total | tr -s "," ".")
echo "[Info]  $Count FSEvent Files found"

# Collecting FSEvents
SOURCE="/System/Volumes/Data/.fseventsd/"
DESTINATION="$OUTPUT/FSEvents/FSEvents_Data"
if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
	sudo /usr/bin/rsync -avE "$SOURCE" "$DESTINATION" >> "$OUTPUT/FSEvents/Collection.txt"
fi

# Creating Archive File
if [ -d "$OUTPUT/FSEvents/FSEvents_Data" ];then
	cd "$OUTPUT/FSEvents"
	/usr/bin/zip -q -r "FSEvents_$SerialNumber.zip" FSEvents_Data
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/FSEvents | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^FSEvents_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/FSEvents/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{print $5}')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of FSEvents Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
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
if [ -d "$FOLDER" ];then
	/bin/rm -rf "$FOLDER"
fi

# Stats
END_FSEVENTS=$(/bin/date +%s)
ELAPSED_TIME_FSEVENTS=$(($END_FSEVENTS - $START_FSEVENTS))
echo "FSEvents Collection: $(($ELAPSED_TIME_FSEVENTS/60)) min $(($ELAPSED_TIME_FSEVENTS%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

UnifiedLogs()

{

# Apple Unified Logs (AUL)

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Stats
START_AUL=$(/bin/date +%s)

# Host Name
HostName=$(/bin/hostname)
echo "[Info]  Host Name: $HostName"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType)

# Model Name
ModelName=$(echo "$SPHardwareDataType" | /usr/bin/grep "Model Name:" | /usr/bin/sed -e 's/.*Model Name: //')
echo "[Info]  Model Name: $ModelName"

# Model Identifier
ModelIdentifier=$(echo "$SPHardwareDataType" | /usr/bin/grep "Model Identifier:" | /usr/bin/sed -e 's/.*Model Identifier: //')
echo "[Info]  Model Identifier: $ModelIdentifier"

# CPU
Chip=$(/usr/sbin/sysctl -n machdep.cpu.brand_string)
echo "[Info]  Chip: $Chip"

# SPHardwareDataType
SPHardwareDataType=$(/usr/sbin/system_profiler SPHardwareDataType)

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
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $2}')
	os_codename=(
	["10"]="Yosemite"
	["11"]="El Capitan"
	["12"]="Sierra"
	["13"]="High Sierra"
	["14"]="Mojave"
	["15"]="Catalina"
	)
else
	os_num=$(echo "$PRODUCTVERSION" | /usr/bin/awk -F '[.]' '{print $1}')
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
FILE="/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist" CFBundleShortVersionString)
	YARA=$(/bin/cat "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/XProtect.yara" | /usr/bin/grep -c "^rule")
	echo "[Info]  XProtect Version: $VERSION ($YARA YARA rules)"
fi

# XProtect Remediator (XPR)
FILE="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist" CFBundleShortVersionString)
	echo "[Info]  XProtect Remediator Version: $VERSION"
fi

# Malware Removal Tool (MRT)
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" # Catalina 10.15
if [ -f "$FILE" ];then
	VERSION=$(/usr/bin/defaults read "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" CFBundleShortVersionString)
	COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.")
	echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
fi

# Gather system logs into a log archive (.logarchive)
echo "[Info]  Collecting Unified Logs (.logarchive) ..."
/bin/mkdir -p "$OUTPUT/UnifiedLogs/"
LOGARCHIVE="$OUTPUT/UnifiedLogs/system_logs.logarchive"
sudo /usr/bin/log collect --output "$LOGARCHIVE" > /dev/null

# Creating Archive File
if [ -d "$LOGARCHIVE" ];then
	echo "[Info]  Compressing Unified Logs (.zip) ..."
	cd "$OUTPUT/UnifiedLogs"
	/usr/bin/zip -q -r "UnifiedLogs_$SerialNumber.zip" system_logs.logarchive
	cd "$SCRIPT_DIR"
fi

# Archive Name
ARCHIVE=$(/bin/ls -l "$OUTPUT"/UnifiedLogs | /usr/bin/awk '{ print $9 }' | /usr/bin/grep "^UnifiedLogs_.*.zip$")
echo "[Info]  Archive Name: $ARCHIVE"

# Archive Size
FILE="$OUTPUT/UnifiedLogs/$ARCHIVE"
BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{print $5}')
FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
echo "[Info]  Archive Size: $FILESIZE"

# MD5 Calculation
if [[ -s $(/bin/ls -A "$FILE") ]]; then
	echo "[Info]  Calculating MD5 checksum of Unified Logs Archive ..."
	MD5=$(/sbin/md5 "$FILE" | /usr/bin/awk '{print $4}' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	echo "[Info]  MD5 Hash: $MD5"
fi

# Create Time
BIRTH=$(TZ= /usr/bin/stat -f "%SB" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Create Time: $BIRTH UTC"

# Last Modified Time
MODIFY=$(TZ= /usr/bin/stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$FILE")
echo "[Info]  Last Modified Time: $MODIFY UTC"

# Show system logging statistics
if [ -d "$LOGARCHIVE" ];then
	echo "[Info]  Creating System Logging Statistics ..."
	sudo /usr/bin/log stats --archive "$LOGARCHIVE" > "$OUTPUT"/UnifiedLogs/Statistics.txt
fi

# Cleaning up
if [ -d "$LOGARCHIVE" ];then
	/bin/rm -r "$LOGARCHIVE"
fi

# Stats
END_AUL=$(/bin/date +%s)
ELAPSED_TIME_AUL=$(($END_AUL - $START_AUL))
echo "Unified Logs Collection: $(($ELAPSED_TIME_AUL/60)) min $(($ELAPSED_TIME_AUL%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

Finished()

{

echo ""
echo "FINISHED!"

ELAPSED_TIME=$(($SECONDS - $START_TIME))
echo "Overall analysis duration: $(($ELAPSED_TIME/60)) min $(($ELAPSED_TIME%60)) sec"

}

#############################################################
#############################################################

Footer()

{

# screenlog.txt
/bin/cp "$SCRIPT_DIR"/screenlog-draft.txt "$OUTPUT"/
/bin/cat "$OUTPUT"/screenlog-draft.txt > "$OUTPUT"/screenlog-colored.txt
/bin/cat "$OUTPUT"/screenlog-draft.txt | /usr/bin/sed -e $'s/\x1b//g' | /usr/bin/sed -e $'s/\x07//g' | /usr/bin/sed -e 's/\[3J//g' | /usr/bin/sed -e 's/\[H//g' | /usr/bin/sed -e 's/\[2J//g' | /usr/bin/sed -e 's/\[91m//g' | /usr/bin/sed -e 's/\[0m//g' | /usr/bin/sed -e 's/\[?1034h//g' > "$OUTPUT"/screenlog.txt 2> /dev/null
/bin/rm "$SCRIPT_DIR"/screenlog-draft.txt
/bin/rm "$OUTPUT"/screenlog-draft.txt

# Change permissions of output files
LoggedInUser=$(/usr/bin/stat -f %Su /dev/console)
sudo /usr/sbin/chown -R $LoggedInUser "$SCRIPT_DIR/output/"

}

#############################################################
#############################################################

# Main

case $1 in
	-a|--analyze)
	{
	Header
	Check
	Output
	Aftermath_Analysis
	Finished
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-c|--collect)
	{
	Header
	Check
	Output
	Aftermath_Collection_DeepScan
	Finished
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-d|--ds_store)
	{
	Header
	Check
	Output
	DS_Store
	Finished
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-f|--fsevents)
	{
	Header
	Check
	Output
	FSEvents
	Finished
	Footer
	} 2>&1 | /usr/bin/tee screenlog-draft.txt
	;;
	-l|--logs)
	{
	Header
	Check
	Output
	UnifiedLogs
	Finished
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

#############################################################
#############################################################
