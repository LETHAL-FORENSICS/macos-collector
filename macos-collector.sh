#!/bin/bash
#
# macOS-Collector
#
# @author: 		Martin Willing
# @copyright: 	Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact: 	Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url: 		https://lethal-forensics.com/
# @date: 		2025-12-07
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
# https://github.com/stuartjash/aftermath
# https://github.com/jamf/jamfprotect/tree/main/soar_playbooks/aftermath_collection
#
# KnockKnock v3.1.0 (2025-01-05)
# https://objective-see.com/products/knockknock.html
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
echo "-b / --btm             Collect BTM Dump File (Background Task Management)"
echo "-d / --ds_store        Collect .DS_Store Files"
echo "-f / --fsevents        Collect FSEvents Data"
echo "-k / --knockknock      Scan Live System w/ KnockKnock (Persistence)"
echo "-l / --logs            Collect Apple Unified Logs (AUL)"
echo "-m / --metadata        Collect Spotlight Database (Desktop Search Engine)"
echo "-s / --sysdiagnose     Collect Sysdiagnose Logs"
echo "-t / --triage          Collect ALL supported macOS Forensic Artifacts"
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
echo "-b / --btm             Collect BTM Dump File (Background Task Management)"
echo "-d / --ds_store        Collect .DS_Store Files"
echo "-f / --fsevents        Collect FSEvents Data"
echo "-k / --knockknock      Scan Live System w/ KnockKnock (Persistence)"
echo "-l / --logs            Collect Apple Unified Logs (AUL)"
echo "-m / --metadata        Collect Spotlight Database (Desktop Search Engine)"
echo "-s / --sysdiagnose     Collect Sysdiagnose Logs"
echo "-t / --triage          Collect ALL supported macOS Forensic Artifacts"
echo "-h / --help            Show this help message"
echo ""
exit 0
}

#############################################################
#############################################################

Check_Admin()

{
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

Check_FDA()

{
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
	# Time Duration
	START_TIME=$SECONDS

	# Check if output folder exists
	OUTPUT="$SCRIPT_DIR/output/$(/bin/hostname)/$TIMESTAMP-macos-collector"
	if [[ -d "$OUTPUT" ]]
		then
			/bin/rm -r "$OUTPUT"
		else
			/bin/mkdir -p "$OUTPUT"
	fi
}

#############################################################
#############################################################

BasicInfo()

{

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; /bin/date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

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
FILE="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist" # Catalina 10.15
if [[ -f "$FILE" ]]; then
	VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
	COUNT=$(/usr/bin/strings -a "/Library/Apple/System/Library/CoreServices/MRT.app/Contents/MacOS/MRT" | /usr/bin/grep -c "^OSX.")
	echo "[Info]  MRT Version: $VERSION ($COUNT Signatures)"
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

# Stats
START_COLLECTION=$(/bin/date +%s)

# Verify File Integrity
if [[ -s $(/bin/ls -A "$AFTERMATH") ]]; then
	MD5=$(/sbin/md5 "$AFTERMATH" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
	if [[ "$MD5" = "$FILEHASH" ]]; then

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
		MD5=$(/sbin/md5 "$AFTERMATH" | /usr/bin/awk '{ print $4 }' | /usr/bin/awk 'BEGIN { getline; print toupper($0) }')
		if [[ "$MD5" = "$FILEHASH" ]]; then

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

BTM_Dump()

{

# Background Task Management (BTM)

# Stats
START_BTM=$(/bin/date +%s)

# Collecting BTM Dump File (via Shared File List Tool)
echo "[Info]  Collecting BTM Dump File ..."
/bin/mkdir -p "$OUTPUT/BTM"
sudo /usr/bin/sfltool dumpbtm > "$OUTPUT/BTM/btm.txt"

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
sudo /usr/bin/find "/private/var/db/com.apple.backgroundtaskmanagement" -name "BackgroundItems-v*.btm" -type f > "$OUTPUT/BTM/Files.txt" 2> /dev/null
if [[ -s "$OUTPUT/BTM/Files.txt" ]]; then
	echo "[Info]  Collecting BTM Database File(s) ..."
	/bin/mkdir -p "$OUTPUT/BTM/BTM_Data"
	sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/BTM/Files.txt" / "$OUTPUT/BTM/BTM_Data" >> "$OUTPUT/BTM/Collection.txt" 2>&1
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
	/usr/bin/zip -q -r "BTM_$SerialNumber.zip" BTM_Data
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

DS_Store()

{

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
sudo /usr/bin/find / -name ".DS_Store" -type f > "$OUTPUT/DS_Store/Files.txt" 2> "$OUTPUT/DS_Store/Error.txt"

# Count Desktop Service Store Files w/ thousands separator
FILES=$(/bin/cat "$OUTPUT/DS_Store/Files.txt" | /usr/bin/grep -c ^)
COUNT=$(/usr/bin/printf "%'d\n" $FILES | /usr/bin/tr -s "," ".")
echo "[Info]  $COUNT DS_Store Files found"

# Copy and preserve Apple Extended Attributes w/ Rsync (Archive Mode)
echo "[Info]  Collecting Desktop Service Store Files ..."
if [[ -s "$OUTPUT/DS_Store/Files.txt" ]]; then
	sudo /usr/bin/rsync --recursive -av --files-from="$OUTPUT/DS_Store/Files.txt" / "$OUTPUT/DS_Store/DSStore_Data" >> "$OUTPUT/DS_Store/Collection.txt" 2>&1
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
	/usr/bin/zip -q -r "DSStore_$SerialNumber.zip" DSStore_Data
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

FSEvents()

{

# File System Events (FSEvents)

# Stats
START_FSEVENTS=$(/bin/date +%s)

# FSEvents
echo "[Info]  Collecting File System Events ..."
/bin/mkdir -p "$OUTPUT/FSEvents/FSEvents_Data"

# Count GZIP Files w/ thousands separator
Total=$(sudo /usr/bin/find "/System/Volumes/Data/.fseventsd/" -type f ! -name 'fseventsd-uuid' | wc -l | awk '{ print $1 }')
Count=$(/usr/bin/printf "%'d\n" $Total | /usr/bin/tr -s "," ".")
echo "[Info]  $Count FSEvent Files found"

# Collecting FSEvents
SOURCE="/System/Volumes/Data/.fseventsd/"
DESTINATION="$OUTPUT/FSEvents/FSEvents_Data"
if [[ -d "$SOURCE" ]] && [[ -n "$(/bin/ls -A "$SOURCE")" ]]; then
	sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" >> "$OUTPUT/FSEvents/Collection.txt"
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
	/usr/bin/zip -q -r "FSEvents_$SerialNumber.zip" FSEvents_Data
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

UnifiedLogs()

{

# Apple Unified Logs (AUL)

# Stats
START_AUL=$(/bin/date +%s)

# Gather system logs into a log archive (.logarchive)
echo "[Info]  Collecting Unified Logs (.logarchive) ..."
/bin/mkdir -p "$OUTPUT/UnifiedLogs/"
LOGARCHIVE="$OUTPUT/UnifiedLogs/system_logs.logarchive"
sudo /usr/bin/log collect --output "$LOGARCHIVE" > /dev/null 2>&1

# Creating Archive File
if [[ -d "$LOGARCHIVE" ]]; then
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
	sudo /usr/bin/log stats --archive "$LOGARCHIVE" > "$OUTPUT"/UnifiedLogs/Statistics.txt
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

Sysdiagnose()

{

# Sysdiagnose Logs Generation

# Stats
START_SYSDIAGNOSE=$(/bin/date +%s)

# Collecting Sysdiagnose Logs (System Diagnostic Information)
echo "[Info]  Collecting Sysdiagnose Logs [approx. 1-5 min] ..."
/bin/mkdir -p "$OUTPUT/Sysdiagnose/Sysdiagnose_Data"
sudo sysdiagnose -f "$OUTPUT/Sysdiagnose/Sysdiagnose_Data" -nbSu > "$OUTPUT/Sysdiagnose/Sysdiagnose.txt" 2>&1

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
		/usr/bin/zip -q -r "Sysdiagnose_$SerialNumber.zip" Sysdiagnose_Data
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

KnockKnock()

{

# Who's there? See what's persistently installed on your Mac.

# KnockKnock tells you who's there, querying your system for any software that leverages many of the myriad of persistence mechanisms (Persistence Enumerator).

# https://attack.mitre.org/tactics/TA0003/

# Stats
START_KNOCK=$(/bin/date +%s)

# Verify File Integrity
ExpectedTeamID="VBG97UB4TA" # Objective-See, LLC (VBG97UB4TA)
Application="$SCRIPT_DIR/tools/KnockKnock/KnockKnock.app"
TeamID=$(/usr/sbin/spctl --assess --type execute -vv "$Application" 2>&1 | awk '/origin=/ {print $NF }' | /usr/bin/tr -d '()')

if [[ "$TeamID" = "$ExpectedTeamID" ]]; then

	# KnockKnock Version
	FILE="$SCRIPT_DIR/tools/KnockKnock/KnockKnock.app/Contents/Info.plist"
	if [[ -f "$FILE" ]]; then
		VERSION=$(/usr/bin/defaults read "$FILE" CFBundleShortVersionString)
		echo "[Info]  KnockKnock Version: $VERSION"
		echo "[Info]  File Integrity: OK"
	fi
else
	echo -e "\033[91m[ALERT] File Integrity: FAILURE\033[0m"
	exit 1
fi

# Launch KnockKnock /wo VirusTotal
echo "[Info]  Scanning Live System w/ KnockKnock [approx. 1-2 min] ..."
/bin/mkdir -p "$OUTPUT"/KnockKnock/
cd tools/KnockKnock/
sudo ./KnockKnock.app/Contents/MacOS/KnockKnock -whosthere -verbose -skipVT > "$OUTPUT/KnockKnock/WhoIsThere-draft.json"
cd $SCRIPT_DIR

# Output
if [[ -s "$OUTPUT/KnockKnock/WhoIsThere-draft.json" ]]; then

	# JSON
	/bin/cat "$OUTPUT/KnockKnock/WhoIsThere-draft.json" | /usr/bin/tail -n 1 > "$OUTPUT/KnockKnock/WhoIsThere.json"

	# TXT
	/bin/cat "$OUTPUT/KnockKnock/WhoIsThere-draft.json" | /usr/bin/sed '$d' > "$OUTPUT/KnockKnock/KnockKnock.txt"
fi

# File Size
FILE="$OUTPUT/KnockKnock/WhoIsThere.json"
if [[ -s "$FILE" ]]; then
	BYTES=$(/bin/ls -l "$FILE" | /usr/bin/awk '{ print $5 }')
	FILESIZE=$(echo "$BYTES" | /usr/bin/awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.0f %s", $1, v[s] }')
	echo "[Info]  File Size (JSON): $FILESIZE ( $BYTES bytes )"
fi

# Results
FILE="$OUTPUT/KnockKnock/KnockKnock.txt"
if [[ -s "$FILE" ]]; then
	COUNT=$(/bin/cat "$FILE" | /usr/bin/grep "persistent items" | /usr/bin/awk '{ print $1 }')
	echo "[Info]  $COUNT Persistent Item(s) found"
	echo "[Info]  VirusTotal Results: N/A (Disabled)"
	echo "[!] VirusTotal Results: N/A (Disabled)" >> "$OUTPUT/KnockKnock/KnockKnock.txt"
fi

# Cleaning up
FILE="$OUTPUT/KnockKnock/WhoIsThere-draft.json"
if [[ -f "$FILE" ]]; then
	rm "$FILE"
fi

# Stats
END_KNOCK=$(/bin/date +%s)
ELAPSED_TIME_KNOCK=$(($END_KNOCK - $START_KNOCK))
echo "KnockKnock Scan: $(($ELAPSED_TIME_KNOCK/60)) min $(($ELAPSED_TIME_KNOCK%60)) sec" >> "$OUTPUT"/Stats.txt

}

#############################################################
#############################################################

Spotlight()

{

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
	sudo /usr/bin/defaults read "$FILE" > "$OUTPUT/Spotlight/VolumeConfiguration.txt"

	# Universal Unique Identifier (Data Volume)
	UUID=$(sudo /usr/bin/defaults read "$FILE" ConfigurationVolumeUUID)
	echo "[Info]  Data Volume: $UUID"
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
	sudo /usr/bin/rsync -av "$SOURCE" "$DESTINATION" >> "$OUTPUT/Spotlight/LogFile.txt"
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
		/usr/bin/zip -q -r "Spotlight_$SerialNumber.zip" Spotlight_Data
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
sudo /usr/bin/mdfind -onlyin / -name "kMDItemWhereFroms == *" > "$OUTPUT/Spotlight/Searches/kMDItemWhereFroms.txt"

# Count files with 'MDItemWhereFroms' attribute
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

Footer()

{

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
sudo /usr/sbin/chown -R $LoggedInUser "$SCRIPT_DIR/output/"

}

#############################################################
#############################################################

# Main

case $1 in
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
	Aftermath_Collection_DeepScan
	DS_Store
	FSEvents
	KnockKnock
	UnifiedLogs
	Sysdiagnose
	Spotlight
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
