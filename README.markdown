# Virus Total Context Menu - Right click on a file to scan it.

### Features
* Based on VirusTotal.NET (https://github.com/Genbox/VirusTotal.NET) to get reports and scanning the files.

### How to install
1. Download the latest release from https://github.com/Genbox/VirusTotalContextMenu/releases
2. Execute the installer and unpack to a destination of your choice.
3. Go to the folder you just unpacked and change the Virus Total API key in appsettings.json
4. Execute VirusTotalContextMenu.exe as Administrator to register the context menu extension.
5. Right-click any file and select "VT Scan". It opens a browser window with the results once finished.

### Notes
* You can use VirusTotalContextMenu.exe "--register" and "--unregister" command line arguments as well.
* Virus Total limits the number of requests to 4 per minute.
* Virus Total also limits the file size to 32 MB.
* It sends your file to Virus Total if they don't already have it.