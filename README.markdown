# Virus Total Context Menu - Right click on a file to scan it.

### Features
* Based on VirusTotal.NET (https://github.com/Genbox/VirusTotal.NET) to get reports and scanning the files.

### How to use it

1. Change appsettings.json and put in your Virus Total API key.
2. Compile the project using Virusl Studio 2017 or the .NET Core 2.0 command line tools
3. Run the resulting application as Administrator to register the right click context menu. Run it again to unregister.

### Notes
* You can use the "--register" and "--unregister" command line arguments as well
* Virus Total limits the number of requests to 4 per minute.
* Virus Total also limits the file size to 32 MB.