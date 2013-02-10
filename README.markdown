# Virus Total Context Menu - Right click on a file to scan it.

### Features
* Based on VirusTotal.NET (https://github.com/Genbox/VirusTotal.NET) to get reports and scanning the files.

### How to use it

1. Compile the project by pressing CTRL + F5 in Visual Studio.
2. Doubleclick the 'VT Context Menu 1.0.exe' in the build folder
3. The context menu is now registered. Right click on a file and choose 'VT scan'
4. Wait for the program to communicate with Virus Total.
5. If the file was scanned by Virus Total already, you will see the existing results.
6. If the file is new, it will be uploaded to Virus Total, and you will have to wait for the results.

### Notes
* Run the application again to unregister the context menu.
* The application is 100% portable. You can move it where you like. If you move it, make sure to unregister and register again.
* Virus Total limits the number of requests to 4 per minute.
* Virus Total also limits the file size to 32 MB.