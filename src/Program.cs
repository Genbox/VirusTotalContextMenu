// Using VS2022 developer command prompt, navigate to the project folder
// Build with: dotnet build -c Release
// Collapse into a single binary with: dotnet publish -r win-x64
// Outputs to .\VirusTotalContextMenu\src\bin\Release\net9.0-windows10.0.26100.0\win-x64

using System.Diagnostics;
using Newtonsoft.Json.Linq;
using VirusTotalNet;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

namespace VirusTotalContextMenu;

public static class Program
{
    // file type to register
    private const string FileType = "*";

    // context menu name in the registry
    private const string KeyName = "VirusTotalContextMenu";

    // context menu text
    private const string MenuText = "VirusTotal Scan";

    public static async Task Main(string[] args)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        // process register or unregister commands
        if (!ProcessCommand(args))
        {
            // invoked from shell, process the selected file
            try
            {
                await VirusScanFile(args[0]);
            }
            catch (Exception e)
            {
                WriteError("Unknown error happened: " + e.Message);
            }
        }
    }

    /// <summary>
    /// Process command line actions (register or unregister).
    /// </summary>
    /// <param name="args">Command line arguments.</param>
    /// <returns>True if processed an action in the command line.</returns>
    private static bool ProcessCommand(string[] args)
    {
        // if no arguments, register or unregister the shell extension
        if (args.Length == 0)
            if (FileShellExtension.IsRegistered(FileType, KeyName))
            {
                if (DialogResult.Yes == MessageBox.Show("VirusTotal Context Menu is currently registered.\nUnregister it?", "VirusTotal Context Menu Registration", MessageBoxButtons.YesNo, MessageBoxIcon.Question))
                    args = new[] { "--unregister" };
                else
                    return true;
            }
            else
            {
                if (DialogResult.Yes == MessageBox.Show("VirusTotal Context Menu is currently not registered.\nRegister it?", "VirusTotal Context Menu Registration", MessageBoxButtons.YesNo, MessageBoxIcon.Question))
                    args = new[] { "--register" };
                else 
                    return true;
            }
        // original code had a toggle; replacing with explicit UI prompt
        //args = FileShellExtension.IsRegistered(FileType, KeyName) ? new[] { "--unregister" } : new[] { "--register" };

        // register
        if (string.Equals(args[0], "--register", StringComparison.OrdinalIgnoreCase))
        {

            // full path to self, %L is placeholder for selected file
            string? path = Environment.ProcessPath;
            if (null == path)
            {
                WriteError("Could not get the path to the executable.");
                return false;
            }
            string menuCommand = $"\"{path}\" \"%L\"";
            string iconPath = path; // Use the same path as the executable for the icon

            // register the context menu
            FileShellExtension.Register(FileType, KeyName, MenuText, menuCommand, iconPath);

            WriteSuccess($"The '{KeyName}' shell extension was registered.");
            return true;
        }

        // unregister
        if (string.Equals(args[0], "--unregister", StringComparison.OrdinalIgnoreCase))
        {
            // unregister the context menu
            FileShellExtension.Unregister(FileType, KeyName);

            WriteSuccess($"The '{KeyName}' shell extension was unregistered.");
            return true;
        }

        // command line did not contain an action
        return false;
    }

    private static void OpenUrl(string url, string prompt)
    {
        if (DialogResult.No == MessageBox.Show(prompt, "Open in Browser?", MessageBoxButtons.YesNo, MessageBoxIcon.Question))
        {
            return;
        }
        url = url.Replace("&", "^&");
        using Process? p = Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
    }

    private static void WriteError(string error)
    {
        MessageBox.Show(error, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private static void WriteSuccess(string message)
    {
        MessageBox.Show(message, "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    private static async Task VirusScanFile(string filePath)
    {
        string path = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath)!, "appsettings.json");

        //Console.WriteLine(path);

        JObject jObj = JObject.Parse(await File.ReadAllTextAsync(path));
        string? key = jObj.GetValue("apikey")?.ToString();

        if (string.IsNullOrWhiteSpace(key) || key.Length != 64)
        {
            WriteError("Invalid API key. Did you remember to change appsettings.json?");
            return;
        }

        Console.WriteLine("Scanning file: " + filePath + "...");

        using VirusTotal virusTotal = new VirusTotal(key);
        virusTotal.UseTLS = true;

        FileInfo info = new FileInfo(filePath);

        if (!info.Exists)
            return;

        //Check if the file has been scanned before.
        string fileName = Path.GetFileName(filePath);

        FileReport report = await virusTotal.GetFileReportAsync(info);

        if (report == null || report.ResponseCode != FileReportResponseCode.Present)
        {
            Console.Write($"No report for {fileName} - sending file to VT...");

            try
            {
                ScanResult result = await virusTotal.ScanFileAsync(info);

                if (result.Permalink.Length < 66)
                {
                    WriteError("Invalid scan ID received from VirusTotal: " + result.Permalink);
                    return;
                }
                string sha256 = result.Permalink.Substring(2, 64);
                OpenUrl("https://www.virustotal.com/gui/file/" + sha256 + "/detection/" + result.Permalink, "File new to VirusTotal. Open in browser?");
            }
            catch (RateLimitException)
            {
                MessageBox.Show("Virus Total limits the number of calls you can make to 4 calls each 60 seconds.", "Rate Exceeded", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (SizeLimitException)
            {
                MessageBox.Show("Virus Total limits the filesize to 32 MB.", "Size Limitation", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception e)
            {
                WriteError("Unknown error happened: " + e.Message);
            }
        }
        else
        {
            if (string.IsNullOrEmpty(report.Permalink))
            {
                WriteError("No permalink associated with the file. Cannot open URL.");
            }
            else
            {
                OpenUrl(report.Permalink, "Results: " + report.Positives + "/" + report.Total + " positive hits.\nLast scanned: " + report.ScanDate.ToString("dd MMM yyyy") + " (" + (DateTime.Now - report.ScanDate).Days + " days ago).\nOpen in browser?");
            }
        }
    }
}