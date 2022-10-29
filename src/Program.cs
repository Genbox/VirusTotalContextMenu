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
    private const string MenuText = "VT Scan";

    public static async Task Main(string[] args)
    {
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
                Console.WriteLine("An error happened:");
                Console.WriteLine(e);
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
        if (args.Length == 0)
            args = FileShellExtension.IsRegistered(FileType, KeyName) ? new[] { "--unregister" } : new[] { "--register" };

        // register
        if (string.Equals(args[0], "--register", StringComparison.OrdinalIgnoreCase))
        {
            RestartBinaryAsAdminIfRequired();

            // full path to self, %L is placeholder for selected file
            string? path = Environment.ProcessPath;
            string menuCommand = $"\"{path}\" \"%L\"";

            // register the context menu
            FileShellExtension.Register(FileType, KeyName, MenuText, menuCommand);

            Console.WriteLine("The '{0}' shell extension was registered.", KeyName);
            Console.WriteLine("Press a key to continue");
            Console.ReadKey();

            return true;
        }

        // unregister
        if (string.Equals(args[0], "--unregister", StringComparison.OrdinalIgnoreCase))
        {
            RestartBinaryAsAdminIfRequired();

            // unregister the context menu
            FileShellExtension.Unregister(FileType, KeyName);

            Console.WriteLine("The '{0}' shell extension was unregistered.", KeyName);
            Console.WriteLine("Press a key to continue");
            Console.ReadKey();

            return true;
        }

        // command line did not contain an action
        return false;
    }

    private static void OpenUrl(string url)
    {
        url = url.Replace("&", "^&");
        using Process? p = Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
    }

    private static void RestartBinaryAsAdminIfRequired()
    {
        if (UacHelper.IsProcessElevated)
            return;

        Console.WriteLine("You have to run as admin to register or unregister the context menu.");
        Console.WriteLine("Press a key to continue");
        Console.ReadKey();
        Environment.Exit(0);
    }

    /// <summary>
    /// We use this instead of a manifest to only elevate the user to admin when needed.
    /// </summary>
    //private static void RestartBinaryAsAdminIfRequired(string[] args)
    //{
    //    if (!UacHelper.IsProcessElevated)
    //    {
    //        Process p = new Process();
    //        p.StartInfo.FileName = Assembly.GetEntryAssembly().Location;
    //        p.StartInfo.Arguments = string.Join(" ", args);
    //        p.StartInfo.Verb = "runAs";
    //        p.Start();

    //        Environment.Exit(0);
    //    }
    //}

    private static async Task VirusScanFile(string filePath)
    {
        JObject jObj = JObject.Parse(await File.ReadAllTextAsync("appsettings.json"));
        string? key = jObj.GetValue("apikey")?.ToString();

        if (string.IsNullOrWhiteSpace(key) || key.Length != 64)
        {
            Console.WriteLine("Invalid API key. Did you remember to change appsettings.json?");
            Console.WriteLine("Press a key to continue");
            Console.ReadKey();
            return;
        }

        using VirusTotal virusTotal = new VirusTotal(key);
        virusTotal.UseTLS = true;

        FileInfo info = new FileInfo(filePath);

        if (!info.Exists)
            return;

        //Check if the file has been scanned before.
        string fileName = Path.GetFileName(filePath);

        Console.WriteLine($"Getting report for {fileName}");
        FileReport report = await virusTotal.GetFileReportAsync(info);

        if (report == null || report.ResponseCode != FileReportResponseCode.Present)
        {
            Console.WriteLine($"No report for {fileName} - sending file to VT");

            try
            {
                ScanResult result = await virusTotal.ScanFileAsync(info);

                Console.WriteLine($"Opening {result.Permalink}");
                OpenUrl(result.Permalink);
            }
            catch (RateLimitException)
            {
                Console.WriteLine("Virus Total limits the number of calls you can make to 4 calls each 60 seconds.");
            }
            catch (SizeLimitException)
            {
                Console.WriteLine("Virus Total limits the filesize to 32 MB.");
            }
        }
        else
        {
            Console.WriteLine($"Opening {report.Permalink}");
            OpenUrl(report.Permalink);
        }
    }
}