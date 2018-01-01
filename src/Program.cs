using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using VirusTotalNET;
using VirusTotalNET.Exceptions;
using VirusTotalNET.ResponseCodes;
using VirusTotalNET.Results;

namespace VirusTotalContextMenu
{
    public static class Program
    {
        // file type to register
        const string FileType = "*";

        // context menu name in the registry
        const string KeyName = "VirusTotal Context Menu";

        // context menu text
        const string MenuText = "VT Scan";

        static async Task Main(string[] args)
        {
            var builder = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json");

            Configuration = builder.Build();

            // process register or unregister commands
            if (!ProcessCommand(args))
            {
                // invoked from shell, process the selected file
                await VirusScanFile(args[0]);
            }
        }

        public static IConfigurationRoot Configuration { get; set; }

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
            if ("--register".Equals(args[0], StringComparison.OrdinalIgnoreCase))
            {
                RestartBinaryAsAdminIfRequired();

                // full path to self, %L is placeholder for selected file
                string menuCommand = string.Format("\"{0}\" \"%L\"", Assembly.GetEntryAssembly().Location);

                // register the context menu
                FileShellExtension.Register(FileType, KeyName, MenuText, menuCommand);

                Console.WriteLine("The '{0}' shell extension was registered.", KeyName);
                Console.WriteLine("Press a key to continue");
                Console.ReadKey();

                return true;
            }

            // unregister
            if ("--unregister".Equals(args[0], StringComparison.OrdinalIgnoreCase))
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
            VirusTotal virusTotal = new VirusTotal(Configuration["apikey"]);
            virusTotal.UseTLS = true;

            FileInfo fileInfo = new FileInfo(filePath);

            if (!fileInfo.Exists)
                return;

            //Check if the file has been scanned before.
            Console.WriteLine("Getting report for " + Path.GetFileName(filePath));
            FileReport report = await virusTotal.GetFileReportAsync(fileInfo);

            if (report == null || report.ResponseCode != FileReportResponseCode.Present)
            {
                Console.WriteLine("No report for " + Path.GetFileName(filePath) + " - sending file to VT");

                try
                {
                    ScanResult result = await virusTotal.ScanFileAsync(fileInfo);

                    Console.WriteLine("Opening report for " + Path.GetFileName(filePath));
                    Process.Start(result.Permalink);
                }
                catch (RateLimitException)
                {
                    Console.WriteLine("Virus Total limits the number of calls you can make to 4 calls each 60 seconds.");
                }
                catch (SizeLimitException)
                {
                    Console.WriteLine("Virus Total limits the filesize to 32 MB.", "File too large");
                }
            }
            else
            {
                Console.WriteLine("Opening report for " + Path.GetFileName(filePath));
                Process.Start(report.Permalink);
            }
        }
    }
}