using System;
using System.Configuration;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using VirusTotalNET;
using VirusTotalNET.Objects;

[assembly: CLSCompliant(true)]
namespace VirusTotalContextMenu
{
    static class Program
    {
        // file type to register
        const string FileType = "*";

        // context menu name in the registry
        const string KeyName = "VirusTotal Context Menu";

        // context menu text
        const string MenuText = "VT Scan";

        [STAThread]
        static void Main(string[] args)
        {
            // process register or unregister commands
            if (!ProcessCommand(args))
            {
                // invoked from shell, process the selected file
                VirusScanFile(args[0]);
            }
        }

        /// <summary>
        /// Process command line actions (register or unregister).
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        /// <returns>True if processed an action in the command line.</returns>
        static bool ProcessCommand(string[] args)
        {
            // register
            if (args.Length == 0 || string.Compare(args[0], "--register", true) == 0)
            {
                // full path to self, %L is placeholder for selected file
                string menuCommand = string.Format("\"{0}\" \"%L\"", Application.ExecutablePath);

                // register the context menu
                FileShellExtension.Register(FileType, KeyName, MenuText, menuCommand);

                MessageBox.Show(string.Format("The {0} shell extension was registered.", KeyName), KeyName);

                return true;
            }

            // unregister
            if (string.Compare(args[0], "--unregister", true) == 0)
            {
                // unregister the context menu
                FileShellExtension.Unregister(FileType, KeyName);

                MessageBox.Show(string.Format("The {0} shell extension was unregistered.", KeyName), KeyName);

                return true;
            }

            // command line did not contain an action
            return false;
        }

        private static void VirusScanFile(string filePath)
        {
            VirusTotal virusTotal = new VirusTotal(ConfigurationManager.AppSettings["ApiKey"]);

            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = false;

            FileInfo fileInfo = new FileInfo(filePath);

            if (!fileInfo.Exists)
                return;

            //Check if the file has been scanned before.
            Console.WriteLine("Getting report for " + Path.GetFileName(filePath));
            Report report = virusTotal.GetFileReport(HashHelper.GetSHA256(fileInfo)).FirstOrDefault();

            if (report == null || report.ResponseCode == 0)
            {
                Console.WriteLine("No report for " + Path.GetFileName(filePath) + " - sending file to VT");

                try
                {
                    ScanResult result = virusTotal.ScanFile(fileInfo);

                    Console.WriteLine("Opening report for " + Path.GetFileName(filePath));
                    Process.Start(result.Permalink);
                }
                catch (RateLimitException)
                {
                    MessageBox.Show("Virus Total limits the number of calls you can make to 4 calls each 60 seconds.", "Rate limit");
                }
                catch (SizeLimitException)
                {
                    MessageBox.Show("Virus Total limits the filesize to 32 MB.", "File too large");
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