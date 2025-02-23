using System.Diagnostics;
using Newtonsoft.Json.Linq;
using VirusTotalNet;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using System.Diagnostics;
using System.IO;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace VirusTotalContextMenu
{
    public static class Program
    {
        private const string FileType = "*"; // file type to register
        private const string KeyName = "VirusTotalContextMenu"; // context menu name in the registry
        private const string MenuText = "VirusTotal Scan"; // context menu text

        public static async Task Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            if (args.Length == 0)
            {
                if (FileShellExtension.IsRegistered(FileType, KeyName))
                {
                    if (MessageBox.Show("VirusTotal Context Menu is currently registered.\nUnregister it?", "VirusTotal Context Menu Registration", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    {
                        FileShellExtension.Unregister(FileType, KeyName);
                        WriteSuccess($"The '{KeyName}' shell extension was unregistered.");
                    }
                }
                else
                {
                    if (MessageBox.Show("VirusTotal Context Menu is currently not registered.\nRegister it?", "VirusTotal Context Menu Registration", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                    {
                        FileShellExtension.Register(FileType, KeyName, MenuText, $"\"{Environment.ProcessPath}\" \"%L\"", Environment.ProcessPath!);
                        WriteSuccess($"The '{KeyName}' shell extension was registered.");
                    }
                }
            }
            else
            {
                try
                {
                    await VirusScanFile(args[0]);
                }
                catch (Exception e)
                {
                    WriteError($"Unknown error happened: {e.Message}");
                }
            }
        }

        private static void OpenUrl(string url, string prompt)
        {
            if (MessageBox.Show(prompt, "Open in Browser?", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No)
                return;

            using Process? p = Process.Start(new ProcessStartInfo
            {
                FileName = url,
                UseShellExecute = true
            });
        }

        private static void WriteError(string error) => MessageBox.Show(error, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
        private static void WriteSuccess(string message) => MessageBox.Show(message, "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);

        private static async Task VirusScanFile(string filePath)
        {
            string path = Path.Combine(Path.GetDirectoryName(Environment.ProcessPath)!, "appsettings.json");

            JObject jObj = JObject.Parse(await File.ReadAllTextAsync(path));
            string? key = jObj.GetValue("apikey")?.ToString();

            if (string.IsNullOrWhiteSpace(key) || key.Length != 64)
            {
                WriteError("Invalid API key. Did you remember to change appsettings.json?");
                return;
            }

            using VirusTotal virusTotal = new VirusTotal(key);
            virusTotal.UseTLS = true;

            FileInfo info = new FileInfo(filePath);

            if (!info.Exists)
                return;

            // Check if the file has been scanned before.
            FileReport? report = await virusTotal.GetFileReportAsync(info);

            if (report == null || report.ResponseCode != FileReportResponseCode.Present)
            {
                try
                {
                    ScanResult result = await virusTotal.ScanFileAsync(info);

                    if (result.Permalink.Length < 66)
                    {
                        WriteError($"Invalid scan ID received from VirusTotal: {result.Permalink}");
                        return;
                    }

                    string sha256 = result.Permalink.Substring(2, 64);
                    OpenUrl($"https://www.virustotal.com/gui/file/{sha256}/detection/{result.Permalink}", "File new to VirusTotal. Open in browser?");
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
                    WriteError($"Unknown error happened: {e.Message}");
                }
            }
            else
            {
                if (string.IsNullOrEmpty(report.Permalink))
                    WriteError("No permalink associated with the file. Cannot open URL.");
                else
                    OpenUrl(report.Permalink, $"Results: {report.Positives}/{report.Total} positive hits.\nLast scanned: {report.ScanDate:dd MMM yyyy} ({(DateTime.Now - report.ScanDate).Days} days ago).\nOpen in browser?");
            }
        }
    }
}