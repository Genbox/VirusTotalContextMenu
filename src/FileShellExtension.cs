using System.Diagnostics;
using Microsoft.Win32;

namespace VirusTotalContextMenu;

internal static class FileShellExtension
{
    public static bool IsRegistered(string fileType, string shellKeyName)
    {
        string regPath = $@"Software\Classes\{fileType}\shell\{shellKeyName}";

        using RegistryKey? key = Registry.CurrentUser.OpenSubKey(regPath);
        return key != null;
    }

    internal static void Register(string fileType, string shellKeyName, string menuText, string menuCommand, string iconPath)
    {
Debug.Assert(!string.IsNullOrEmpty(fileType) && !string.IsNullOrEmpty(shellKeyName) && !string.IsNullOrEmpty(menuText) && !string.IsNullOrEmpty(menuCommand));

        Debug.Assert(!string.IsNullOrEmpty(fileType) && !string.IsNullOrEmpty(shellKeyName) && !string.IsNullOrEmpty(menuText) && !string.IsNullOrEmpty(menuCommand));

        // create full path to registry location
        string regPath = $@"Software\Classes\{fileType}\shell\{shellKeyName}";

        // add context menu to the registry
        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(regPath))
        {
            key.SetValue(null, menuText);
            key.SetValue("Icon", iconPath);
        }

        // add command that is invoked to the registry
        using (RegistryKey key = Registry.CurrentUser.CreateSubKey($@"{regPath}\command"))
            key.SetValue(null, menuCommand);
    }

    internal static void Unregister(string fileType, string shellKeyName)Debug.Assert(!string.IsNullOrEmpty(fileType) && !string.IsNullOrEmpty(shellKeyName));

    {
        Debug.Assert(!string.IsNullOrEmpty(fileType) && !string.IsNullOrEmpty(shellKeyName));
        Registry.CurrentUser.DeleteSubKeyTree($@"Software\Classes\{fileType}\shell\{shellKeyName}", false);
    }
}