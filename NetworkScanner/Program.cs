using NetworkScanner.UI;

namespace NetworkScanner;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        var form = new MainForm();
        form.Icon = SystemIcons.Information;
        Application.Run(form);
    }
}
