using System.ComponentModel;
using System.Runtime.InteropServices;
using static Nodar.Core.Localization.Loc;

namespace Nodar.App.Services;

/// <summary>
/// Ícone na área de notificação do Windows (bandeja), com menu e notificações.
/// </summary>
/// <remarks>
/// Usa <c>Shell_NotifyIcon</c>: no Windows 10/11 as notificações deste ícone aparecem como notificações
/// normais do sistema (e ficam na central de notificações), sem dependências WinRT nem empacotamento.
/// A janela de mensagens é criada no thread da interface, que já tem o ciclo de mensagens do Avalonia.
/// </remarks>
public sealed class WindowsTray : IDisposable
{
    public event Action? OpenRequested;
    public event Action? ScanRequested;
    public event Action? ExitRequested;

    private const int CallbackMessage = 0x0400 + 0x42; // WM_APP-like: WM_USER + 0x42
    private const int IconId = 1;
    private const int MenuOpen = 1, MenuScan = 2, MenuExit = 3;

    private readonly WndProc _wndProc; // manter referência viva (o delegado é chamado por código nativo)
    private readonly IntPtr _hwnd;
    private readonly IntPtr _icon;      // pequeno: bandeja
    private readonly IntPtr _largeIcon; // grande: notificações
    private readonly uint _taskbarCreated;
    private string _tooltip;
    private bool _added;
    private bool _disposed;

    public WindowsTray(string tooltip)
    {
        _tooltip = tooltip;
        _wndProc = WindowProc;
        var hInstance = GetModuleHandle(null);
        var className = "NodarTrayWindow_" + Environment.ProcessId;

        var wc = new WNDCLASSEX
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEX>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(_wndProc),
            hInstance = hInstance,
            lpszClassName = className
        };
        if (RegisterClassEx(ref wc) == 0)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "RegisterClassEx");

        // Janela invisível só para receber as mensagens do ícone (HWND_MESSAGE não recebe TaskbarCreated,
        // por isso é uma janela de topo nunca mostrada).
        _hwnd = CreateWindowEx(0, className, "Nodar", 0, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);
        if (_hwnd == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateWindowEx");

        _taskbarCreated = RegisterWindowMessage("TaskbarCreated");
        (_icon, _largeIcon) = LoadAppIcons();
        AddIcon();
    }

    /// <summary>Indica se o ícone foi registado na bandeja.</summary>
    public bool IsVisible => _added;

    /// <summary>Mostra uma notificação do Windows (título até 63 caracteres, texto até 255).</summary>
    public bool Notify(string title, string message)
    {
        if (_disposed)
            return false;
        if (!_added)
            AddIcon();

        var data = NewData();
        data.uFlags = NIF_INFO;
        data.szInfoTitle = Truncate(title, 63);
        data.szInfo = Truncate(string.IsNullOrWhiteSpace(message) ? " " : message, 255);
        data.dwInfoFlags = _largeIcon != IntPtr.Zero ? NIIF_USER | NIIF_LARGE_ICON : NIIF_INFO;
        data.hBalloonIcon = _largeIcon;
        return Shell_NotifyIcon(NIM_MODIFY, ref data);
    }

    /// <summary>Atualiza a dica do ícone (ex.: depois de mudar de idioma).</summary>
    public void SetTooltip(string tooltip)
    {
        _tooltip = tooltip;
        if (!_added) return;
        var data = NewData();
        data.uFlags = NIF_TIP | NIF_SHOWTIP;
        data.szTip = Truncate(tooltip, 127);
        Shell_NotifyIcon(NIM_MODIFY, ref data);
    }

    private void AddIcon()
    {
        var data = NewData();
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP;
        data.uCallbackMessage = CallbackMessage;
        data.hIcon = _icon;
        data.szTip = Truncate(_tooltip, 127);
        _added = Shell_NotifyIcon(NIM_ADD, ref data);
        if (_added)
        {
            data.uTimeoutOrVersion = NOTIFYICON_VERSION_4;
            Shell_NotifyIcon(NIM_SETVERSION, ref data);
        }
    }

    private NOTIFYICONDATA NewData() => new()
    {
        cbSize = (uint)Marshal.SizeOf<NOTIFYICONDATA>(),
        hWnd = _hwnd,
        uID = IconId,
        szTip = "", szInfo = "", szInfoTitle = ""
    };

    private IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
    {
        if (msg == CallbackMessage)
        {
            // NOTIFYICON_VERSION_4: o evento vem no LOWORD de lParam.
            var evt = (int)(lParam.ToInt64() & 0xFFFF);
            switch (evt)
            {
                case NIN_SELECT:
                case NIN_KEYSELECT:
                case WM_LBUTTONDBLCLK:
                case NIN_BALLOONUSERCLICK:
                    OpenRequested?.Invoke();
                    break;
                case WM_CONTEXTMENU:
                case WM_RBUTTONUP:
                    ShowMenu();
                    break;
            }
            return IntPtr.Zero;
        }

        if (msg == _taskbarCreated && _taskbarCreated != 0)
        {
            // O Explorador reiniciou: voltar a pôr o ícone.
            _added = false;
            AddIcon();
            return IntPtr.Zero;
        }

        return DefWindowProc(hwnd, msg, wParam, lParam);
    }

    private void ShowMenu()
    {
        var menu = CreatePopupMenu();
        try
        {
            AppendMenu(menu, MF_STRING, MenuOpen, T("tray.open"));
            AppendMenu(menu, MF_STRING, MenuScan, T("tray.scanNow"));
            AppendMenu(menu, MF_SEPARATOR, 0, null);
            AppendMenu(menu, MF_STRING, MenuExit, T("tray.exit"));
            SetMenuDefaultItem(menu, MenuOpen, 0);

            GetCursorPos(out var point);
            SetForegroundWindow(_hwnd); // necessário para o menu fechar ao clicar fora
            var command = TrackPopupMenuEx(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, point.X, point.Y, _hwnd, IntPtr.Zero);
            PostMessage(_hwnd, 0, IntPtr.Zero, IntPtr.Zero);

            switch (command)
            {
                case MenuOpen: OpenRequested?.Invoke(); break;
                case MenuScan: ScanRequested?.Invoke(); break;
                case MenuExit: ExitRequested?.Invoke(); break;
            }
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    private static (IntPtr Small, IntPtr Large) LoadAppIcons()
    {
        // Ícone embutido no próprio executável (ApplicationIcon).
        var path = Environment.ProcessPath;
        if (path != null && ExtractIconEx(path, 0, out var large, out var small, 1) > 0)
            return (small != IntPtr.Zero ? small : large, large != IntPtr.Zero ? large : small);
        return (IntPtr.Zero, IntPtr.Zero);
    }

    private static string Truncate(string text, int max) => text.Length <= max ? text : text[..(max - 1)] + "…";

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_added)
        {
            var data = NewData();
            Shell_NotifyIcon(NIM_DELETE, ref data);
        }
        if (_icon != IntPtr.Zero)
            DestroyIcon(_icon);
        if (_largeIcon != IntPtr.Zero && _largeIcon != _icon)
            DestroyIcon(_largeIcon);
        DestroyWindow(_hwnd);
    }

    // ------------------------------------------------------------------ Win32

    private delegate IntPtr WndProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    private const uint NIM_ADD = 0, NIM_MODIFY = 1, NIM_DELETE = 2, NIM_SETVERSION = 4;
    private const uint NIF_MESSAGE = 0x1, NIF_ICON = 0x2, NIF_TIP = 0x4, NIF_INFO = 0x10, NIF_SHOWTIP = 0x80;
    private const uint NIIF_INFO = 0x1, NIIF_USER = 0x4, NIIF_LARGE_ICON = 0x20;
    private const uint NOTIFYICON_VERSION_4 = 4;
    private const int NIN_SELECT = 0x0400, NIN_KEYSELECT = 0x0401, NIN_BALLOONUSERCLICK = 0x0405;
    private const int WM_CONTEXTMENU = 0x007B, WM_RBUTTONUP = 0x0205, WM_LBUTTONDBLCLK = 0x0203;
    private const uint MF_STRING = 0x0, MF_SEPARATOR = 0x800;
    private const uint TPM_RETURNCMD = 0x100, TPM_RIGHTBUTTON = 0x2, TPM_BOTTOMALIGN = 0x20;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NOTIFYICONDATA
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string szTip;
        public uint dwState;
        public uint dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string szInfoTitle;
        public uint dwInfoFlags;
        public Guid guidItem;
        public IntPtr hBalloonIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEX
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct POINT { public int X, Y; }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern bool Shell_NotifyIcon(uint message, ref NOTIFYICONDATA data);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)] private static extern uint ExtractIconEx(string file, int index, out IntPtr large, out IntPtr small, uint count);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern ushort RegisterClassEx(ref WNDCLASSEX wc);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowEx(uint exStyle, string className, string windowName, uint style, int x, int y, int w, int h, IntPtr parent, IntPtr menu, IntPtr instance, IntPtr param);
    [DllImport("user32.dll")] private static extern IntPtr DefWindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool DestroyWindow(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint RegisterWindowMessage(string name);
    [DllImport("user32.dll")] private static extern IntPtr CreatePopupMenu();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern bool AppendMenu(IntPtr menu, uint flags, int id, string? text);
    [DllImport("user32.dll")] private static extern bool SetMenuDefaultItem(IntPtr menu, int item, uint byPosition);
    [DllImport("user32.dll")] private static extern int TrackPopupMenuEx(IntPtr menu, uint flags, int x, int y, IntPtr hwnd, IntPtr tpm);
    [DllImport("user32.dll")] private static extern bool DestroyMenu(IntPtr menu);
    [DllImport("user32.dll")] private static extern bool GetCursorPos(out POINT point);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] private static extern IntPtr GetModuleHandle(string? name);
}
