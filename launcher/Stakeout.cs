// Stakeout.exe, the launcher on Windows: does what Stakeout.bat does (starts the page's local server with
// Python and opens the page in the browser), as a program that can carry the pixel-detective icon
// (launcher/icon.ico). Built by .github/workflows/tests.yml with the C# compiler of .NET Framework 4, which
// comes with Windows; C# 5, the language that compiler takes.
//
// Arguments are passed on to `stakeout.py ui` (for example --port 8766, --no-open).
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Text;

[assembly: AssemblyTitle("Stakeout")]
[assembly: AssemblyProduct("Stakeout")]
[assembly: AssemblyDescription("Stakeout: see what the apps on a rooted Android phone are doing")]
[assembly: AssemblyVersion("0.1.0.0")]
[assembly: AssemblyFileVersion("0.1.0.0")]

static class Launcher
{
    static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        // Ctrl+C is for Stakeout, which finishes a running observation before it quits: the launcher waits.
        Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; };

        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(dir, "stakeout.py");
        if (!File.Exists(script))
            return Fail("找不到 stakeout.py。Stakeout.exe 要和 Stakeout 的其他文件放在同一个文件夹里。");
        string rest = Quote(script) + " ui";
        foreach (string a in args)
            rest += " " + Quote(a);

        // The Python launcher py first (python.org installs it), then python on PATH.
        string[,] pythons = { { "py", "-3 " }, { "python", "" } };
        for (int i = 0; i < pythons.GetLength(0); i++)
        {
            ProcessStartInfo info = new ProcessStartInfo(pythons[i, 0], pythons[i, 1] + rest);
            info.UseShellExecute = false;           // Python shares this console window
            info.WorkingDirectory = dir;
            info.EnvironmentVariables["PYTHONUTF8"] = "1";
            Process proc;
            try
            {
                proc = Process.Start(info);
            }
            catch (Win32Exception)
            {
                continue;                           // not installed: try the next one
            }
            proc.WaitForExit();
            if (proc.ExitCode != 0)
                Pause();                            // keep Stakeout's message readable
            return proc.ExitCode;
        }
        return Fail("找不到 Python。请从 https://www.python.org 安装 Python 3.12，安装时勾上 “Add python.exe to PATH”。");
    }

    static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        Pause();
        return 1;
    }

    static void Pause()
    {
        Console.Error.WriteLine("按任意键关闭这个窗口。");
        try
        {
            Console.ReadKey(true);
        }
        catch (InvalidOperationException)
        {
            // no keyboard (input redirected): nothing to wait for
        }
    }

    // One argument as Windows programs read it back (the rules of CommandLineToArgvW).
    static string Quote(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny(new[] { ' ', '\t', '"' }) < 0)
            return arg;
        StringBuilder sb = new StringBuilder("\"");
        int slashes = 0;
        foreach (char c in arg)
        {
            if (c == '\\')
            {
                slashes++;
                continue;
            }
            sb.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
            slashes = 0;
            sb.Append(c);
        }
        sb.Append('\\', slashes * 2);
        return sb.Append('"').ToString();
    }
}
