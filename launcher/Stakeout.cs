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
[assembly: AssemblyVersion("0.2.1.0")]
[assembly: AssemblyFileVersion("0.2.1.0")]

static class Launcher
{
    static int Main(string[] args)
    {
        // The messages below are Chinese: UTF-8 while the launcher runs, the console's own setting back after.
        Encoding before = Console.OutputEncoding;
        Console.OutputEncoding = Encoding.UTF8;
        try
        {
            return Run(args);
        }
        finally
        {
            Console.OutputEncoding = before;
        }
    }

    static int Run(string[] args)
    {
        // Ctrl+C is for Stakeout, which finishes a running observation before it quits: the launcher waits.
        Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; };

        string dir = AppDomain.CurrentDomain.BaseDirectory;
        string script = Path.Combine(dir, "stakeout.py");
        if (!File.Exists(script))
            return Fail("找不到 stakeout.py。Stakeout.exe 要和 Stakeout 的其他文件放在同一个文件夹里。");
        string rest = Quote(script) + " ui";
        foreach (string a in args)
            rest += " " + Quote(a);

        // The first Python that is 3.12 or newer (MIN_PYTHON in stakeout.py): the Python launcher py with its
        // default (python.org installs py), python on PATH, then py with each newer version by name, for when
        // the default is an older one. Stakeout.bat looks in the same order.
        string[,] pythons = { { "py", "-3 " }, { "python", "" }, { "py", "-3.14 " }, { "py", "-3.13 " }, { "py", "-3.12 " } };
        for (int i = 0; i < pythons.GetLength(0); i++)
        {
            if (!NewEnough(pythons[i, 0], pythons[i, 1]))
                continue;                           // not installed, or too old: try the next one
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
                continue;                           // gone since the check: try the next one
            }
            proc.WaitForExit();
            if (proc.ExitCode != 0)
                Pause();                            // keep Stakeout's message readable
            return proc.ExitCode;
        }
        return Fail("找不到 Python 3.12 或更新的版本。请从 https://www.python.org 安装，安装时勾上 “Add python.exe to PATH”。");
    }

    // Whether this Python is there and at least 3.12. Quietly: the Microsoft Store's stand-in for python, there
    // when no Python is installed, prints a message and fails.
    static bool NewEnough(string exe, string flags)
    {
        ProcessStartInfo info = new ProcessStartInfo(exe, flags + "-c \"import sys; sys.exit(sys.version_info < (3, 12))\"");
        info.UseShellExecute = false;
        info.CreateNoWindow = true;
        info.RedirectStandardOutput = true;
        info.RedirectStandardError = true;
        try
        {
            using (Process proc = Process.Start(info))
            {
                proc.StandardOutput.ReadToEnd();    // a few lines at most
                proc.StandardError.ReadToEnd();
                proc.WaitForExit();
                return proc.ExitCode == 0;
            }
        }
        catch (Win32Exception)
        {
            return false;                           // not installed
        }
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
