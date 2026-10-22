#!/usr/bin/env bash
#
# ps12_exe.sh - Convert a PowerShell script (e.g. twigs.ps1) into a Windows
# .exe from Linux, using only the dotnet SDK (no Windows, no mono, no ps2exe).
#
# The exe is a small .NET Framework 4.6.2 console host that embeds the script and
# runs it in-process on the target's built-in Windows PowerShell 5.1, the same
# way ps2exe does: $PSScriptRoot is empty and
# [Environment]::GetCommandLineArgs()[0] is the exe path. Any .psm1 modules are
# embedded too and pre-loaded into the session before the script runs.
#
# Usage:
#   ./ps12exe.sh [-i script.ps1] [-o output.exe] [-m module.psm1]... [-a] [-v version] [-c icon.ico]
#
#   -i  input script                 (default: twigs/twigs.ps1)
#   -o  output exe                   (default: <script name>.exe next to the script)
#   -m  module to embed, repeatable  (default: every *.psm1 next to the script)
#   -a  require administrator (UAC prompt when the exe starts)
#   -v  file/product version         (default: 1.0.0)
#   -c  icon file (.ico)
#
# Requirements: dotnet SDK 6+ and access to nuget.org (first build only).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INPUT="$SCRIPT_DIR/twigs/twigs.ps1"
OUTPUT=""
MODULES=()
REQUIRE_ADMIN=false
VERSION="1.0.0"
ICON=""

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while getopts ":i:o:m:av:c:h" opt; do
    case "$opt" in
        i) INPUT="$OPTARG" ;;
        o) OUTPUT="$OPTARG" ;;
        m) MODULES+=("$OPTARG") ;;
        a) REQUIRE_ADMIN=true ;;
        v) VERSION="$OPTARG" ;;
        c) ICON="$OPTARG" ;;
        h) usage 0 ;;
        :) echo "Option -$OPTARG needs a value" >&2; usage 1 ;;
        *) echo "Unknown option -$OPTARG" >&2; usage 1 ;;
    esac
done

command -v dotnet >/dev/null || { echo "dotnet SDK not found (apt install dotnet-sdk-8.0)" >&2; exit 1; }
[[ -f "$INPUT" ]] || { echo "Input script not found: $INPUT" >&2; exit 1; }
INPUT="$(realpath "$INPUT")"
SRC_DIR="$(dirname "$INPUT")"
BASE="$(basename "$INPUT" .ps1)"
[[ -n "$OUTPUT" ]] || OUTPUT="$SRC_DIR/$BASE.exe"
OUTPUT="$(realpath -m "$OUTPUT")"

if [[ ${#MODULES[@]} -eq 0 ]]; then
    shopt -s nullglob
    MODULES=("$SRC_DIR"/*.psm1)
    shopt -u nullglob
fi
for m in "${MODULES[@]}"; do
    [[ -f "$m" ]] || { echo "Module not found: $m" >&2; exit 1; }
done
if [[ -n "$ICON" ]]; then
    [[ -f "$ICON" ]] || { echo "Icon not found: $ICON" >&2; exit 1; }
    ICON="$(realpath "$ICON")"
fi

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

xml_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g' <<<"$1"; }

# ---------------------------------------------------------------- project file
{
    cat <<EOF
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net462</TargetFramework>
    <AssemblyName>$(xml_escape "$BASE")</AssemblyName>
    <RootNamespace>PsExeHost</RootNamespace>
    <LangVersion>latest</LangVersion>
    <PlatformTarget>AnyCPU</PlatformTarget>
    <Prefer32Bit>false</Prefer32Bit>
    <DebugType>none</DebugType>
    <Version>$(xml_escape "$VERSION")</Version>
    <Product>$(xml_escape "$BASE")</Product>
    <SatelliteResourceLanguages>en</SatelliteResourceLanguages>
EOF
    [[ "$REQUIRE_ADMIN" == true ]] && echo "    <ApplicationManifest>app.manifest</ApplicationManifest>"
    [[ -n "$ICON" ]] && echo "    <ApplicationIcon>$(xml_escape "$ICON")</ApplicationIcon>"
    cat <<EOF
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Microsoft.NETFramework.ReferenceAssemblies.net462" Version="1.0.3" PrivateAssets="all" />
    <PackageReference Include="Microsoft.PowerShell.5.1.ReferenceAssemblies" Version="1.0.0" PrivateAssets="all" ExcludeAssets="runtime" />
  </ItemGroup>
  <ItemGroup>
    <EmbeddedResource Include="$(xml_escape "$INPUT")" LogicalName="script/main.ps1" />
EOF
    for m in "${MODULES[@]}"; do
        mp="$(realpath "$m")"
        echo "    <EmbeddedResource Include=\"$(xml_escape "$mp")\" LogicalName=\"module/$(xml_escape "$(basename "$mp")")\" />"
    done
    cat <<EOF
  </ItemGroup>
</Project>
EOF
} > "$BUILD_DIR/host.csproj"

if [[ "$REQUIRE_ADMIN" == true ]]; then
    cat > "$BUILD_DIR/app.manifest" <<'EOF'
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="1.0.0.0" name="pshost.app"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>
EOF
fi

# ---------------------------------------------------------------- host source
cat > "$BUILD_DIR/Program.cs" <<'EOF'
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Language;
using System.Management.Automation.Runspaces;
using System.Reflection;
using System.Security;
using System.Text.RegularExpressions;
using System.Threading;

namespace PsExeHost
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            var asm = Assembly.GetExecutingAssembly();
            string script = ReadResource(asm, "script/main.ps1");
            var host = new ExeHost();

            var iss = InitialSessionState.CreateDefault();
            iss.ExecutionPolicy = Microsoft.PowerShell.ExecutionPolicy.Bypass;

            using (Runspace rs = RunspaceFactory.CreateRunspace(host, iss))
            {
                rs.Open();

                // Pre-load embedded modules into the global scope. Export-ModuleMember
                // is only valid inside a real module, so it is dropped.
                foreach (string name in asm.GetManifestResourceNames().Where(n => n.StartsWith("module/")).OrderBy(n => n))
                {
                    string src = ReadResource(asm, name);
                    src = Regex.Replace(src, @"^\s*Export-ModuleMember\b.*$", "", RegexOptions.Multiline | RegexOptions.IgnoreCase);
                    using (PowerShell ps = PowerShell.Create())
                    {
                        ps.Runspace = rs;
                        ps.AddScript(src, false);
                        try
                        {
                            ps.Invoke();
                            foreach (ErrorRecord e in ps.Streams.Error)
                                host.UI.WriteErrorLine(name + ": " + e);
                        }
                        catch (Exception ex)
                        {
                            host.UI.WriteErrorLine("Failed to load " + name + ": " + ex.Message);
                        }
                    }
                }

                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;
                    ps.AddScript(script);
                    if (!BindArguments(ps, script, args, host))
                        return 1;
                    ps.Commands.Commands[0].MergeMyResults(PipelineResultTypes.Error, PipelineResultTypes.Output);
                    ps.AddCommand("Out-Default");

                    Console.CancelKeyPress += (s, e) =>
                    {
                        e.Cancel = true;
                        try { ps.BeginStop(null, null); } catch { }
                    };

                    try
                    {
                        ps.Invoke();
                    }
                    catch (RuntimeException ex)
                    {
                        host.UI.WriteErrorLine(ex.ErrorRecord != null ? ex.ErrorRecord.ToString() : ex.Message);
                        return host.ExitCodeSet ? host.ExitCode : 1;
                    }
                    catch (Exception ex)
                    {
                        host.UI.WriteErrorLine(ex.Message);
                        return 1;
                    }
                    if (!host.ExitCodeSet && ps.HadErrors && ps.InvocationStateInfo.State == PSInvocationState.Failed)
                        return 1;
                }
            }
            return host.ExitCode;
        }

        private static string ReadResource(Assembly asm, string name)
        {
            using (Stream s = asm.GetManifestResourceStream(name))
            using (var r = new StreamReader(s, true))
                return r.ReadToEnd();
        }

        private class ParamInfo { public string Name; public bool IsSwitch; public bool IsArray; }

        // Turns "-name value", "-name:value" and "-switch" style arguments into named
        // parameters, using the script's param() block to know switches and arrays.
        private static bool BindArguments(PowerShell ps, string script, string[] args, ExeHost host)
        {
            var parms = new List<ParamInfo>();
            Token[] tokens;
            ParseError[] errors;
            ScriptBlockAst ast = Parser.ParseInput(script, out tokens, out errors);
            if (ast.ParamBlock != null)
            {
                foreach (ParameterAst p in ast.ParamBlock.Parameters)
                {
                    Type t = p.StaticType;
                    parms.Add(new ParamInfo
                    {
                        Name = p.Name.VariablePath.UserPath,
                        IsSwitch = t == typeof(SwitchParameter),
                        IsArray = t.IsArray
                    });
                }
            }

            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "-?" || a == "/?" || a.Equals("-help", StringComparison.OrdinalIgnoreCase))
                {
                    host.UI.WriteLine(HelpText(ast, script, parms));
                    return false;
                }
                if (!IsParamName(a))
                {
                    ps.AddArgument(Unquote(a));
                    continue;
                }

                string name = a.Substring(1);
                string val = null;
                int colon = name.IndexOf(':');
                if (colon >= 0)
                {
                    val = name.Substring(colon + 1);
                    name = name.Substring(0, colon);
                }

                ParamInfo pi = parms.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (pi == null)
                {
                    var matches = parms.Where(p => p.Name.StartsWith(name, StringComparison.OrdinalIgnoreCase)).ToList();
                    if (matches.Count == 1) pi = matches[0];
                }

                if (pi != null && pi.IsSwitch)
                {
                    bool on = val == null || !(val.Equals("$false", StringComparison.OrdinalIgnoreCase) || val.Equals("false", StringComparison.OrdinalIgnoreCase) || val == "0");
                    ps.AddParameter(pi.Name, new SwitchParameter(on));
                    continue;
                }

                if (val == null && i + 1 < args.Length && !IsParamName(args[i + 1]))
                    val = args[++i];

                string pname = pi != null ? pi.Name : name;
                if (val == null)
                    ps.AddParameter(pname);
                else if (pi != null && pi.IsArray)
                    ps.AddParameter(pname, val.Split(',').Select(v => Unquote(v.Trim())).Where(v => v.Length > 0).ToArray());
                else
                    ps.AddParameter(pname, Unquote(val));
            }
            return true;
        }

        private static bool IsParamName(string a)
        {
            return a.Length > 1 && a[0] == '-' && (char.IsLetter(a[1]) || a[1] == '_');
        }

        private static string Unquote(string v)
        {
            if (v.Length >= 2 && ((v[0] == '\'' && v[v.Length - 1] == '\'') || (v[0] == '"' && v[v.Length - 1] == '"')))
                return v.Substring(1, v.Length - 2);
            return v;
        }

        private static string HelpText(ScriptBlockAst ast, string script, List<ParamInfo> parms)
        {
            CommentHelpInfo help = ast.GetHelpContent();
            string exe = Path.GetFileName(Environment.GetCommandLineArgs()[0]);
            var sb = new System.Text.StringBuilder();
            if (help != null && !string.IsNullOrWhiteSpace(help.Synopsis)) sb.AppendLine(help.Synopsis.Trim()).AppendLine();
            if (help != null && !string.IsNullOrWhiteSpace(help.Description)) sb.AppendLine(help.Description.Trim()).AppendLine();
            sb.AppendLine("Usage: " + exe + " " + string.Join(" ", parms.Select(p => p.IsSwitch ? "[-" + p.Name + "]" : "[-" + p.Name + " <value>]")));
            if (help != null)
            {
                sb.AppendLine();
                foreach (var kv in help.Parameters)
                    sb.AppendLine("  -" + kv.Key.ToLowerInvariant() + "\n      " + kv.Value.Trim());
                foreach (string ex in help.Examples)
                    sb.AppendLine().AppendLine("Example:").AppendLine("  " + ex.Trim().Replace(".\\" + "twigs.ps1", exe));
            }
            return sb.ToString();
        }
    }

    internal class ExeHost : PSHost
    {
        private readonly Guid _id = Guid.NewGuid();
        private readonly ExeHostUI _ui = new ExeHostUI();
        public int ExitCode;
        public bool ExitCodeSet;

        public override CultureInfo CurrentCulture { get { return Thread.CurrentThread.CurrentCulture; } }
        public override CultureInfo CurrentUICulture { get { return Thread.CurrentThread.CurrentUICulture; } }
        public override Guid InstanceId { get { return _id; } }
        public override string Name { get { return "PsExeHost"; } }
        public override PSHostUserInterface UI { get { return _ui; } }
        public override Version Version { get { return new Version(1, 0); } }
        public override void EnterNestedPrompt() { throw new NotSupportedException(); }
        public override void ExitNestedPrompt() { throw new NotSupportedException(); }
        public override void NotifyBeginApplication() { }
        public override void NotifyEndApplication() { }
        public override void SetShouldExit(int exitCode) { ExitCode = exitCode; ExitCodeSet = true; }
    }

    internal class ExeHostUI : PSHostUserInterface
    {
        private readonly ExeRawUI _raw = new ExeRawUI();
        public override PSHostRawUserInterface RawUI { get { return _raw; } }

        public override string ReadLine() { return Console.ReadLine() ?? ""; }

        public override SecureString ReadLineAsSecureString()
        {
            var ss = new SecureString();
            if (Console.IsInputRedirected)
            {
                foreach (char c in Console.ReadLine() ?? "") ss.AppendChar(c);
            }
            else
            {
                while (true)
                {
                    ConsoleKeyInfo k = Console.ReadKey(true);
                    if (k.Key == ConsoleKey.Enter) break;
                    if (k.Key == ConsoleKey.Backspace)
                    {
                        if (ss.Length > 0) { ss.RemoveAt(ss.Length - 1); Console.Write("\b \b"); }
                        continue;
                    }
                    if (k.KeyChar == '\0') continue;
                    ss.AppendChar(k.KeyChar);
                    Console.Write('*');
                }
                Console.WriteLine();
            }
            ss.MakeReadOnly();
            return ss;
        }

        public override Dictionary<string, PSObject> Prompt(string caption, string message, Collection<FieldDescription> descriptions)
        {
            if (!string.IsNullOrEmpty(caption)) WriteLine(caption);
            if (!string.IsNullOrEmpty(message)) WriteLine(message);
            var result = new Dictionary<string, PSObject>();
            foreach (FieldDescription fd in descriptions)
            {
                string label = string.IsNullOrEmpty(fd.Label) ? fd.Name : fd.Label.Replace("&", "");
                string type = fd.ParameterTypeFullName ?? "";
                if (type.EndsWith("SecureString"))
                {
                    Write(label + ": ");
                    result[fd.Name] = new PSObject(ReadLineAsSecureString());
                }
                else if (type.EndsWith("PSCredential"))
                {
                    result[fd.Name] = new PSObject(PromptForCredential("", "", null, ""));
                }
                else if (type.EndsWith("[]"))
                {
                    var items = new List<string>();
                    while (true)
                    {
                        Write(label + "[" + items.Count + "]: ");
                        string line = ReadLine();
                        if (line.Length == 0) break;
                        items.Add(line);
                    }
                    result[fd.Name] = new PSObject(items.ToArray());
                }
                else
                {
                    Write(label + ": ");
                    result[fd.Name] = new PSObject(ReadLine());
                }
            }
            return result;
        }

        public override int PromptForChoice(string caption, string message, Collection<ChoiceDescription> choices, int defaultChoice)
        {
            if (!string.IsNullOrEmpty(caption)) WriteLine(caption);
            if (!string.IsNullOrEmpty(message)) WriteLine(message);
            var keys = new List<string>();
            for (int i = 0; i < choices.Count; i++)
            {
                string lbl = choices[i].Label;
                int amp = lbl.IndexOf('&');
                string key = amp >= 0 && amp + 1 < lbl.Length ? lbl.Substring(amp + 1, 1) : (i + 1).ToString();
                keys.Add(key);
                Write("[" + key + "] " + lbl.Replace("&", "") + (i == defaultChoice ? " (default)" : "") + "  ");
            }
            WriteLine();
            while (true)
            {
                Write("Choice: ");
                string ans = ReadLine().Trim();
                if (ans.Length == 0 && defaultChoice >= 0) return defaultChoice;
                int idx = keys.FindIndex(k => k.Equals(ans, StringComparison.OrdinalIgnoreCase));
                if (idx >= 0) return idx;
            }
        }

        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName)
        {
            if (!string.IsNullOrEmpty(caption)) WriteLine(caption);
            if (!string.IsNullOrEmpty(message)) WriteLine(message);
            if (string.IsNullOrEmpty(userName))
            {
                Write("User: ");
                userName = ReadLine();
            }
            Write("Password for " + userName + ": ");
            return new PSCredential(userName, ReadLineAsSecureString());
        }

        public override PSCredential PromptForCredential(string caption, string message, string userName, string targetName,
            PSCredentialTypes allowedCredentialTypes, PSCredentialUIOptions options)
        {
            return PromptForCredential(caption, message, userName, targetName);
        }

        public override void Write(string value) { Console.Write(value); }

        public override void Write(ConsoleColor foregroundColor, ConsoleColor backgroundColor, string value)
        {
            ConsoleColor fg = Console.ForegroundColor, bg = Console.BackgroundColor;
            Console.ForegroundColor = foregroundColor;
            Console.BackgroundColor = backgroundColor;
            Console.Write(value);
            Console.ForegroundColor = fg;
            Console.BackgroundColor = bg;
        }

        public override void WriteLine(string value) { Console.WriteLine(value); }

        private static void Colored(ConsoleColor c, string value, bool err)
        {
            ConsoleColor fg = Console.ForegroundColor;
            Console.ForegroundColor = c;
            if (err) Console.Error.WriteLine(value); else Console.WriteLine(value);
            Console.ForegroundColor = fg;
        }

        public override void WriteErrorLine(string value) { Colored(ConsoleColor.Red, value, true); }
        public override void WriteDebugLine(string message) { Colored(ConsoleColor.Yellow, "DEBUG: " + message, false); }
        public override void WriteVerboseLine(string message) { Colored(ConsoleColor.Yellow, "VERBOSE: " + message, false); }
        public override void WriteWarningLine(string message) { Colored(ConsoleColor.Yellow, "WARNING: " + message, false); }
        public override void WriteProgress(long sourceId, ProgressRecord record) { }
    }

    internal class ExeRawUI : PSHostRawUserInterface
    {
        public override ConsoleColor BackgroundColor
        {
            get { return Console.BackgroundColor; }
            set { Console.BackgroundColor = value; }
        }

        public override ConsoleColor ForegroundColor
        {
            get { return Console.ForegroundColor; }
            set { Console.ForegroundColor = value; }
        }

        public override Size BufferSize
        {
            get { try { return new Size(Console.BufferWidth, Console.BufferHeight); } catch { return new Size(120, 50); } }
            set { try { Console.SetBufferSize(value.Width, value.Height); } catch { } }
        }

        public override Coordinates CursorPosition
        {
            get { try { return new Coordinates(Console.CursorLeft, Console.CursorTop); } catch { return new Coordinates(0, 0); } }
            set { try { Console.SetCursorPosition(value.X, value.Y); } catch { } }
        }

        public override int CursorSize
        {
            get { try { return Console.CursorSize; } catch { return 25; } }
            set { try { Console.CursorSize = value; } catch { } }
        }

        public override bool KeyAvailable
        {
            get { try { return Console.KeyAvailable; } catch { return false; } }
        }

        public override Size MaxPhysicalWindowSize
        {
            get { try { return new Size(Console.LargestWindowWidth, Console.LargestWindowHeight); } catch { return new Size(120, 50); } }
        }

        public override Size MaxWindowSize
        {
            get { try { return new Size(Console.LargestWindowWidth, Console.LargestWindowHeight); } catch { return new Size(120, 50); } }
        }

        public override Coordinates WindowPosition
        {
            get { try { return new Coordinates(Console.WindowLeft, Console.WindowTop); } catch { return new Coordinates(0, 0); } }
            set { try { Console.SetWindowPosition(value.X, value.Y); } catch { } }
        }

        public override Size WindowSize
        {
            get { try { return new Size(Console.WindowWidth, Console.WindowHeight); } catch { return new Size(120, 50); } }
            set { try { Console.SetWindowSize(value.Width, value.Height); } catch { } }
        }

        public override string WindowTitle
        {
            get { try { return Console.Title; } catch { return ""; } }
            set { try { Console.Title = value; } catch { } }
        }

        public override void FlushInputBuffer()
        {
            try { while (Console.KeyAvailable) Console.ReadKey(true); } catch { }
        }

        public override BufferCell[,] GetBufferContents(Rectangle rectangle)
        {
            return new BufferCell[0, 0];
        }

        public override KeyInfo ReadKey(ReadKeyOptions options)
        {
            ConsoleKeyInfo k = Console.ReadKey((options & ReadKeyOptions.NoEcho) != 0);
            ControlKeyStates st = 0;
            if ((k.Modifiers & ConsoleModifiers.Shift) != 0) st |= ControlKeyStates.ShiftPressed;
            if ((k.Modifiers & ConsoleModifiers.Alt) != 0) st |= ControlKeyStates.LeftAltPressed;
            if ((k.Modifiers & ConsoleModifiers.Control) != 0) st |= ControlKeyStates.LeftCtrlPressed;
            return new KeyInfo((int)k.Key, k.KeyChar, st, true);
        }

        public override void ScrollBufferContents(Rectangle source, Coordinates destination, Rectangle clip, BufferCell fill) { }

        public override void SetBufferContents(Coordinates origin, BufferCell[,] contents) { }

        public override void SetBufferContents(Rectangle rectangle, BufferCell fill)
        {
            // Clear-Host passes a (-1,-1,-1,-1) rectangle
            if (rectangle.Left == -1 && rectangle.Top == -1)
                try { Console.Clear(); } catch { }
        }
    }
}
EOF

# ---------------------------------------------------------------- build
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

echo "Script : $INPUT"
for m in "${MODULES[@]}"; do echo "Module : $(realpath "$m")"; done
[[ ${#MODULES[@]} -eq 0 ]] && echo "Module : (none)"
echo "Admin  : $REQUIRE_ADMIN"
echo "Output : $OUTPUT"
echo

dotnet build "$BUILD_DIR/host.csproj" -c Release -nologo -v quiet -o "$BUILD_DIR/out"

mkdir -p "$(dirname "$OUTPUT")"
cp "$BUILD_DIR/out/$BASE.exe" "$OUTPUT"
echo
echo "Built $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
