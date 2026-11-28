#define MyAppName "PhoneProxy"
#define MyAppVersion "4.0.0"
#define MyAppPublisher "gedouluhui"
#define MyAppExeName "tray.exe"

[Setup]
AppId={{8F3B9A54-74C1-4D9A-9B0E-2A6F5D8C1E77}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=PhoneProxy-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
DisableProgramGroupPage=yes
CloseApplications=yes

[Files]
Source: "..\app\*.py"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "..\app\release-public.pem"; DestDir: "{app}\app"; Flags: ignoreversion
Source: "..\_proxy\*.py"; DestDir: "{app}\_proxy"; Excludes: "test_*.py"; Flags: ignoreversion
Source: "..\_proxy\bin\*"; DestDir: "{app}\_proxy\bin"; Flags: ignoreversion
Source: "..\_proxy\rulesets\*"; DestDir: "{app}\_proxy\rulesets"; Flags: ignoreversion
Source: "..\runtime\python\*"; DestDir: "{app}\runtime\python"; Flags: ignoreversion recursesubdirs
Source: "..\runtime\tray.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\version.txt"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{localappdata}\PhoneProxy\data"
Name: "{localappdata}\PhoneProxy\data\logs"
Name: "{localappdata}\PhoneProxy\runtime"
Name: "{localappdata}\PhoneProxy\updates"

[Icons]
Name: "{group}\PhoneProxy"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{group}\Uninstall PhoneProxy"; Filename: "{uninstallexe}"
Name: "{autodesktop}\PhoneProxy"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"

[Run]
Filename: "{app}\runtime\python\python.exe"; Parameters: """{app}\app\make_install_manifest.py"" --install-dir ""{app}"" --output ""{app}\install-manifest.json"""; Flags: runhidden waituntilterminated
Filename: "{app}\runtime\python\python.exe"; Parameters: """{app}\app\broker.py"" tun-stop --data-dir ""{localappdata}\PhoneProxy\data"""; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\runtime\python\python.exe"; Parameters: """{app}\app\broker.py"" tun-stop --data-dir ""{localappdata}\PhoneProxy\data"""; Flags: runhidden waituntilterminated

[Code]
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    // User data is intentionally preserved. The verified broker stop above
    // restores direct networking; only the read-only installation is removed.
  end;
end;
