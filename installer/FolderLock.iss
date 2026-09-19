# FolderLock 安装包脚本（Inno Setup 6）
# 使用前先执行：dotnet publish src\FolderLock.App\FolderLock.App.csproj -c Release -p:PublishProfile=win-x64
# 然后用 Inno Setup Compiler 打开本文件编译，或命令行：ISCC.exe installer\FolderLock.iss

#define AppName "FolderLock"
#define AppVersion "1.0.0"
#define AppPublisher "FolderLock"
#define AppExeName "FolderLock.App.exe"
#define PublishDir "..\src\FolderLock.App\bin\Release\net8.0-windows\publish\win-x64"

[Setup]
AppId={{9B2E4C1F-4B7A-4C3E-9E5D-6A1C2F8B0D31}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=..\artifacts
OutputBaseFilename=FolderLock-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#AppExeName}"; Parameters: "--uninstall-shell"; Flags: runhidden; RunOnceId: "CleanupShellMenu"
