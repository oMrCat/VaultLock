# FolderLock 安装包脚本（Inno Setup 6）
# 使用前先执行：dotnet publish src\FolderLock.App\FolderLock.App.csproj -c Release -p:PublishProfile=win-x64
# 然后用 Inno Setup Compiler 打开本文件编译，或命令行：ISCC.exe installer\FolderLock.iss

#define AppName "FolderLock"
#define AppVersion "1.0.0"
#define AppPublisher "FolderLock"
#define AppExeName "FolderLock.App.exe"
#define PublishDir "..\artifacts\publish\win-x64"

; 代码签名方案：本项目采用“发布前预签名”。
;   - installer\publish.ps1 -Sign 先对所有 exe（含 FolderLock.Service.exe）签名并校验；
;   - Inno 按原样复制已签名文件，签名在解包后依然有效；
;   - 编译出的安装包本身由 installer\sign.ps1 的 InstallerFiles 参数追加签名。
; 如需改用 Inno 内置 SignTool（可额外签名卸载器），取消下面的 [Setup] 注释行，
; 并在编译时传入指纹：ISCC.exe /DSignThumbprint=<证书指纹> installer\FolderLock.iss
#ifndef SignThumbprint
  #define SignThumbprint ""
#endif
#ifndef TimestampUrl
  #define TimestampUrl "http://timestamp.digicert.com"
#endif

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
SetupIconFile=../src/FolderLock.App/Assets/app.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}
; 可选的内置签名（模板，默认关闭；解开注释即可同时签名安装包与卸载器）：
; SignTool=signtool sign /fd SHA256 /tr {#TimestampUrl} /td SHA256 /sha1 {#SignThumbprint} $f
; SignedUninstaller=yes

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加任务:"

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
; 程序目录仅管理员可写（防止普通用户替换 exe 提权）；机器级数据目录允许已登录用户维护 watchlist。
Name: "{app}"; Permissions: admins-full users-read
Name: "{commonappdata}\FolderLock"; Permissions: admins-full users-modify

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Parameters: "--install-service"; Flags: runhidden waituntilterminated; StatusMsg: "安装 FolderLock 守护服务（LocalService 低权限账户）..."
Filename: "{app}\{#AppExeName}"; Description: "启动 {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\{#AppExeName}"; Parameters: "--uninstall-service"; Flags: runhidden; RunOnceId: "RemoveService"
Filename: "{app}\{#AppExeName}"; Parameters: "--uninstall-shell"; Flags: runhidden; RunOnceId: "CleanupShellMenu"
