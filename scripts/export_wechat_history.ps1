<#
.SYNOPSIS
Exports all locally available WeChat databases into one DuckDB file, or caches
validated database keys for later exports.

.DESCRIPTION
Uses chatlog's key extraction and database decryption code, then imports every
physical table and readable view from every decrypted WeChat SQLite database.
The default destination is G:/wechat/wechat-history.duckdb.

With -SaveKeysOnly, the script skips database staging and DuckDB entirely. It
extracts and validates keys for every currently running WeChat account. When an
encrypted BackupFiles/Backup.db is present, it also recovers and validates that
database's distinct key. The keys are merged into chatlog.json, that plaintext
file is protected with a restricted Windows ACL, and the script exits. A
short-lived ACL-protected key staging directory prevents even temporary key
files from inheriting broad permissions. Keep WeChat running throughout this
mode.

All database rows and in-database BLOBs are included. External attachment files
(images, videos, and documents stored beside the databases) remain in their
original WeChat data directories; their database metadata and paths are kept.
Contacts are also normalized into chatlog.contacts: remark is the short display
name, while description is the longer profile note (Windows v3 Reserved6 and
the v4 description column). Darwin v3 descriptions remain empty until their
storage has been verified. Windows v3 contact-label definitions and ordered
contact assignments are exported to chatlog.contact_tag_definitions and
chatlog.contact_tags; unresolved LabelIDList values are retained without an
invented label name.
For Windows v3 contacts, verified Contact.ExtraBuf profile data is decoded into
signature, raw add_scene, add_scene_enum, add_scene_string, country, province,
and city columns in chatlog.contacts. Unknown add-scene values retain their raw
integer and receive explicit UNKNOWN enum/string values instead of a guessed
meaning.
The original ExtraBuf BLOB remains available in the lossless raw Contact table,
and malformed future values are reported without dropping the contact. Add time
is not synthesized because no verified local Windows field stores it.
Phone-backup BAK_*_TEXT archives are decrypted into lossless raw protobuf
message records and canonical message rows. BAK_*_MEDIA payloads remain beside
the source archive; every media index row and archive-file extent is retained.
WeChat's proprietary full-text tokenizer is unavailable outside WeChat, so its
derived virtual facades are catalogued while every physical FTS shadow table is
still imported.

The first run may use the network to provision the Go toolchain, Python, and
DuckDB components when they are not already available locally.

For accounts whose key has never been cached by chatlog, sign in and leave
WeChat running when the export starts. The exporter captures every needed live
key in memory, then checks for WeChat and Weixin processes before creating
source snapshots. When either is running, it prompts you to exit WeChat
completely and does not continue until the processes have stopped. If live key
capture fails, use chatlog's "get key" action and rerun. In a non-interactive
host the exporter fails with the exit instruction instead of waiting.

.PARAMETER OutputPath
Destination directory or a full .duckdb file path. Defaults to G:/wechat/.

.PARAMETER ConfigPath
Path to chatlog.json. Defaults to %USERPROFILE%/.chatlog/chatlog.json.

.PARAMETER BackupKeyFile
Optional file containing the separately recovered 32-byte BackupFiles key as
hexadecimal text. An explicit file overrides the backup_key cached in
chatlog.json. The key is never stored in the DuckDB or staging manifest.

.PARAMETER Force
Replace an existing destination DuckDB after the new export succeeds.

.PARAMETER Delta
Reuse an existing export and replace only source-database partitions whose
cryptographic snapshot has changed. The existing DuckDB is copied to a private
working file and is not replaced unless the delta import succeeds completely.
Delta and Force are mutually exclusive.

Exports created before delta metadata was introduced are upgraded safely on
their first delta run. An unchanged phone backup can be bootstrapped without
its deleted key when the legacy Backup.db metadata, NTFS ChangeTime cutoff,
archive inventory, and all stored ciphertext-segment hashes still match. A new
or changed phone backup still requires BackupKeyFile. Later unchanged phone
backups can be reused directly from their cryptographic fingerprints.

.PARAMETER AllowPartial
Produce an export even when a discovered account or database cannot be read.
The omissions are recorded in the DuckDB catalog tables.

.PARAMETER KeepDecrypted
Keep the temporary decrypted SQLite snapshot beside the DuckDB output.

.PARAMETER SaveKeysOnly
Extract and validate the ordinary database key, the v4 image key when
available, and the distinct BackupFiles key when an encrypted Backup.db is
present. Atomically merge the keys into ConfigPath and exit without creating a
decrypted-database stage, preparation manifest, export lock, or DuckDB. A
private key-cache staging directory and lock are normally removed before the
script exits; if cleanup fails, the script reports the still ACL-protected path.
-CacheKeysOnly is an alias for this option.

chatlog.json keeps these keys as plaintext for compatibility with chatlog. The
script restricts the file ACL to the current user, SYSTEM, and Administrators.
For a custom ConfigPath, its parent must not grant other principals write or
delete access. Keep WeChat running; this mode does not ask you to exit it.

.EXAMPLE
./scripts/export_wechat_history.ps1

.EXAMPLE
./scripts/export_wechat_history.ps1 D:/backups/wechat.duckdb -Force

.EXAMPLE
./scripts/export_wechat_history.ps1 G:/wechat/ -Delta

.EXAMPLE
./scripts/export_wechat_history.ps1 -SaveKeysOnly
#>


[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [Alias("Target")]
    [string]$OutputPath = "G:/wechat/",

    [string]$ConfigPath = $(
        if ([string]::IsNullOrWhiteSpace($env:CHATLOG_DIR)) {
            Join-Path $env:USERPROFILE ".chatlog\chatlog.json"
        } else {
            Join-Path $env:CHATLOG_DIR "chatlog.json"
        }
    ),

    [string]$BackupKeyFile,

    [switch]$Force,

    [switch]$Delta,

    [switch]$AllowPartial,

    [switch]$KeepDecrypted,

    [Alias("CacheKeysOnly")]
    [switch]$SaveKeysOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Delta -and $Force) {
    throw "-Delta and -Force are mutually exclusive."
}

$OutputWasSpecified = $PSBoundParameters.ContainsKey("OutputPath")
$ConfigWasSpecified = $PSBoundParameters.ContainsKey("ConfigPath")

if ($SaveKeysOnly) {
    $Conflicts = @()
    if ($OutputWasSpecified) { $Conflicts += "-OutputPath" }
    if ($PSBoundParameters.ContainsKey("BackupKeyFile")) { $Conflicts += "-BackupKeyFile" }
    if ($Force) { $Conflicts += "-Force" }
    if ($Delta) { $Conflicts += "-Delta" }
    if ($AllowPartial) { $Conflicts += "-AllowPartial" }
    if ($KeepDecrypted) { $Conflicts += "-KeepDecrypted" }
    if ($Conflicts.Count -ne 0) {
        throw "-SaveKeysOnly cannot be combined with: $($Conflicts -join ', ')."
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir
$GoScript = Join-Path $ScriptDir "export_wechat_history.go"
$BackupKeyRecoveryScript = Join-Path $ScriptDir "recover_wechat_backup_key.go"
$PythonScript = Join-Path $ScriptDir "export_wechat_history.py"
$BackupPythonModule = Join-Path $ScriptDir "wechat_backup_archive.py"

$RequiredScripts = @($GoScript)
if ($SaveKeysOnly) {
    $RequiredScripts += $BackupKeyRecoveryScript
} else {
    $RequiredScripts += @($PythonScript, $BackupPythonModule)
}
foreach ($RequiredScript in $RequiredScripts) {
    if (-not (Test-Path -LiteralPath $RequiredScript -PathType Leaf)) {
        throw "Required export helper is missing: $RequiredScript"
    }
}

$LocalGo = Join-Path $ProjectRoot "go\bin\go.exe"
if (Test-Path -LiteralPath $LocalGo) {
    $GoExe = $LocalGo
} else {
    $GoCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $GoCommand) {
        throw "Go was not found. Keep the bundled go/ directory or install Go 1.25+."
    }
    $GoExe = $GoCommand.Source
}

function Get-PrivateChatlogSids {
    $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $CurrentSid) {
        throw "Could not determine the current Windows user SID."
    }

    $SidsByValue = @{}
    foreach ($Sid in @(
        $CurrentSid,
        [Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    )) {
        $SidsByValue[$Sid.Value] = $Sid
    }
    return $SidsByValue
}

function Assert-PrivateChatlogAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$AllowInherited,
        [switch]$RequireDirectoryInheritance
    )

    $SidsByValue = Get-PrivateChatlogSids
    $Check = Get-Acl -LiteralPath $LiteralPath
    if (-not $AllowInherited -and -not $Check.AreAccessRulesProtected) {
        throw "The private key-cache ACL still inherits permissions."
    }

    $SeenSidValues = @{}
    $FullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $RequiredInheritance = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    foreach ($Rule in @($Check.Access)) {
        $RuleSid = $Rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if (
            ((-not $AllowInherited) -and $Rule.IsInherited) -or
            $Rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            -not $SidsByValue.ContainsKey($RuleSid) -or
            (($Rule.FileSystemRights -band $FullControl) -ne $FullControl) -or
            ($RequireDirectoryInheritance -and
                (($Rule.InheritanceFlags -band $RequiredInheritance) -ne $RequiredInheritance))
        ) {
            throw "The private key-cache ACL contains an unexpected access rule."
        }
        $SeenSidValues[$RuleSid] = $true
    }
    foreach ($SidValue in $SidsByValue.Keys) {
        if (-not $SeenSidValues.ContainsKey($SidValue)) {
            throw "The private key-cache ACL is missing a required access rule."
        }
    }
}

function Set-PrivateChatlogAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$Directory
    )

    try {
        Assert-PrivateChatlogAcl -LiteralPath $LiteralPath -RequireDirectoryInheritance:$Directory
        return
    } catch {
        # Build and apply a clean DACL below. Do not reuse the descriptor from
        # Get-Acl: after File.Replace it can include SACL control bits that make
        # Set-Acl incorrectly require SeSecurityPrivilege.
    }

    $SidsByValue = Get-PrivateChatlogSids
    $InheritanceFlags = [Security.AccessControl.InheritanceFlags]::None
    if ($Directory) {
        $InheritanceFlags = (
            [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        )
    }

    if ($Directory) {
        $Acl = [Security.AccessControl.DirectorySecurity]::new()
    } else {
        $Acl = [Security.AccessControl.FileSecurity]::new()
    }
    $Acl.SetAccessRuleProtection($true, $false)
    foreach ($Sid in $SidsByValue.Values) {
        $Rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $InheritanceFlags,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    $AclExtensions = "System.IO.FileSystemAclExtensions" -as [type]
    if ($null -ne $AclExtensions) {
        if ($Directory) {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.DirectoryInfo]::new($LiteralPath),
                $Acl
            )
        } else {
            [IO.FileSystemAclExtensions]::SetAccessControl(
                [IO.FileInfo]::new($LiteralPath),
                $Acl
            )
        }
    } else {
        # Windows PowerShell on .NET Framework exposes these as instance
        # methods rather than through FileSystemAclExtensions.
        $Item = Get-Item -LiteralPath $LiteralPath
        $Item.SetAccessControl($Acl)
    }
    Assert-PrivateChatlogAcl -LiteralPath $LiteralPath -RequireDirectoryInheritance:$Directory
}

function Assert-PrivateChatlogParent {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $SidsByValue = Get-PrivateChatlogSids
    $Acl = Get-Acl -LiteralPath $LiteralPath
    $OwnerSid = $Acl.Owner
    try {
        $OwnerSid = ([Security.Principal.NTAccount]$Acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    } catch {
        try {
            $OwnerSid = ([Security.Principal.SecurityIdentifier]$Acl.Owner).Value
        } catch {
            throw "Could not verify the key-cache parent directory owner."
        }
    }
    if (-not $SidsByValue.ContainsKey($OwnerSid)) {
        throw "The key-cache parent directory is owned by an unapproved principal."
    }

    $DangerousRights = (
        [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::AppendData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    )
    foreach ($Rule in @($Acl.Access)) {
        if ($Rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            continue
        }
        $RuleSid = $Rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if (
            -not $SidsByValue.ContainsKey($RuleSid) -and
            (($Rule.FileSystemRights -band $DangerousRights) -ne 0)
        ) {
            throw "The key-cache parent directory grants another principal write or delete access."
        }
    }
}

function Remove-PrivateChatlogStage {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $ResolvedPath = [IO.Path]::GetFullPath($Path)
    $ResolvedParent = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $Leaf = [IO.Path]::GetFileName($ResolvedPath)
    if (
        -not $ResolvedPath.StartsWith($ResolvedParent, [StringComparison]::OrdinalIgnoreCase) -or
        -not $Leaf.StartsWith(".chatlog-key-staging-", [StringComparison]::Ordinal)
    ) {
        throw "Refusing to remove a key-cache staging directory outside its expected parent: $ResolvedPath"
    }
    [IO.Directory]::Delete($ResolvedPath, $true)
}

function New-PrivateChatlogStage {
    param([Parameter(Mandatory = $true)][string]$Parent)

    $StagePath = Join-Path $Parent (".chatlog-key-staging-{0}" -f [Guid]::NewGuid().ToString("N"))
    try {
        [void][IO.Directory]::CreateDirectory($StagePath)
        Set-PrivateChatlogAcl -LiteralPath $StagePath -Directory

        $ProbePath = Join-Path $StagePath ".acl-inheritance-probe"
        $Probe = [IO.File]::Open(
            $ProbePath,
            [IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        $Probe.Dispose()
        Assert-PrivateChatlogAcl -LiteralPath $ProbePath -AllowInherited
        [IO.File]::Delete($ProbePath)
        return $StagePath
    } catch {
        try {
            Remove-PrivateChatlogStage -Path $StagePath -Parent $Parent
        } catch {
            # The directory contains no key material yet. Preserve the original
            # ACL/setup error, which is the actionable failure.
        }
        throw
    }
}

function Test-SQLiteDatabaseHeader {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $Expected = [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0")
    $Actual = [byte[]]::new($Expected.Length)
    $Share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    try {
        $Stream = [IO.File]::Open(
            $LiteralPath,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            $Share
        )
        try {
            if ($Stream.Read($Actual, 0, $Actual.Length) -ne $Actual.Length) {
                return $false
            }
        } finally {
            $Stream.Dispose()
        }
    } catch {
        throw "Could not inspect a phone-backup database before key recovery: $LiteralPath"
    }
    for ($Index = 0; $Index -lt $Expected.Length; $Index++) {
        if ($Actual[$Index] -ne $Expected[$Index]) {
            return $false
        }
    }
    return $true
}

function Get-EncryptedPhoneBackupDatabases {
    param([Parameter(Mandatory = $true)][string]$ConfigPath)

    try {
        $Document = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
    } catch {
        throw "Could not inspect chatlog.json for phone-backup databases."
    }
    if ($null -eq $Document) {
        throw "chatlog.json contains no configuration object."
    }
    $HistoryProperty = $Document.PSObject.Properties["history"]
    $Accounts = if ($null -ne $HistoryProperty -and @($HistoryProperty.Value).Count -gt 0) {
        @($HistoryProperty.Value)
    } else {
        @($Document)
    }

    $Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Results = @()
    foreach ($Account in $Accounts) {
        $DataDirProperty = $Account.PSObject.Properties["data_dir"]
        if ($null -eq $DataDirProperty -or [string]::IsNullOrWhiteSpace([string]$DataDirProperty.Value)) {
            continue
        }
        $BackupRoot = Join-Path ([string]$DataDirProperty.Value) "BackupFiles"
        if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
            continue
        }
        $Version = 0
        $VersionProperty = $Account.PSObject.Properties["version"]
        if ($null -ne $VersionProperty) {
            [void][int]::TryParse([string]$VersionProperty.Value, [ref]$Version)
        }
        $Platform = "windows"
        $PlatformProperty = $Account.PSObject.Properties["platform"]
        if ($null -ne $PlatformProperty -and -not [string]::IsNullOrWhiteSpace([string]$PlatformProperty.Value)) {
            $Platform = ([string]$PlatformProperty.Value).Trim().ToLowerInvariant()
        }
        $Pending = [Collections.Generic.Stack[string]]::new()
        $Pending.Push([IO.Path]::GetFullPath($BackupRoot))
        while ($Pending.Count -gt 0) {
            $DirectoryPath = $Pending.Pop()
            $Directory = Get-Item -LiteralPath $DirectoryPath -Force
            if (($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A configured BackupFiles directory contains a reparse point: $DirectoryPath"
            }
            try {
                $Entries = @($Directory.EnumerateFileSystemInfos())
            } catch {
                throw "Could not inspect a configured BackupFiles directory: $DirectoryPath"
            }
            foreach ($Entry in $Entries) {
                if (($Entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                    throw "A configured BackupFiles directory contains a reparse point: $($Entry.FullName)"
                }
                if (($Entry.Attributes -band [IO.FileAttributes]::Directory) -ne 0) {
                    $Pending.Push($Entry.FullName)
                    continue
                }
                if (-not $Entry.Name.Equals("Backup.db", [StringComparison]::OrdinalIgnoreCase)) {
                    continue
                }
                $FullPath = [IO.Path]::GetFullPath($Entry.FullName)
                if ($Seen.Add($FullPath) -and -not (Test-SQLiteDatabaseHeader -LiteralPath $FullPath)) {
                    $Results += [pscustomobject]@{
                        Path = $FullPath
                        Platform = $Platform
                        Version = $Version
                    }
                }
            }
        }
    }
    return $Results
}

function Get-ChatlogConfigState {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $Item = Get-Item -LiteralPath $LiteralPath
    return [pscustomobject]@{
        Length = [int64]$Item.Length
        LastWriteUtcTicks = [int64]$Item.LastWriteTimeUtc.Ticks
        CreationUtcTicks = [int64]$Item.CreationTimeUtc.Ticks
        SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LiteralPath).Hash
    }
}

function Assert-ChatlogConfigState {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Expected,
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "chatlog.json disappeared while keys were being decoded; nothing was replaced."
    }
    $Actual = Get-ChatlogConfigState -LiteralPath $LiteralPath
    if (
        $Actual.Length -ne $Expected.Length -or
        $Actual.LastWriteUtcTicks -ne $Expected.LastWriteUtcTicks -or
        $Actual.CreationUtcTicks -ne $Expected.CreationUtcTicks -or
        $Actual.SHA256 -cne $Expected.SHA256
    ) {
        throw "chatlog.json changed while keys were being decoded; nothing was replaced."
    }
}

function Test-ChatlogConfigContentMatches {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Expected,
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        return $false
    }
    $Actual = Get-ChatlogConfigState -LiteralPath $LiteralPath
    return (
        $Actual.Length -eq $Expected.Length -and
        $Actual.SHA256 -ceq $Expected.SHA256
    )
}

if ($SaveKeysOnly) {
    if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
        throw "-ConfigPath must name a chatlog.json file."
    }

    $ConfigPath = [IO.Path]::GetFullPath($ConfigPath)
    if ((Test-Path -LiteralPath $ConfigPath) -and -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
        throw "The chatlog config path is not a regular file: $ConfigPath"
    }
    $ConfigDir = Split-Path -Parent $ConfigPath
    if ([string]::IsNullOrWhiteSpace($ConfigDir)) {
        throw "The chatlog config path must have a parent directory."
    }
    if ((Test-Path -LiteralPath $ConfigDir) -and -not (Test-Path -LiteralPath $ConfigDir -PathType Container)) {
        throw "The chatlog config parent is not a directory: $ConfigDir"
    }
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    try {
        Assert-PrivateChatlogParent -LiteralPath $ConfigDir
    } catch {
        throw "Secure key caching is unavailable at '$ConfigPath'; no new keys were written. $($_.Exception.Message)"
    }

    $KeyConfigLock = $null
    $KeyStageDir = $null
    $KeyStageConfig = $null
    $PreviousCgo = $env:CGO_ENABLED
    $PreviousPrivateKeyStage = $env:CHATLOG_KEY_CACHE_PRIVATE_STAGE
    $KeysPublished = $false
    $TargetWasReplaced = $false
    $PreserveKeyStage = $false
    try {
        $LockPath = Join-Path $ConfigDir (".{0}.key-cache.lock" -f [IO.Path]::GetFileName($ConfigPath))
        try {
            $KeyConfigLock = [IO.FileStream]::new(
                $LockPath,
                [IO.FileMode]::OpenOrCreate,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None,
                4096,
                [IO.FileOptions]::DeleteOnClose
            )
        } catch {
            throw "Could not acquire the key-cache lock for '$ConfigPath'. Another key-cache run may be active. $($_.Exception.Message)"
        }

        $ConfigExisted = Test-Path -LiteralPath $ConfigPath -PathType Leaf
        $OriginalConfigState = $null
        if ($ConfigExisted) {
            try {
                Set-PrivateChatlogAcl -LiteralPath $ConfigPath
                $OriginalConfigState = Get-ChatlogConfigState -LiteralPath $ConfigPath
            } catch {
                throw "Secure key caching is unavailable at '$ConfigPath'; no new keys were written. $($_.Exception.Message)"
            }
        }

        try {
            $KeyStageDir = New-PrivateChatlogStage -Parent $ConfigDir
        } catch {
            throw "Secure key caching is unavailable at '$ConfigPath'; no new keys were written. $($_.Exception.Message)"
        }
        $KeyStageConfig = Join-Path $KeyStageDir ([IO.Path]::GetFileName($ConfigPath))
        if ($ConfigExisted) {
            [IO.File]::Copy($ConfigPath, $KeyStageConfig, $false)
            Set-PrivateChatlogAcl -LiteralPath $KeyStageConfig
            if (-not (Test-ChatlogConfigContentMatches -Expected $OriginalConfigState -LiteralPath $KeyStageConfig)) {
                throw "chatlog.json changed while its protected working copy was being created; nothing was replaced."
            }
        }

        $env:CGO_ENABLED = "0"
        $env:CHATLOG_KEY_CACHE_PRIVATE_STAGE = $KeyStageDir
        $KeyArgs = @("run", $GoScript, "--save-keys-only", "--config", $KeyStageConfig)
        Push-Location $ProjectRoot
        try {
            $KeyHelperOutput = @(& $GoExe @KeyArgs 2>&1)
            $KeyHelperExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        if ($KeyHelperExitCode -ne 0) {
            $Details = ($KeyHelperOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
            throw "WeChat key decoding failed with exit code $KeyHelperExitCode.$([Environment]::NewLine)$Details"
        }

        if (-not (Test-Path -LiteralPath $KeyStageConfig -PathType Leaf)) {
            throw "The key helper did not create chatlog.json."
        }

        $EncryptedPhoneBackups = @(Get-EncryptedPhoneBackupDatabases -ConfigPath $KeyStageConfig)
        if ($EncryptedPhoneBackups.Count -gt 0) {
            $Platforms = @($EncryptedPhoneBackups | ForEach-Object { $_.Platform } | Sort-Object -Unique)
            $Versions = @($EncryptedPhoneBackups | ForEach-Object { [int]$_.Version } | Sort-Object -Unique)
            if ($Platforms.Count -ne 1 -or $Platforms[0] -cne "windows") {
                throw "Automatic BackupFiles key recovery currently requires Windows WeChat."
            }
            if ($Versions.Count -ne 1 -or $Versions[0] -notin @(3, 4)) {
                throw "Automatic BackupFiles key recovery requires one supported Windows database version (3 or 4)."
            }

            $RunningPIDs = @(
                Get-Process -ErrorAction SilentlyContinue |
                    Where-Object { $_.ProcessName -in @("WeChat", "Weixin") } |
                    ForEach-Object { [string]$_.Id } |
                    Sort-Object -Unique
            )
            if ($RunningPIDs.Count -eq 0) {
                throw "An encrypted BackupFiles/Backup.db needs its distinct key. Start and sign in to WeChat, then rerun -SaveKeysOnly."
            }

            $RecoveredBackupKeyPath = Join-Path $KeyStageDir (".backup-key-{0}.txt" -f [Guid]::NewGuid().ToString("N"))
            try {
                $RecoveryArgs = @(
                    "run",
                    $BackupKeyRecoveryScript,
                    "--pids", ($RunningPIDs -join ","),
                    "--version", [string]$Versions[0],
                    "--output", $RecoveredBackupKeyPath
                )
                foreach ($PhoneBackup in $EncryptedPhoneBackups) {
                    $RecoveryArgs += @("--database", [string]$PhoneBackup.Path)
                }
                Push-Location $ProjectRoot
                try {
                    $RecoveryOutput = @(& $GoExe @RecoveryArgs 2>&1)
                    $RecoveryExitCode = $LASTEXITCODE
                } finally {
                    Pop-Location
                }
                if ($RecoveryExitCode -ne 0) {
                    $Details = ($RecoveryOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
                    throw "BackupFiles key decoding failed with exit code $RecoveryExitCode.$([Environment]::NewLine)$Details"
                }
                if (-not (Test-Path -LiteralPath $RecoveredBackupKeyPath -PathType Leaf)) {
                    throw "The BackupFiles key helper did not create its protected result."
                }
                Set-PrivateChatlogAcl -LiteralPath $RecoveredBackupKeyPath

                $CacheBackupKeyArgs = @(
                    "run",
                    $GoScript,
                    "--cache-backup-key-file", $RecoveredBackupKeyPath,
                    "--config", $KeyStageConfig
                )
                Push-Location $ProjectRoot
                try {
                    $CacheBackupKeyOutput = @(& $GoExe @CacheBackupKeyArgs 2>&1)
                    $CacheBackupKeyExitCode = $LASTEXITCODE
                } finally {
                    Pop-Location
                }
                if ($CacheBackupKeyExitCode -ne 0) {
                    $Details = ($CacheBackupKeyOutput | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine
                    throw "Could not cache the validated BackupFiles key (exit code $CacheBackupKeyExitCode).$([Environment]::NewLine)$Details"
                }
            } finally {
                if (Test-Path -LiteralPath $RecoveredBackupKeyPath -PathType Leaf) {
                    [IO.File]::Delete($RecoveredBackupKeyPath)
                }
            }
        }

        Set-PrivateChatlogAcl -LiteralPath $KeyStageConfig
        $UpdatedConfigState = Get-ChatlogConfigState -LiteralPath $KeyStageConfig

        if ($ConfigExisted) {
            Assert-ChatlogConfigState -Expected $OriginalConfigState -LiteralPath $ConfigPath
            # File.Replace is atomic and is available in both Windows
            # PowerShell and PowerShell 7. Its required rollback file remains
            # inside the ACL-protected staging directory and is deleted with it.
            $ProtectedPreviousConfig = Join-Path $KeyStageDir ".previous-chatlog.json"
            [IO.File]::Replace($KeyStageConfig, $ConfigPath, $ProtectedPreviousConfig)
            $TargetWasReplaced = $true
            Set-PrivateChatlogAcl -LiteralPath $ProtectedPreviousConfig

            if (-not (Test-ChatlogConfigContentMatches -Expected $OriginalConfigState -LiteralPath $ProtectedPreviousConfig)) {
                # A non-cooperating writer won the small interval between the
                # state check and Replace. Restore that exact version, keeping
                # the rejected key-cache output inside the protected stage.
                $RejectedKeyConfig = Join-Path $KeyStageDir ".rejected-key-cache.json"
                $ConcurrentConfigState = Get-ChatlogConfigState -LiteralPath $ProtectedPreviousConfig
                [IO.File]::Replace($ProtectedPreviousConfig, $ConfigPath, $RejectedKeyConfig)
                Set-PrivateChatlogAcl -LiteralPath $ConfigPath
                Set-PrivateChatlogAcl -LiteralPath $RejectedKeyConfig
                $TargetWasReplaced = $false

                if (
                    -not (Test-ChatlogConfigContentMatches -Expected $ConcurrentConfigState -LiteralPath $ConfigPath) -or
                    -not (Test-ChatlogConfigContentMatches -Expected $UpdatedConfigState -LiteralPath $RejectedKeyConfig)
                ) {
                    $PreserveKeyStage = $true
                    throw "Concurrent chatlog.json updates continued during recovery. Protected recovery files remain at: $KeyStageDir"
                }
                throw "chatlog.json changed during atomic publication; the concurrent version was restored and no keys were saved."
            }
        } else {
            if (Test-Path -LiteralPath $ConfigPath) {
                throw "chatlog.json appeared while keys were being decoded; nothing was replaced."
            }
            [IO.File]::Move($KeyStageConfig, $ConfigPath)
            $TargetWasReplaced = $true
        }
        Set-PrivateChatlogAcl -LiteralPath $ConfigPath
        if (-not (Test-ChatlogConfigContentMatches -Expected $UpdatedConfigState -LiteralPath $ConfigPath)) {
            if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
                Set-PrivateChatlogAcl -LiteralPath $ConfigPath
            }
            throw "chatlog.json changed immediately after atomic publication; key persistence could not be confirmed."
        }
        $KeysPublished = $true
    } finally {
        $env:CGO_ENABLED = $PreviousCgo
        $env:CHATLOG_KEY_CACHE_PRIVATE_STAGE = $PreviousPrivateKeyStage
        if ($TargetWasReplaced -and -not $KeysPublished -and $ConfigExisted) {
            $PreserveKeyStage = $true
        }
        if (
            -not $PreserveKeyStage -and
            $null -ne $KeyStageDir -and
            (Test-Path -LiteralPath $KeyStageDir)
        ) {
            try {
                Remove-PrivateChatlogStage -Path $KeyStageDir -Parent $ConfigDir
            } catch {
                Write-Warning "Could not remove the ACL-protected key-cache staging directory at ${KeyStageDir}: $($_.Exception.Message)"
            }
        } elseif ($PreserveKeyStage -and $null -ne $KeyStageDir) {
            Write-Warning "Protected key-cache recovery files remain at: $KeyStageDir"
        }
        if ($null -ne $KeyConfigLock) {
            try {
                $KeyConfigLock.Dispose()
            } catch {
                Write-Warning "Could not release the key-cache lock at ${LockPath}: $($_.Exception.Message)"
            }
            $KeyConfigLock = $null
        }
    }

    if ($KeysPublished) {
        Write-Warning "chatlog.json contains plaintext WeChat database keys; keep this protected file private."
        Write-Host "Validated WeChat keys saved to: $ConfigPath" -ForegroundColor Green
    }
    return
}

$OutputPath = [IO.Path]::GetFullPath($OutputPath)

if ([IO.Path]::GetExtension($OutputPath) -ieq ".duckdb") {
    $DuckDBPath = $OutputPath
    $OutputDir = Split-Path -Parent $DuckDBPath
} else {
    $OutputDir = $OutputPath
    $DuckDBPath = Join-Path $OutputDir "wechat-history.duckdb"
}

if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    throw "The output path must have a parent directory."
}

$OutputDir = [IO.Path]::GetFullPath($OutputDir)
$DuckDBPath = [IO.Path]::GetFullPath($DuckDBPath)
$DuckDBWalPath = "$DuckDBPath.wal"

if ((Test-Path -LiteralPath $OutputDir) -and -not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
    throw "The output directory path is an existing file: $OutputDir"
}
if ((Test-Path -LiteralPath $DuckDBPath) -and -not (Test-Path -LiteralPath $DuckDBPath -PathType Leaf)) {
    throw "The DuckDB destination is an existing directory: $DuckDBPath"
}
if ((Test-Path -LiteralPath $DuckDBWalPath) -and -not (Test-Path -LiteralPath $DuckDBWalPath -PathType Leaf)) {
    throw "The DuckDB WAL path is an existing directory: $DuckDBWalPath"
}

New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

if ($ConfigWasSpecified -and -not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "The requested chatlog config does not exist: $ConfigPath"
}

$UvCommand = Get-Command uv -ErrorAction SilentlyContinue
if ($null -eq $UvCommand) {
    throw "uv was not found. Install uv so the DuckDB Python dependency can be run."
}

$RunID = [Guid]::NewGuid().ToString("N")
$StageDir = Join-Path $OutputDir ".wechat-history-staging-$RunID"
$ManifestPath = Join-Path $StageDir "manifest.json"
$BaselinePath = Join-Path $StageDir "baseline.json"
$RevalidatedBaselinePath = Join-Path $StageDir "baseline-revalidated.json"
$PartialDuckDBPath = "$DuckDBPath.partial-$RunID"
$PartialDuckDBWalPath = "$PartialDuckDBPath.wal"
$BackupDuckDBPath = "$DuckDBPath.backup-$RunID"
$BackupDuckDBWalPath = "$BackupDuckDBPath.wal"
$DestinationLockPath = "$DuckDBPath.export.lock"

function Remove-ExportStage {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $ResolvedPath = [IO.Path]::GetFullPath($Path)
    $ResolvedParent = [IO.Path]::GetFullPath($OutputDir).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $ResolvedPath.StartsWith($ResolvedParent, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove staging directory outside the output directory: $ResolvedPath"
    }

    Remove-Item -LiteralPath $ResolvedPath -Recurse -Force
}

function Get-DestinationState {
    param([string]$Path)

    $Item = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        Length = [int64]$Item.Length
        LastWriteUtcTicks = [int64]$Item.LastWriteTimeUtc.Ticks
        CreationUtcTicks = [int64]$Item.CreationTimeUtc.Ticks
    }
}

function Assert-DestinationState {
    param(
        [pscustomobject]$Expected,
        [string]$Path,
        [string]$Context
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Context The baseline DuckDB is missing or is no longer a regular file: $Path"
    }
    $Actual = Get-DestinationState -Path $Path
    if (
        $Actual.Length -ne $Expected.Length -or
        $Actual.LastWriteUtcTicks -ne $Expected.LastWriteUtcTicks -or
        $Actual.CreationUtcTicks -ne $Expected.CreationUtcTicks
    ) {
        throw "$Context The baseline DuckDB changed during the delta export; nothing was replaced."
    }
}

function Get-BaselineRunID {
    param([string]$Path)

    $Document = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $RunProperty = $Document.PSObject.Properties["base_run_id"]
    if ($null -eq $RunProperty -or [string]::IsNullOrWhiteSpace([string]$RunProperty.Value)) {
        throw "The baseline catalog does not identify a completed export run. Run a full export before using -Delta."
    }
    return [string]$RunProperty.Value
}

$DestinationLock = $null
try {
    $DestinationLock = [IO.FileStream]::new(
        $DestinationLockPath,
        [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None,
        4096,
        [IO.FileOptions]::DeleteOnClose
    )
    $LockText = "pid=$PID run=$RunID started=$([DateTime]::UtcNow.ToString('O'))`n"
    $LockBytes = [Text.Encoding]::UTF8.GetBytes($LockText)
    $DestinationLock.SetLength(0)
    $DestinationLock.Write($LockBytes, 0, $LockBytes.Length)
    $DestinationLock.Flush()
} catch {
    if ($null -ne $DestinationLock) {
        $DestinationLock.Dispose()
        $DestinationLock = $null
    }
    throw "Could not acquire the export lock for '$DuckDBPath'. Another export may be running: $($_.Exception.Message)"
}

$PreviousCgo = $env:CGO_ENABLED
$Succeeded = $false
$Published = $false
$BaseState = $null
$BaseRunID = $null
$BaselineCatalogHash = $null

try {
    $DestinationExists = Test-Path -LiteralPath $DuckDBPath
    $DestinationWalExists = Test-Path -LiteralPath $DuckDBWalPath
    if ($DestinationExists -and -not (Test-Path -LiteralPath $DuckDBPath -PathType Leaf)) {
        throw "The DuckDB destination is not a regular file: $DuckDBPath"
    }
    if ($DestinationWalExists -and -not (Test-Path -LiteralPath $DuckDBWalPath -PathType Leaf)) {
        throw "The DuckDB WAL path is not a regular file: $DuckDBWalPath"
    }
    if ($Delta) {
        if (-not $DestinationExists) {
            throw "Delta export requires an existing DuckDB destination: $DuckDBPath"
        }
        if ($DestinationWalExists) {
            throw "Delta export refuses a baseline with an active WAL: $DuckDBWalPath"
        }
    } elseif (($DestinationExists -or $DestinationWalExists) -and -not $Force) {
        throw "Destination already exists: $DuckDBPath. Pass -Force to replace it, or -Delta to update it."
    }

    New-Item -ItemType Directory -Path $StageDir | Out-Null
    $env:CGO_ENABLED = "0"

    if ($Delta) {
        $BaseState = Get-DestinationState -Path $DuckDBPath
        Write-Host "Reading the existing export catalog..." -ForegroundColor Cyan
        & $UvCommand.Source "run" "--script" $PythonScript "--base" $DuckDBPath "--write-baseline" $BaselinePath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not read the baseline DuckDB catalog (exit code $LASTEXITCODE)."
        }
        if (-not (Test-Path -LiteralPath $BaselinePath -PathType Leaf)) {
            throw "The baseline catalog writer did not create: $BaselinePath"
        }
        Assert-DestinationState -Expected $BaseState -Path $DuckDBPath -Context "While reading the baseline catalog."
        $BaseRunID = Get-BaselineRunID -Path $BaselinePath
        $BaselineCatalogHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BaselinePath).Hash
    }

    if ($Delta) {
        Write-Host "Preparing changed WeChat database snapshots..." -ForegroundColor Cyan
    } else {
        Write-Host "Preparing a decrypted WeChat snapshot..." -ForegroundColor Cyan
    }
    $PrepareArgs = @(
        "run",
        $GoScript,
        "--stage", $StageDir,
        "--manifest", $ManifestPath,
        "--prompt-exit-wechat"
    )
    if ($Delta) {
        $PrepareArgs += @("--baseline", $BaselinePath)
    }
    if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
        $PrepareArgs += @("--config", ([IO.Path]::GetFullPath($ConfigPath)))
    }
    if (-not [string]::IsNullOrWhiteSpace($BackupKeyFile)) {
        if (-not (Test-Path -LiteralPath $BackupKeyFile -PathType Leaf)) {
            throw "The requested backup key file does not exist: $BackupKeyFile"
        }
        $BackupKeyFile = [IO.Path]::GetFullPath($BackupKeyFile)
        $PrepareArgs += @("--backup-key-file", $BackupKeyFile)
    }
    if ($AllowPartial) {
        $PrepareArgs += "--allow-partial"
    }

    Push-Location $ProjectRoot
    try {
        & $GoExe @PrepareArgs
        if ($LASTEXITCODE -ne 0) {
            throw "WeChat database preparation failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }

    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "The preparation step did not create its manifest: $ManifestPath"
    }

    if ($Delta) {
        Write-Host "Applying changed database partitions to a private DuckDB copy..." -ForegroundColor Cyan
    } else {
        Write-Host "Importing every SQLite table into DuckDB..." -ForegroundColor Cyan
    }
    $ImportArgs = @("run", "--script", $PythonScript, "--manifest", $ManifestPath, "--output", $PartialDuckDBPath)
    if ($Delta) {
        $ImportArgs += @("--base", $DuckDBPath)
    }
    if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
        $ImportArgs += @("--config", ([IO.Path]::GetFullPath($ConfigPath)))
    }
    if (-not [string]::IsNullOrWhiteSpace($BackupKeyFile)) {
        $ImportArgs += @("--backup-key-file", $BackupKeyFile)
    }
    & $UvCommand.Source @ImportArgs
    if ($LASTEXITCODE -ne 0) {
        throw "DuckDB import failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath $PartialDuckDBPath)) {
        throw "The DuckDB importer did not create: $PartialDuckDBPath"
    }
    if (Test-Path -LiteralPath $PartialDuckDBWalPath) {
        throw "The DuckDB importer left an uncheckpointed WAL: $PartialDuckDBWalPath"
    }

    # Recheck immediately before promotion; an export can take a long time.
    $DestinationExists = Test-Path -LiteralPath $DuckDBPath
    $DestinationWalExists = Test-Path -LiteralPath $DuckDBWalPath
    if ($DestinationExists -and -not (Test-Path -LiteralPath $DuckDBPath -PathType Leaf)) {
        throw "The DuckDB destination became a directory during export: $DuckDBPath"
    }
    if ($DestinationWalExists -and -not (Test-Path -LiteralPath $DuckDBWalPath -PathType Leaf)) {
        throw "The DuckDB WAL path became a directory during export: $DuckDBWalPath"
    }
    if ($Delta) {
        if ($DestinationWalExists) {
            throw "The baseline acquired a WAL during the delta export: $DuckDBWalPath. Nothing was replaced."
        }
        Assert-DestinationState -Expected $BaseState -Path $DuckDBPath -Context "Before delta promotion."

        & $UvCommand.Source "run" "--script" $PythonScript "--base" $DuckDBPath "--write-baseline" $RevalidatedBaselinePath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not revalidate the baseline DuckDB catalog (exit code $LASTEXITCODE)."
        }
        Assert-DestinationState -Expected $BaseState -Path $DuckDBPath -Context "While revalidating the baseline catalog."
        $RevalidatedRunID = Get-BaselineRunID -Path $RevalidatedBaselinePath
        $RevalidatedCatalogHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $RevalidatedBaselinePath).Hash
        if ($RevalidatedRunID -cne $BaseRunID -or $RevalidatedCatalogHash -cne $BaselineCatalogHash) {
            throw "The baseline DuckDB catalog changed during the delta export; nothing was replaced."
        }
    } elseif (($DestinationExists -or $DestinationWalExists) -and -not $Force) {
        throw "Destination appeared during export: $DuckDBPath. Nothing was replaced."
    }

    if ($Delta) {
        try {
            # Both files are in the destination directory, so File.Replace uses
            # the filesystem's atomic replace primitive and retains a rollback copy.
            [IO.File]::Replace($PartialDuckDBPath, $DuckDBPath, $BackupDuckDBPath)
            $Published = $true
        } catch {
            if ((Test-Path -LiteralPath $BackupDuckDBPath) -and -not (Test-Path -LiteralPath $DuckDBPath)) {
                [IO.File]::Move($BackupDuckDBPath, $DuckDBPath)
            }
            throw
        }
    } else {
        try {
            if ($DestinationExists) {
                [IO.File]::Move($DuckDBPath, $BackupDuckDBPath)
            }
            if ($DestinationWalExists) {
                [IO.File]::Move($DuckDBWalPath, $BackupDuckDBWalPath)
            }
            [IO.File]::Move($PartialDuckDBPath, $DuckDBPath)
            $Published = $true
        } catch {
            if ((Test-Path -LiteralPath $BackupDuckDBPath) -and -not (Test-Path -LiteralPath $DuckDBPath)) {
                [IO.File]::Move($BackupDuckDBPath, $DuckDBPath)
            }
            if ((Test-Path -LiteralPath $BackupDuckDBWalPath) -and -not (Test-Path -LiteralPath $DuckDBWalPath)) {
                [IO.File]::Move($BackupDuckDBWalPath, $DuckDBWalPath)
            }
            throw
        }
    }

    $Succeeded = $true
} finally {
    $env:CGO_ENABLED = $PreviousCgo

    foreach ($TemporaryFile in @($PartialDuckDBPath, $PartialDuckDBWalPath)) {
        if (Test-Path -LiteralPath $TemporaryFile) {
            try {
                Remove-Item -LiteralPath $TemporaryFile -Force
            } catch {
                Write-Warning "Could not remove temporary file ${TemporaryFile}: $($_.Exception.Message)"
            }
        }
    }

    if ($Published) {
        foreach ($BackupFile in @($BackupDuckDBPath, $BackupDuckDBWalPath)) {
            if (Test-Path -LiteralPath $BackupFile) {
                try {
                    Remove-Item -LiteralPath $BackupFile -Force
                } catch {
                    Write-Warning "The previous export backup remains at ${BackupFile}: $($_.Exception.Message)"
                }
            }
        }
    }

    if (-not $KeepDecrypted) {
        try {
            Remove-ExportStage -Path $StageDir
        } catch {
            Write-Warning "Could not remove decrypted staging data at ${StageDir}: $($_.Exception.Message)"
        }
    }

    if ($null -ne $DestinationLock) {
        try {
            $DestinationLock.Dispose()
        } catch {
            Write-Warning "Could not release the export lock ${DestinationLockPath}: $($_.Exception.Message)"
        }
        $DestinationLock = $null
    }
}

if ($Succeeded) {
    Write-Host "Export complete: $DuckDBPath" -ForegroundColor Green
    if ($KeepDecrypted) {
        Write-Host "Decrypted snapshot retained at: $StageDir" -ForegroundColor Yellow
    }
}
