<#
.SYNOPSIS
Creates an all-or-nothing backup of every configured WeChat .db file as
ordinary, decrypted SQLite databases.

.DESCRIPTION
Reads database keys from the central chatlog.json, validates them before asking
you to exit WeChat, recursively stages every .db file from every configured
account, runs PRAGMA integrity_check, and publishes the completed directory only
after every database succeeds. If an encrypted phone-backup database needs a
key that has not been cached yet, keep WeChat signed in: the script invokes the
exporter's protected key-cache mode before asking you to exit WeChat.

The destination contains the SQLite files plus a key-free inventory named
.chatlog-sqlite-backup.json. It never contains chatlog.json, DataKey, ImgKey,
or a phone-backup key. "Remove all keys" means removing database encryption
and excluding external decryption secrets; rows or columns in WeChat's own
tables are preserved unchanged even if their names contain "key".

Committed plaintext and encrypted WAL state is consolidated into each standalone
SQLite copy without modifying the source. Without -Delta, the destination must
not already exist.

.PARAMETER OutputPath
Required destination directory. It must not overlap a configured WeChat data
directory. It must not exist for a full backup and must exist for -Delta.

.PARAMETER Delta
Incrementally refresh an existing backup. Unchanged databases are copied from
the validated prior backup, changed and new databases are staged from WeChat,
and removed databases are omitted. A complete replacement tree is published
with rollback protection only after every source and output passes validation.

.PARAMETER ConfigPath
Central chatlog.json. Defaults to %USERPROFILE%/.chatlog/chatlog.json, or to
%CHATLOG_DIR%/chatlog.json when CHATLOG_DIR is set.

.PARAMETER BackupKeyFile
Optional file containing the separate 32-byte hexadecimal BackupFiles key.
This explicitly supplied key takes precedence over the top-level backup_key in
chatlog.json. When neither is available for an encrypted BackupFiles/.../Backup.db,
the script attempts to capture and cache the key while WeChat is still running.
The key is never copied to output.

.PARAMETER AllowUnprotectedFileSystem
Allow decrypted SQLite files to be staged and published on a filesystem such
as exFAT/FAT32 that cannot enforce private Windows ACLs. Without this explicit
acknowledgement, the script fails before creating decrypted data. Prefer an
NTFS or ReFS destination whenever possible.

.EXAMPLE
./scripts/backup_wechat_databases.ps1 G:/wechat-sqlite-backup

.EXAMPLE
./scripts/backup_wechat_databases.ps1 D:/backups/wechat-sqlite -ConfigPath C:/Users/me/.chatlog/chatlog.json

.EXAMPLE
./scripts/backup_wechat_databases.ps1 G:/wechat-sqlite-backup -AllowUnprotectedFileSystem

.EXAMPLE
./scripts/backup_wechat_databases.ps1 G:/wechat-sqlite-backup -Delta
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [Alias("Target")]
    [string]$OutputPath,

    [string]$ConfigPath = $(
        if ([string]::IsNullOrWhiteSpace($env:CHATLOG_DIR)) {
            Join-Path $env:USERPROFILE ".chatlog\chatlog.json"
        } else {
            Join-Path $env:CHATLOG_DIR "chatlog.json"
        }
    ),

    [string]$BackupKeyFile,

    [switch]$Delta,

    [switch]$IncludeBackup,

    [switch]$AllowUnprotectedFileSystem
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Get-NormalizedFullPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $Full = [IO.Path]::GetFullPath($Path)
    $Root = [IO.Path]::GetPathRoot($Full)
    if ($Full.TrimEnd('\', '/').Equals($Root.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
        return $Root
    }
    return $Full.TrimEnd('\', '/')
}

function Get-SourceIdentity {
    param([Parameter(Mandatory = $true)][string]$DataDir)

    $Canonical = (Get-NormalizedFullPath -Path $DataDir).ToLowerInvariant()
    $Provider = [Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = $Provider.ComputeHash([Text.Encoding]::UTF8.GetBytes($Canonical))
    } finally {
        $Provider.Dispose()
    }
    return ([BitConverter]::ToString($Bytes)).Replace("-", "").ToLowerInvariant()
}

function Test-SHA256Digest {
    param([AllowEmptyString()][string]$Value)

    return -not [string]::IsNullOrWhiteSpace($Value) -and $Value.Trim() -cmatch '^[0-9a-fA-F]{64}$'
}

function Get-RequiredPropertyValue {
    param(
        [Parameter(Mandatory = $true)][psobject]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        throw "$Description is missing required property '$Name'."
    }
    return $Property.Value
}

function Get-OptionalPropertyValue {
    param(
        [Parameter(Mandatory = $true)][psobject]$Object,
        [Parameter(Mandatory = $true)][string]$Name,
        $DefaultValue = $null
    )

    $Property = $Object.PSObject.Properties[$Name]
    if ($null -eq $Property) {
        return $DefaultValue
    }
    return $Property.Value
}

function Get-SafeBackupRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $Normalized = $Value.Trim().Replace('\', '/')
    if (
        [string]::IsNullOrWhiteSpace($Normalized) -or
        $Normalized.StartsWith("/", [StringComparison]::Ordinal) -or
        [IO.Path]::IsPathRooted($Normalized) -or
        $Normalized.Contains(":")
    ) {
        throw "$Description is not a safe relative path: $Value"
    }
    foreach ($Component in $Normalized.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($Component) -or $Component -eq "." -or $Component -eq "..") {
            throw "$Description contains an unsafe path component: $Value"
        }
    }
    $Ext = [IO.Path]::GetExtension($Normalized)
    $Name = [IO.Path]::GetFileName($Normalized).ToUpperInvariant()
    if (-not $Ext.Equals(".db", [StringComparison]::OrdinalIgnoreCase) -and -not ($Name -match '^BAK_.*_(TEXT|MEDIA)$')) {
        throw "$Description is not a .db file or backup archive: $Value"
    }
    return $Normalized
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $ResolvedParent = Get-NormalizedFullPath -Path $Parent
    $ResolvedChild = Get-NormalizedFullPath -Path $Child
    if ($ResolvedChild.Equals($ResolvedParent, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $Prefix = $ResolvedParent.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    return $ResolvedChild.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NoReparsePathComponents {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $Current = Get-NormalizedFullPath -Path $LiteralPath
    while (-not [string]::IsNullOrWhiteSpace($Current)) {
        $Item = Get-Item -LiteralPath $Current -Force
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Description contains a symbolic link, junction, or other reparse point: $Current"
        }
        $Parent = Split-Path -Parent $Current
        if ([string]::IsNullOrWhiteSpace($Parent) -or $Parent.Equals($Current, [StringComparison]::OrdinalIgnoreCase)) {
            break
        }
        $Current = $Parent
    }
}

function Get-PrivateBackupSids {
    $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ($null -eq $CurrentSid) {
        throw "Could not determine the current Windows user SID."
    }
    $Sids = @{}
    foreach ($Sid in @(
        $CurrentSid,
        [Security.Principal.SecurityIdentifier]::new("S-1-5-18"),
        [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    )) {
        $Sids[$Sid.Value] = $Sid
    }
    return $Sids
}

function Assert-PrivateBackupAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$SkipAclProtection
    )

    if ($SkipAclProtection) {
        return
    }

    $Allowed = Get-PrivateBackupSids
    $Acl = Get-Acl -LiteralPath $LiteralPath
    if (-not $Acl.AreAccessRulesProtected) {
        throw "The decrypted-backup directory still inherits permissions: $LiteralPath"
    }
    $Seen = @{}
    $FullControl = [Security.AccessControl.FileSystemRights]::FullControl
    $RequiredInheritance = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    foreach ($Rule in @($Acl.Access)) {
        $SidValue = $Rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if (
            $Rule.IsInherited -or
            $Rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            -not $Allowed.ContainsKey($SidValue) -or
            (($Rule.FileSystemRights -band $FullControl) -ne $FullControl) -or
            (($Rule.InheritanceFlags -band $RequiredInheritance) -ne $RequiredInheritance)
        ) {
            throw "The decrypted-backup directory has an unexpected ACL rule: $LiteralPath"
        }
        $Seen[$SidValue] = $true
    }
    foreach ($SidValue in $Allowed.Keys) {
        if (-not $Seen.ContainsKey($SidValue)) {
            throw "The decrypted-backup directory ACL is missing a required principal: $LiteralPath"
        }
    }
}

function Set-PrivateBackupAcl {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [switch]$SkipAclProtection
    )

    if ($SkipAclProtection) {
        return
    }

    $Allowed = Get-PrivateBackupSids
    $Acl = [Security.AccessControl.DirectorySecurity]::new()
    $Acl.SetAccessRuleProtection($true, $false)
    $Inheritance = (
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    )
    foreach ($Sid in $Allowed.Values) {
        $Rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $Inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$Acl.AddAccessRule($Rule)
    }
    $AclExtensions = "System.IO.FileSystemAclExtensions" -as [type]
    if ($null -ne $AclExtensions) {
        [IO.FileSystemAclExtensions]::SetAccessControl(
            [IO.DirectoryInfo]::new($LiteralPath),
            $Acl
        )
    } else {
        (Get-Item -LiteralPath $LiteralPath).SetAccessControl($Acl)
    }
    Assert-PrivateBackupAcl -LiteralPath $LiteralPath
}

function Get-FileState {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $Item = Get-Item -LiteralPath $LiteralPath
    return [pscustomobject]@{
        Length = [int64]$Item.Length
        LastWriteUtcTicks = [int64]$Item.LastWriteTimeUtc.Ticks
        CreationUtcTicks = [int64]$Item.CreationTimeUtc.Ticks
        SHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $LiteralPath).Hash
    }
}

function Assert-FileState {
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Expected,
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Description
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "$Description disappeared while the backup was running."
    }
    $Actual = Get-FileState -LiteralPath $LiteralPath
    if (
        $Actual.Length -ne $Expected.Length -or
        $Actual.LastWriteUtcTicks -ne $Expected.LastWriteUtcTicks -or
        $Actual.CreationUtcTicks -ne $Expected.CreationUtcTicks -or
        $Actual.SHA256 -cne $Expected.SHA256
    ) {
        throw "$Description changed while the backup was running; no backup was published."
    }
}

function Test-ValidCachedBackupKey {
    param([Parameter(Mandatory = $true)][psobject]$Document)

    $Property = $Document.PSObject.Properties["backup_key"]
    if ($null -eq $Property -or $Property.Value -isnot [string]) {
        return $false
    }
    return ([string]$Property.Value).Trim() -cmatch '^[0-9A-Fa-f]{64}$'
}

function Test-OrdinarySQLiteHeader {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $Expected = [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0")
    $Actual = [byte[]]::new($Expected.Length)
    $Share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $Stream = [IO.FileStream]::new(
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
    for ($Index = 0; $Index -lt $Expected.Length; $Index++) {
        if ($Actual[$Index] -ne $Expected[$Index]) {
            return $false
        }
    }
    return $true
}

function Test-EncryptedPhoneBackupDatabasePresent {
    param([Parameter(Mandatory = $true)][object[]]$Accounts)

    foreach ($Account in $Accounts) {
        $DataDirProperty = $Account.PSObject.Properties["data_dir"]
        if ($null -eq $DataDirProperty -or [string]::IsNullOrWhiteSpace([string]$DataDirProperty.Value)) {
            continue
        }
        $DataDir = Get-NormalizedFullPath -Path ([string]$DataDirProperty.Value)
        $BackupRoot = Join-Path $DataDir "BackupFiles"
        if (-not (Test-Path -LiteralPath $BackupRoot)) {
            continue
        }
        if (-not (Test-Path -LiteralPath $BackupRoot -PathType Container)) {
            throw "The configured BackupFiles path is not a directory: $BackupRoot"
        }

        # Traverse explicitly so a junction or directory symlink cannot make
        # this preflight inspect a Backup.db outside the configured account.
        $Pending = [Collections.Generic.Stack[string]]::new()
        $Pending.Push($BackupRoot)
        while ($Pending.Count -gt 0) {
            $DirectoryPath = $Pending.Pop()
            $Directory = Get-Item -LiteralPath $DirectoryPath -Force
            if (($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "A configured BackupFiles directory contains a reparse point: $DirectoryPath"
            }
            try {
                $Entries = @($Directory.EnumerateFileSystemInfos())
            } catch {
                throw "Could not inspect a configured BackupFiles directory: $DirectoryPath. $($_.Exception.Message)"
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
                try {
                    if (-not (Test-OrdinarySQLiteHeader -LiteralPath $Entry.FullName)) {
                        return $true
                    }
                } catch {
                    throw "Could not inspect a configured phone-backup database: $($Entry.FullName). $($_.Exception.Message)"
                }
            }
        }
    }
    return $false
}

function Read-ValidatedBackupConfig {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ResolvedOutput
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "chatlog.json disappeared or is no longer a regular file: $LiteralPath"
    }
    $ConfigItem = Get-Item -LiteralPath $LiteralPath -Force
    if (($ConfigItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "chatlog.json must be a regular non-reparse file: $LiteralPath"
    }

    $Guard = [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        try {
            $Document = Get-Content -Raw -LiteralPath $LiteralPath | ConvertFrom-Json
        } catch {
            throw "Could not parse chatlog.json because it is not valid JSON."
        }
        if ($null -eq $Document) {
            throw "chatlog.json contains no configuration object."
        }
        $HistoryProperty = $Document.PSObject.Properties["history"]
        $HasHistory = $null -ne $HistoryProperty -and @($HistoryProperty.Value).Count -gt 0
        $HasFlatAccount = $null -ne $Document.PSObject.Properties["data_dir"]
        if (-not $HasHistory -and -not $HasFlatAccount) {
            throw "chatlog.json contains no configured account history."
        }
        $Accounts = if ($HasHistory) { @($HistoryProperty.Value) } else { @($Document) }
        foreach ($ConfiguredAccount in $Accounts) {
            $DataDirProperty = $ConfiguredAccount.PSObject.Properties["data_dir"]
            if ($null -eq $DataDirProperty -or [string]::IsNullOrWhiteSpace([string]$DataDirProperty.Value)) {
                throw "A chatlog.json account is missing its data_dir."
            }
            $ConfiguredDataDir = Get-NormalizedFullPath -Path ([string]$DataDirProperty.Value)
            if (-not (Test-Path -LiteralPath $ConfiguredDataDir -PathType Container)) {
                throw "A configured WeChat data directory is unavailable: $ConfiguredDataDir"
            }
            Assert-NoReparsePathComponents -LiteralPath $ConfiguredDataDir -Description "A configured WeChat data directory"
            if (
                (Test-PathWithin -Parent $ConfiguredDataDir -Child $ResolvedOutput) -or
                (Test-PathWithin -Parent $ResolvedOutput -Child $ConfiguredDataDir)
            ) {
                throw "The backup destination must not contain, equal, or be inside a configured WeChat data directory: $ConfiguredDataDir"
            }
        }
        return [pscustomobject]@{
            Document = $Document
            Accounts = @($Accounts)
            State = Get-FileState -LiteralPath $LiteralPath
        }
    } finally {
        try {
            $Guard.Dispose()
        } catch {
            Write-Warning "Could not release the chatlog.json validation guard: $($_.Exception.Message)"
        }
    }
}

function Test-WeChatClientRunning {
    $Processes = @(Get-Process -Name @("WeChat", "Weixin") -ErrorAction SilentlyContinue)
    return $Processes.Count -gt 0
}

function Assert-SQLiteHeader {
    param([Parameter(Mandatory = $true)][string]$LiteralPath)

    $Name = [IO.Path]::GetFileName($LiteralPath).ToUpperInvariant()
    if ($Name -match '^BAK_.*_(TEXT|MEDIA)$') {
        return
    }

    $Expected = [Text.Encoding]::ASCII.GetBytes("SQLite format 3`0")
    $Actual = [byte[]]::new($Expected.Length)
    $Stream = [IO.File]::Open(
        $LiteralPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    try {
        if ($Stream.Read($Actual, 0, $Actual.Length) -ne $Actual.Length) {
            throw "Published database is shorter than a SQLite header: $LiteralPath"
        }
    } finally {
        $Stream.Dispose()
    }
    for ($Index = 0; $Index -lt $Expected.Length; $Index++) {
        if ($Actual[$Index] -ne $Expected[$Index]) {
            throw "Published database is not ordinary SQLite: $LiteralPath"
        }
    }
}

function Read-ValidatedPortableBackup {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][Collections.Generic.List[IO.FileStream]]$Guards,
        [switch]$SkipAclProtection
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Container)) {
        throw "Delta backup requires an existing backup directory: $LiteralPath"
    }
    $Root = Get-NormalizedFullPath -Path $LiteralPath
    $RootItem = Get-Item -LiteralPath $Root -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The existing backup directory is a reparse point: $Root"
    }
    Assert-NoReparsePathComponents -LiteralPath $Root -Description "The existing backup path"
    Assert-PrivateBackupAcl -LiteralPath $Root -SkipAclProtection:$SkipAclProtection

    $ManifestPath = Join-Path $Root ".chatlog-sqlite-backup.json"
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        throw "The existing backup has no .chatlog-sqlite-backup.json manifest."
    }
    $ManifestItem = Get-Item -LiteralPath $ManifestPath -Force
    if (($ManifestItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The existing backup manifest is a reparse point."
    }
    $ManifestGuard = [IO.File]::Open(
        $ManifestPath,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    [void]$Guards.Add($ManifestGuard)
    $ManifestState = Get-FileState -LiteralPath $ManifestPath
    try {
        $ManifestJSON = [IO.File]::ReadAllText($ManifestPath)
        $Document = $ManifestJSON | ConvertFrom-Json
    } catch {
        throw "The existing backup manifest is not valid JSON."
    }
    if ($null -eq $Document) {
        throw "The existing backup manifest contains no object."
    }
    if ($ManifestJSON -match '(?i)"(data_key|img_key|backup_key|data_dir)"\s*:') {
        throw "The existing backup manifest contains a forbidden key or source-path field."
    }

    $FormatVersion = [int](Get-RequiredPropertyValue -Object $Document -Name "format_version" -Description "The existing backup manifest")
    if ($FormatVersion -ne 1 -and $FormatVersion -ne 2) {
        throw "The existing backup manifest format_version $FormatVersion is not supported for delta backup."
    }
    if ([string](Get-RequiredPropertyValue -Object $Document -Name "kind" -Description "The existing backup manifest") -cne "chatlog-decrypted-sqlite-backup") {
        throw "The existing destination is not a chatlog decrypted SQLite backup."
    }
    if ([string](Get-RequiredPropertyValue -Object $Document -Name "database_encryption" -Description "The existing backup manifest") -cne "none") {
        throw "The existing backup manifest does not describe plaintext SQLite databases."
    }
    if ([int](Get-RequiredPropertyValue -Object $Document -Name "sqlite_format" -Description "The existing backup manifest") -ne 3) {
        throw "The existing backup manifest does not describe SQLite format 3."
    }

    $ExpectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    [void]$ExpectedPaths.Add((Get-NormalizedFullPath -Path $ManifestPath))
    $AccountIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $SourceIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $Records = [Collections.Generic.List[object]]::new()
    $AccountRecords = [Collections.Generic.List[object]]::new()
    $Accounts = @((Get-RequiredPropertyValue -Object $Document -Name "accounts" -Description "The existing backup manifest"))
    foreach ($Account in $Accounts) {
        $AccountID = [string](Get-RequiredPropertyValue -Object $Account -Name "id" -Description "A backup account")
        if ($AccountID -notmatch '^[A-Za-z0-9_-]+$' -or -not $AccountIDs.Add($AccountID)) {
            throw "The existing backup contains an unsafe or duplicate account ID."
        }
        $Version = [int](Get-RequiredPropertyValue -Object $Account -Name "version" -Description "Backup account '$AccountID'")
        $SourceID = ""
        if ($FormatVersion -eq 2) {
            $SourceID = ([string](Get-RequiredPropertyValue -Object $Account -Name "source_id" -Description "Backup account '$AccountID'")).Trim().ToLowerInvariant()
            if (-not (Test-SHA256Digest -Value $SourceID) -or -not $SourceIDs.Add($SourceID)) {
                throw "Backup account '$AccountID' has an invalid or duplicate source_id."
            }
        }
        $AccountDirectory = Get-NormalizedFullPath -Path (Join-Path $Root $AccountID)
        if (-not (Test-PathWithin -Parent $Root -Child $AccountDirectory)) {
            throw "Backup account '$AccountID' escapes the backup directory."
        }
        $DatabaseRecords = [Collections.Generic.List[object]]::new()
        $Databases = @((Get-RequiredPropertyValue -Object $Account -Name "databases" -Description "Backup account '$AccountID'"))
        foreach ($Database in $Databases) {
            $Description = "A database in backup account '$AccountID'"
            $RelativePath = Get-SafeBackupRelativePath -Value ([string](Get-RequiredPropertyValue -Object $Database -Name "relative_path" -Description $Description)) -Description "$Description relative_path"
            $OutputPath = ([string](Get-RequiredPropertyValue -Object $Database -Name "output_path" -Description $Description)).Trim().Replace('\', '/')
            $ExpectedOutputPath = "$AccountID/$RelativePath"
            if (-not $OutputPath.Equals($ExpectedOutputPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw "$Description has an output_path that does not match its account and relative_path."
            }
            $ExpectedPath = Get-NormalizedFullPath -Path (Join-Path $Root $OutputPath.Replace('/', [IO.Path]::DirectorySeparatorChar))
            if (-not (Test-PathWithin -Parent $AccountDirectory -Child $ExpectedPath) -or -not $ExpectedPaths.Add($ExpectedPath)) {
                throw "$Description resolves outside its account or duplicates another output path."
            }
            if (-not (Test-Path -LiteralPath $ExpectedPath -PathType Leaf)) {
                throw "The existing backup is missing database '$OutputPath'."
            }
            $Item = Get-Item -LiteralPath $ExpectedPath -Force
            if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "The existing backup database is a reparse point: $OutputPath"
            }
            $Guard = [IO.File]::Open(
                $ExpectedPath,
                [IO.FileMode]::Open,
                [IO.FileAccess]::Read,
                [IO.FileShare]::Read
            )
            [void]$Guards.Add($Guard)
            $State = Get-FileState -LiteralPath $ExpectedPath
            $ByteSize = [int64](Get-RequiredPropertyValue -Object $Database -Name "byte_size" -Description $Description)
            $FileSHA256 = ([string](Get-RequiredPropertyValue -Object $Database -Name "sha256" -Description $Description)).Trim().ToLowerInvariant()
            if ($ByteSize -le 0 -or $State.Length -ne $ByteSize -or -not (Test-SHA256Digest -Value $FileSHA256) -or $State.SHA256.ToLowerInvariant() -cne $FileSHA256) {
                throw "The existing backup database no longer matches its size or SHA-256 manifest proof: $OutputPath"
            }
            if ([string](Get-RequiredPropertyValue -Object $Database -Name "integrity_check" -Description $Description) -cne "ok") {
                throw "The existing backup database lacks a successful integrity_check marker: $OutputPath"
            }
            Assert-SQLiteHeader -LiteralPath $ExpectedPath
            Assert-FileState -Expected $State -LiteralPath $ExpectedPath -Description "Existing backup database '$OutputPath'"

            $SourceSHA256 = ""
            $SnapshotSize = $ByteSize
            $SnapshotSHA256 = ""
            $AuxiliarySHA256 = ""
            $LegacyPhoneBootstrap = $false
            if ($FormatVersion -eq 2) {
                $SourceSHA256 = ([string](Get-RequiredPropertyValue -Object $Database -Name "source_sha256" -Description $Description)).Trim().ToLowerInvariant()
                $SnapshotSize = [int64](Get-RequiredPropertyValue -Object $Database -Name "snapshot_size" -Description $Description)
                $SnapshotSHA256 = ([string](Get-RequiredPropertyValue -Object $Database -Name "snapshot_sha256" -Description $Description)).Trim().ToLowerInvariant()
                $AuxiliarySHA256 = ([string](Get-OptionalPropertyValue -Object $Database -Name "auxiliary_sha256" -DefaultValue "")).Trim().ToLowerInvariant()
                $LegacyPhoneBootstrap = [bool](Get-OptionalPropertyValue -Object $Database -Name "legacy_phone_bootstrap" -DefaultValue $false)
                if (
                    -not (Test-SHA256Digest -Value $SourceSHA256) -or
                    $SnapshotSize -ne $ByteSize -or
                    -not (Test-SHA256Digest -Value $SnapshotSHA256) -or
                    (-not [string]::IsNullOrEmpty($AuxiliarySHA256) -and -not (Test-SHA256Digest -Value $AuxiliarySHA256))
                ) {
                    throw "The existing backup database has incomplete or invalid delta proof fields: $OutputPath"
                }
            }
            $Record = [pscustomobject]@{
                AccountID = $AccountID
                RelativePath = $RelativePath
                OutputPath = $OutputPath
                FullPath = $ExpectedPath
                State = $State
                SourceSHA256 = $SourceSHA256
                SnapshotSize = $SnapshotSize
                SnapshotSHA256 = $SnapshotSHA256
                FileSHA256 = $FileSHA256
                AuxiliarySHA256 = $AuxiliarySHA256
                LegacyPhoneBootstrap = $LegacyPhoneBootstrap
            }
            [void]$Records.Add($Record)
            [void]$DatabaseRecords.Add($Record)
        }
        [void]$AccountRecords.Add([pscustomobject]@{
            ID = $AccountID
            Version = $Version
            SourceID = $SourceID
            Databases = @($DatabaseRecords)
        })
    }
    $ExpectedAccountCount = [int](Get-RequiredPropertyValue -Object $Document -Name "account_count" -Description "The existing backup manifest")
    $ExpectedDatabaseCount = [int](Get-RequiredPropertyValue -Object $Document -Name "database_count" -Description "The existing backup manifest")
    if ($ExpectedAccountCount -ne $AccountRecords.Count -or $ExpectedDatabaseCount -ne $Records.Count) {
        throw "The existing backup manifest account or database count is inconsistent."
    }
    foreach ($Directory in @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force)) {
        if (($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The existing backup contains a reparse directory: $($Directory.FullName)"
        }
    }
    $ActualFiles = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force)
    if ($ActualFiles.Count -ne $ExpectedPaths.Count) {
        throw "The existing backup contains an unexpected or missing file."
    }
    foreach ($File in $ActualFiles) {
        if (($File.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $ExpectedPaths.Contains((Get-NormalizedFullPath -Path $File.FullName))) {
            throw "The existing backup contains an unexpected or reparse file: $($File.FullName)"
        }
    }
    Assert-FileState -Expected $ManifestState -LiteralPath $ManifestPath -Description "The existing backup manifest"
    return [pscustomobject]@{
        FormatVersion = $FormatVersion
        Document = $Document
        ManifestPath = $ManifestPath
        ManifestState = $ManifestState
        Accounts = @($AccountRecords)
        Records = @($Records)
        ExpectedPaths = $ExpectedPaths
    }
}

function Assert-PortableBackupUnchanged {
    param([Parameter(Mandatory = $true)][psobject]$Snapshot)

    Assert-FileState -Expected $Snapshot.ManifestState -LiteralPath $Snapshot.ManifestPath -Description "The existing backup manifest"
    foreach ($Record in @($Snapshot.Records)) {
        Assert-FileState -Expected $Record.State -LiteralPath $Record.FullPath -Description "Existing backup database '$($Record.OutputPath)'"
    }
    $Root = Split-Path -Parent $Snapshot.ManifestPath
    foreach ($Directory in @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force)) {
        if (($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The existing backup gained a reparse directory while the delta was being prepared: $($Directory.FullName)"
        }
    }
    $ActualFiles = @(Get-ChildItem -LiteralPath $Root -File -Recurse -Force)
    if ($ActualFiles.Count -ne $Snapshot.ExpectedPaths.Count) {
        throw "The existing backup inventory changed while the delta was being prepared."
    }
    foreach ($File in $ActualFiles) {
        if (($File.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or -not $Snapshot.ExpectedPaths.Contains((Get-NormalizedFullPath -Path $File.FullName))) {
            throw "The existing backup changed while the delta was being prepared: $($File.FullName)"
        }
    }
}

function Write-PrivateDeltaBaseline {
    param(
        [Parameter(Mandatory = $true)][psobject]$Snapshot,
        [Parameter(Mandatory = $true)][object[]]$ConfiguredAccounts,
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )

    if ([int]$Snapshot.FormatVersion -ne 2) {
        throw "Only a version 2 backup can be used as an unchanged-file delta baseline."
    }
    $CurrentBySourceID = @{}
    foreach ($ConfiguredAccount in $ConfiguredAccounts) {
        $DataDirProperty = $ConfiguredAccount.PSObject.Properties["data_dir"]
        if ($null -eq $DataDirProperty -or [string]::IsNullOrWhiteSpace([string]$DataDirProperty.Value)) {
            throw "A configured account is missing data_dir while constructing the private delta baseline."
        }
        # Keep the exact configured spelling (including a possible Windows 8.3
        # path) for Go's private baseline lookup. Normalize only for source_id.
        $ConfiguredDataDir = [string]$DataDirProperty.Value
        $SourceID = Get-SourceIdentity -DataDir $ConfiguredDataDir
        if ($CurrentBySourceID.ContainsKey($SourceID)) {
            throw "chatlog.json contains duplicate configured data directories."
        }
        $CurrentBySourceID[$SourceID] = $ConfiguredDataDir
    }

    $BaselineAccounts = @()
    foreach ($Account in @($Snapshot.Accounts)) {
        if (-not $CurrentBySourceID.ContainsKey([string]$Account.SourceID)) {
            continue
        }
        $BaselineFiles = @()
        foreach ($Database in @($Account.Databases)) {
            $BaselineFiles += [ordered]@{
                relative_path = [string]$Database.RelativePath
                output_path = [string]$Database.OutputPath
                source_sha256 = [string]$Database.SourceSHA256
                snapshot_size = [int64]$Database.SnapshotSize
                snapshot_sha256 = [string]$Database.SnapshotSHA256
                file_sha256 = [string]$Database.FileSHA256
                auxiliary_sha256 = [string]$Database.AuxiliarySHA256
                legacy_phone_bootstrap = [bool]$Database.LegacyPhoneBootstrap
            }
        }
        $BaselineAccounts += [ordered]@{
            id = [string]$Account.ID
            data_dir = [string]$CurrentBySourceID[[string]$Account.SourceID]
            version = [int]$Account.Version
            files = $BaselineFiles
        }
    }
    $Baseline = [ordered]@{
        format_version = 2
        accounts = $BaselineAccounts
    }
    $JSON = $Baseline | ConvertTo-Json -Depth 10
    $Utf8WithoutBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($LiteralPath, $JSON + [Environment]::NewLine, $Utf8WithoutBom)
}

function Remove-BackupWorkDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedParent
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return
    }
    $Resolved = Get-NormalizedFullPath -Path $LiteralPath
    $Parent = Get-NormalizedFullPath -Path $ExpectedParent
    $Leaf = [IO.Path]::GetFileName($Resolved)
    if (
        -not (Test-PathWithin -Parent $Parent -Child $Resolved) -or
        $Resolved.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        -not $Leaf.StartsWith(".chatlog-sqlite-backup-staging-", [StringComparison]::Ordinal)
    ) {
        throw "Refusing to remove an unexpected backup staging path: $Resolved"
    }
    $RootItem = Get-Item -LiteralPath $Resolved -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to recursively remove a backup staging path that became a reparse point: $Resolved"
    }
    foreach ($Item in @(Get-ChildItem -LiteralPath $Resolved -Recurse -Force)) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to recursively remove backup staging data containing a reparse point: $($Item.FullName)"
        }
    }
    [IO.Directory]::Delete($Resolved, $true)
}

function Remove-BackupRollbackDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$ExpectedParent,
        [Parameter(Mandatory = $true)][string]$ExpectedLeaf
    )

    if (-not (Test-Path -LiteralPath $LiteralPath)) {
        return
    }
    $Resolved = Get-NormalizedFullPath -Path $LiteralPath
    $Parent = Get-NormalizedFullPath -Path $ExpectedParent
    if (
        -not ([IO.Path]::GetDirectoryName($Resolved)).Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($Resolved)).Equals($ExpectedLeaf, [StringComparison]::Ordinal)
    ) {
        throw "Refusing to remove an unexpected backup rollback path: $Resolved"
    }
    $RootItem = Get-Item -LiteralPath $Resolved -Force
    if (($RootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing to remove a backup rollback path that became a reparse point: $Resolved"
    }
    foreach ($Item in @(Get-ChildItem -LiteralPath $Resolved -Recurse -Force)) {
        if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to remove backup rollback data containing a reparse point: $($Item.FullName)"
        }
    }
    [IO.Directory]::Delete($Resolved, $true)
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = Split-Path -Parent $ScriptDir
$GoScript = Join-Path $ScriptDir "export_wechat_history.go"
if (-not (Test-Path -LiteralPath $GoScript -PathType Leaf)) {
    throw "Required database preparation helper is missing: $GoScript"
}

$LocalGo = Join-Path $ProjectRoot "go\bin\go.exe"
if (Test-Path -LiteralPath $LocalGo -PathType Leaf) {
    $GoExe = $LocalGo
} else {
    $GoCommand = Get-Command go -ErrorAction SilentlyContinue
    if ($null -eq $GoCommand) {
        throw "Go was not found. Keep the bundled go/ directory or install Go 1.25+."
    }
    $GoExe = $GoCommand.Source
}

$ResolvedOutput = Get-NormalizedFullPath -Path $OutputPath
$OutputRoot = [IO.Path]::GetPathRoot($ResolvedOutput)
if ($ResolvedOutput.TrimEnd('\', '/').Equals($OutputRoot.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
    throw "A filesystem root cannot be used as the backup destination: $ResolvedOutput"
}
$OutputParent = Split-Path -Parent $ResolvedOutput
$OutputLeaf = Split-Path -Leaf $ResolvedOutput
if ([string]::IsNullOrWhiteSpace($OutputLeaf)) {
    throw "The backup destination must name a directory below a filesystem root."
}
$ExistingOutputAncestor = $OutputParent
while (-not (Test-Path -LiteralPath $ExistingOutputAncestor)) {
    $NextAncestor = Split-Path -Parent $ExistingOutputAncestor
    if (
        [string]::IsNullOrWhiteSpace($NextAncestor) -or
        $NextAncestor.Equals($ExistingOutputAncestor, [StringComparison]::OrdinalIgnoreCase)
    ) {
        throw "Could not find an existing ancestor for the backup destination: $ResolvedOutput"
    }
    $ExistingOutputAncestor = $NextAncestor
}
if (-not (Test-Path -LiteralPath $ExistingOutputAncestor -PathType Container)) {
    throw "A backup destination ancestor is not a directory: $ExistingOutputAncestor"
}
Assert-NoReparsePathComponents -LiteralPath $ExistingOutputAncestor -Description "The backup destination path"

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "chatlog.json does not exist: $ConfigPath. Run export_wechat_history.ps1 -SaveKeysOnly first if keys have not been cached."
}
$ResolvedConfig = Get-NormalizedFullPath -Path $ConfigPath
if (Test-PathWithin -Parent $ResolvedOutput -Child $ResolvedConfig) {
    throw "The backup destination must not contain chatlog.json."
}

# Parse the central cache before any process prompt or database staging. Do not
# echo or serialize this object because it contains the cached plaintext keys.
$ConfigSnapshot = Read-ValidatedBackupConfig -LiteralPath $ResolvedConfig -ResolvedOutput $ResolvedOutput
$ConfigDocument = $ConfigSnapshot.Document
$ConfiguredAccounts = @($ConfigSnapshot.Accounts)
$ConfigState = $ConfigSnapshot.State

$ResolvedBackupKey = $null
$BackupKeyState = $null
if (-not [string]::IsNullOrWhiteSpace($BackupKeyFile)) {
    if (-not (Test-Path -LiteralPath $BackupKeyFile -PathType Leaf)) {
        throw "The phone-backup key file does not exist: $BackupKeyFile"
    }
    $ResolvedBackupKey = Get-NormalizedFullPath -Path $BackupKeyFile
    $BackupKeyItem = Get-Item -LiteralPath $ResolvedBackupKey -Force
    if (($BackupKeyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "The phone-backup key must be a regular non-reparse file: $ResolvedBackupKey"
    }
    if (Test-PathWithin -Parent $ResolvedOutput -Child $ResolvedBackupKey) {
        throw "The backup destination must not contain the phone-backup key file."
    }
    $BackupKeyState = Get-FileState -LiteralPath $ResolvedBackupKey
}

if (
    $null -eq $ResolvedBackupKey -and
    (Test-EncryptedPhoneBackupDatabasePresent -Accounts $ConfiguredAccounts) -and
    -not (Test-ValidCachedBackupKey -Document $ConfigDocument)
) {
    if (-not (Test-WeChatClientRunning)) {
        throw (
            "An encrypted BackupFiles/.../Backup.db needs its separate phone-backup key, but chatlog.json " +
            "does not contain a valid backup_key and no WeChat client is running. Start WeChat, sign in, " +
            "and rerun this backup so the key can be decoded, or provide -BackupKeyFile."
        )
    }

    $KeyCacheScript = Join-Path $ScriptDir "export_wechat_history.ps1"
    if (-not (Test-Path -LiteralPath $KeyCacheScript -PathType Leaf)) {
        throw "Required key-cache helper is missing: $KeyCacheScript"
    }
    Write-Host "Caching the validated phone-backup key before asking you to exit WeChat..." -ForegroundColor Cyan
    try {
        & $KeyCacheScript -SaveKeysOnly -ConfigPath $ResolvedConfig
    } catch {
        throw (
            "The encrypted phone-backup key could not be cached while WeChat was running. " +
            "Keep the account signed in and rerun, or provide -BackupKeyFile. $($_.Exception.Message)"
        )
    }

    # SaveKeysOnly atomically replaces chatlog.json. Discard every object and
    # fingerprint from the old file, then parse and validate the published file
    # again before displaying the filesystem warning or creating any staging.
    $ConfigSnapshot = Read-ValidatedBackupConfig -LiteralPath $ResolvedConfig -ResolvedOutput $ResolvedOutput
    $ConfigDocument = $ConfigSnapshot.Document
    $ConfiguredAccounts = @($ConfigSnapshot.Accounts)
    $ConfigState = $ConfigSnapshot.State
    if (-not (Test-ValidCachedBackupKey -Document $ConfigDocument)) {
        throw (
            "The key-cache operation completed without saving a valid phone-backup key. " +
            "Keep WeChat signed in and rerun, or provide -BackupKeyFile."
        )
    }
}

$PathDigestProvider = [Security.Cryptography.SHA256]::Create()
try {
    $PathDigestBytes = $PathDigestProvider.ComputeHash([Text.Encoding]::UTF8.GetBytes($ResolvedOutput.ToLowerInvariant()))
} finally {
    $PathDigestProvider.Dispose()
}
$PathDigest = ([BitConverter]::ToString($PathDigestBytes)).Replace("-", "").Substring(0, 16).ToLowerInvariant()
$RollbackLeaf = ".chatlog-sqlite-backup-rollback-$PathDigest"
$RollbackDirectory = Join-Path $OutputParent $RollbackLeaf

if ($Delta) {
    $HasOutput = Test-Path -LiteralPath $ResolvedOutput -PathType Container
    $HasRollback = Test-Path -LiteralPath $RollbackDirectory -PathType Container
    if (-not $HasOutput -and -not $HasRollback) {
        throw "Delta backup requires an existing backup directory: $ResolvedOutput"
    }
    $HasOutputManifest = Test-Path -LiteralPath (Join-Path $ResolvedOutput ".chatlog-sqlite-backup.json") -PathType Leaf
    $HasRollbackManifest = Test-Path -LiteralPath (Join-Path $RollbackDirectory ".chatlog-sqlite-backup.json") -PathType Leaf
    if (-not $HasOutputManifest -and -not $HasRollbackManifest) {
        throw "The existing backup has no .chatlog-sqlite-backup.json manifest."
    }
} else {
    if ((Test-Path -LiteralPath $ResolvedOutput) -or (Test-Path -LiteralPath $RollbackDirectory)) {
        throw "Backup destination already exists: $ResolvedOutput. Use -Delta to update it or choose a new directory."
    }
}

$DestinationFileSystem = "unknown"
try {
    $DestinationDrive = [IO.DriveInfo]::new($OutputRoot)
    if ($DestinationDrive.IsReady) {
        $DestinationFileSystem = [string]$DestinationDrive.DriveFormat
    }
} catch {
    # Unknown/network filesystems are capability-tested by applying and then
    # verifying the ACL. Only positively identified ACL-less formats bypass it.
}
$AclLessFileSystems = @("exfat", "fat", "fat32")
$SkipAclProtection = $AclLessFileSystems -contains $DestinationFileSystem.ToLowerInvariant()
$FileSystemAccessControl = if ($SkipAclProtection) {
    "unavailable_acknowledged"
} else {
    "private_windows_acl"
}
if ($SkipAclProtection) {
    $AclWarning = (
        "The destination uses $DestinationFileSystem, which cannot enforce private Windows ACLs. " +
        "The decrypted WeChat SQLite files will be readable by anyone who can access this device. " +
        "Use an NTFS/ReFS destination for per-user protection."
    )
    if (-not $AllowUnprotectedFileSystem) {
        $CanPrompt = $false
        try {
            $CanPrompt = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
        } catch {
            $CanPrompt = $false
        }
        if (-not $CanPrompt) {
            throw "$AclWarning Rerun with -AllowUnprotectedFileSystem to acknowledge this in a non-interactive session."
        }
        try {
            $Choices = [Management.Automation.Host.ChoiceDescription[]]@(
                [Management.Automation.Host.ChoiceDescription]::new("&Yes", "Create unprotected plaintext SQLite files."),
                [Management.Automation.Host.ChoiceDescription]::new("&No", "Cancel without creating decrypted data.")
            )
            $Choice = $Host.UI.PromptForChoice(
                "Unprotected plaintext backup",
                "$AclWarning Continue anyway?",
                $Choices,
                1
            )
        } catch {
            throw "$AclWarning Rerun with -AllowUnprotectedFileSystem to acknowledge it explicitly."
        }
        if ($Choice -ne 0) {
            throw "Backup cancelled before any decrypted data was created."
        }
    }
    Write-Warning $AclWarning
}

# Only create a missing destination parent after central configuration, source
# overlap, input containment, and existing-ancestor checks have all succeeded.
[void][IO.Directory]::CreateDirectory($OutputParent)
Assert-NoReparsePathComponents -LiteralPath $OutputParent -Description "The backup destination path"

$LockPath = Join-Path $OutputParent ".chatlog-sqlite-backup-$PathDigest.lock"
$RunID = [Guid]::NewGuid().ToString("N")
$WorkDirectory = Join-Path $OutputParent ".chatlog-sqlite-backup-staging-$RunID"
$PayloadDirectory = Join-Path $WorkDirectory "payload"
$PreparationManifestPath = Join-Path $WorkDirectory "preparation.json"
$DeltaBaselinePath = Join-Path $WorkDirectory "delta-baseline.json"
$PortableManifestPath = Join-Path $PayloadDirectory ".chatlog-sqlite-backup.json"

$Lock = $null
$ConfigGuard = $null
$BackupKeyGuard = $null
$BaselineGuards = [Collections.Generic.List[IO.FileStream]]::new()
$BaselineSnapshot = $null
$UseDeltaBaseline = $false
$Published = $false
$PreserveWorkDirectory = $false
$DatabaseCount = 0
$ReusedCount = 0
$ChangedCount = 0
$AddedCount = 0
$RemovedCount = 0
$HadCgoSetting = Test-Path Env:CGO_ENABLED
$PreviousCgo = $env:CGO_ENABLED
try {
    try {
        $Lock = [IO.FileStream]::new(
            $LockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None,
            4096,
            [IO.FileOptions]::DeleteOnClose
        )
    } catch {
        throw "Could not acquire the backup lock for '$ResolvedOutput'. Another backup may be running: $($_.Exception.Message)"
    }

    if (Test-Path -LiteralPath $RollbackDirectory) {
        if (-not $Delta) {
            throw "A previous delta rollback directory needs recovery before a full backup can run: $RollbackDirectory"
        }
        if (Test-Path -LiteralPath $ResolvedOutput) {
            throw "A previous delta left both the backup and rollback directories. Refusing ambiguous recovery: $RollbackDirectory"
        }
        $RollbackItem = Get-Item -LiteralPath $RollbackDirectory -Force
        if (-not $RollbackItem.PSIsContainer -or ($RollbackItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The previous delta rollback path is not a safe directory: $RollbackDirectory"
        }
        [IO.Directory]::Move($RollbackDirectory, $ResolvedOutput)
        Write-Warning "Recovered the prior backup after an interrupted delta publication."
    }

    if ($Delta) {
        if (-not (Test-Path -LiteralPath $ResolvedOutput -PathType Container)) {
            throw "Delta backup requires an existing backup directory: $ResolvedOutput"
        }
        $BaselineSnapshot = Read-ValidatedPortableBackup `
            -LiteralPath $ResolvedOutput `
            -Guards $BaselineGuards `
            -SkipAclProtection:$SkipAclProtection
        if ([int]$BaselineSnapshot.FormatVersion -eq 1) {
            Write-Warning "The existing backup uses legacy manifest v1; this delta will perform a one-time full refresh to v2."
        } else {
            $UseDeltaBaseline = $true
        }
    } elseif (Test-Path -LiteralPath $ResolvedOutput) {
        throw "Backup destination already exists: $ResolvedOutput. Use -Delta to update it or choose a new directory."
    }

    # Keep the original secret inputs open with sharing restricted to readers.
    # This lets Go read them while preventing modification, deletion, rename,
    # or atomic replacement for the duration of the backup, without making a
    # second on-disk copy of any key.
    $ConfigGuard = [IO.File]::Open(
        $ResolvedConfig,
        [IO.FileMode]::Open,
        [IO.FileAccess]::Read,
        [IO.FileShare]::Read
    )
    Assert-FileState -Expected $ConfigState -LiteralPath $ResolvedConfig -Description "chatlog.json"
    if ($null -ne $ResolvedBackupKey) {
        $BackupKeyGuard = [IO.File]::Open(
            $ResolvedBackupKey,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read
        )
        Assert-FileState -Expected $BackupKeyState -LiteralPath $ResolvedBackupKey -Description "The phone-backup key file"
    }

    [void][IO.Directory]::CreateDirectory($WorkDirectory)
    Set-PrivateBackupAcl -LiteralPath $WorkDirectory -SkipAclProtection:$SkipAclProtection
    [void][IO.Directory]::CreateDirectory($PayloadDirectory)
    Set-PrivateBackupAcl -LiteralPath $PayloadDirectory -SkipAclProtection:$SkipAclProtection

    if ($UseDeltaBaseline) {
        Write-PrivateDeltaBaseline `
            -Snapshot $BaselineSnapshot `
            -ConfiguredAccounts $ConfiguredAccounts `
            -LiteralPath $DeltaBaselinePath
    }

    $env:CGO_ENABLED = "0"
    $PrepareArgs = @(
        "run",
        $GoScript,
        "--stage", $PayloadDirectory,
        "--manifest", $PreparationManifestPath,
        "--config", $ResolvedConfig,
        "--sqlite-backup",
        "--destination-root", $ResolvedOutput,
        "--prompt-exit-wechat"
    )
    if ($IncludeBackup) {
        $PrepareArgs += @("--include-backup")
    }
    if ($null -ne $ResolvedBackupKey) {
        $PrepareArgs += @("--backup-key-file", $ResolvedBackupKey)
    }
    if ($UseDeltaBaseline) {
        $PrepareArgs += @(
            "--baseline", $DeltaBaselinePath,
            "--sqlite-backup-baseline-root", $ResolvedOutput
        )
    }

    Write-Host "Preparing verified decrypted SQLite databases..." -ForegroundColor Cyan
    Push-Location $ProjectRoot
    try {
        & $GoExe @PrepareArgs
        if ($LASTEXITCODE -ne 0) {
            throw "WeChat SQLite backup preparation failed with exit code $LASTEXITCODE."
        }
    } finally {
        Pop-Location
    }

    Assert-FileState -Expected $ConfigState -LiteralPath $ResolvedConfig -Description "chatlog.json"
    if ($null -ne $BackupKeyState) {
        Assert-FileState -Expected $BackupKeyState -LiteralPath $ResolvedBackupKey -Description "The phone-backup key file"
    }
    if (-not (Test-Path -LiteralPath $PreparationManifestPath -PathType Leaf)) {
        throw "The preparation helper did not create its key-free working manifest."
    }
    $Preparation = Get-Content -Raw -LiteralPath $PreparationManifestPath | ConvertFrom-Json
    if ([string]$Preparation.status -cne "complete" -or [bool]$Preparation.allow_partial) {
        throw "The preparation manifest is not complete; no backup was published."
    }
    if (@($Preparation.unresolved).Count -ne 0) {
        throw "The preparation manifest contains unresolved databases; no backup was published."
    }

    $ExpectedPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $AccountIDs = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $BaselineDatabaseKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $BaselineSnapshot) {
        foreach ($PriorDatabase in @($BaselineSnapshot.Records)) {
            [void]$BaselineDatabaseKeys.Add("$($PriorDatabase.AccountID)/$($PriorDatabase.RelativePath)")
        }
    }
    $CurrentDatabaseKeys = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $PortableAccounts = @()
    foreach ($Account in @($Preparation.accounts)) {
        $AccountID = [string]$Account.id
        if ($AccountID -notmatch '^[A-Za-z0-9_-]+$' -or -not $AccountIDs.Add($AccountID)) {
            throw "The preparation manifest contains an unsafe or duplicate account output ID."
        }
        if ([string]$Account.status -cne "complete" -or -not [bool]$Account.resolved) {
            throw "Account '$AccountID' was not staged completely."
        }
        $AccountDirectory = Get-NormalizedFullPath -Path (Join-Path $PayloadDirectory $AccountID)
        $AccountDataDir = [string](Get-RequiredPropertyValue -Object $Account -Name "data_dir" -Description "Preparation account '$AccountID'")
        $SourceID = Get-SourceIdentity -DataDir $AccountDataDir
        $PortableFiles = @()
        foreach ($Database in @($Account.files)) {
            $DatabaseStatus = [string]$Database.status
            if ($DatabaseStatus -cne "ok" -and $DatabaseStatus -cne "unchanged") {
                throw "Database '$AccountID/$($Database.relative_path)' was not staged successfully."
            }
            $RelativePath = Get-SafeBackupRelativePath -Value ([string]$Database.relative_path) -Description "The preparation manifest database path"
            $ExpectedPath = Get-NormalizedFullPath -Path (Join-Path $AccountDirectory $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar))
            if (-not (Test-PathWithin -Parent $AccountDirectory -Child $ExpectedPath)) {
                throw "The preparation manifest database path escapes its account directory: $RelativePath"
            }
            $StagedPath = Get-NormalizedFullPath -Path ([string]$Database.staged_path)
            if (-not $StagedPath.Equals($ExpectedPath, [StringComparison]::OrdinalIgnoreCase)) {
                throw "The preparation manifest points outside the expected database path: $RelativePath"
            }
            if (-not (Test-Path -LiteralPath $ExpectedPath -PathType Leaf)) {
                throw "A staged database is missing: $ExpectedPath"
            }
            $Item = Get-Item -LiteralPath $ExpectedPath -Force
            if (
                ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                (-not [IO.Path]::GetExtension($Item.Name).Equals(".db", [StringComparison]::OrdinalIgnoreCase) -and -not ($Item.Name.ToUpperInvariant() -match '^BAK_.*_(TEXT|MEDIA)$'))
            ) {
                throw "A staged database is not a regular .db file or backup archive: $ExpectedPath"
            }
            if (-not $ExpectedPaths.Add($ExpectedPath)) {
                throw "The preparation manifest contains a duplicate staged database path: $ExpectedPath"
            }
            $DatabaseKey = "$AccountID/$RelativePath"
            [void]$CurrentDatabaseKeys.Add($DatabaseKey)
            Assert-SQLiteHeader -LiteralPath $ExpectedPath
            if ([int64]$Database.snapshot_size -ne [int64]$Item.Length) {
                throw "A staged database size no longer matches the verified preparation result: $ExpectedPath"
            }
            $OrdinarySHA256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $ExpectedPath).Hash.ToLowerInvariant()
            $VerifiedSHA256 = ([string]$Database.file_sha256).Trim().ToLowerInvariant()
            if ($VerifiedSHA256 -notmatch '^[0-9a-f]{64}$' -or $OrdinarySHA256 -cne $VerifiedSHA256) {
                throw "A staged database changed after SQLite integrity verification: $ExpectedPath"
            }
            $SourceSHA256 = ([string](Get-RequiredPropertyValue -Object $Database -Name "source_sha256" -Description "Preparation database '$DatabaseKey'")).Trim().ToLowerInvariant()
            $SnapshotSHA256 = ([string](Get-RequiredPropertyValue -Object $Database -Name "snapshot_sha256" -Description "Preparation database '$DatabaseKey'")).Trim().ToLowerInvariant()
            $AuxiliarySHA256 = ([string](Get-OptionalPropertyValue -Object $Database -Name "auxiliary_sha256" -DefaultValue "")).Trim().ToLowerInvariant()
            $LegacyPhoneBootstrap = [bool](Get-OptionalPropertyValue -Object $Database -Name "legacy_phone_bootstrap" -DefaultValue $false)
            if (
                -not (Test-SHA256Digest -Value $SourceSHA256) -or
                -not (Test-SHA256Digest -Value $SnapshotSHA256) -or
                (-not [string]::IsNullOrEmpty($AuxiliarySHA256) -and -not (Test-SHA256Digest -Value $AuxiliarySHA256))
            ) {
                throw "The preparation manifest has incomplete delta proof fields for '$DatabaseKey'."
            }
            $DeltaStatus = "full"
            if ($Delta) {
                if ($DatabaseStatus -ceq "unchanged") {
                    $DeltaStatus = "reused"
                    $ReusedCount++
                } elseif ($BaselineDatabaseKeys.Contains($DatabaseKey)) {
                    $DeltaStatus = "changed"
                    $ChangedCount++
                } else {
                    $DeltaStatus = "added"
                    $AddedCount++
                }
            }
            $PortableFiles += [ordered]@{
                relative_path = $RelativePath
                output_path = "$AccountID/$RelativePath"
                source_sha256 = $SourceSHA256
                snapshot_size = [int64]$Database.snapshot_size
                snapshot_sha256 = $SnapshotSHA256
                auxiliary_sha256 = $AuxiliarySHA256
                legacy_phone_bootstrap = $LegacyPhoneBootstrap
                byte_size = [int64]$Item.Length
                sha256 = $OrdinarySHA256
                integrity_check = "ok"
                delta_status = $DeltaStatus
            }
            $DatabaseCount++
        }
        $PortableAccounts += [ordered]@{
            id = $AccountID
            account = [string]$Account.account
            platform = [string]$Account.platform
            version = [int]$Account.version
            source_id = $SourceID
            full_version = if ($null -ne $Account.PSObject.Properties["full_version"]) {
                [string]$Account.PSObject.Properties["full_version"].Value
            } else {
                ""
            }
            databases = $PortableFiles
        }
    }
    if ($Delta) {
        foreach ($PriorKey in $BaselineDatabaseKeys) {
            if (-not $CurrentDatabaseKeys.Contains($PriorKey)) {
                $RemovedCount++
            }
        }
    }
    if ($DatabaseCount -eq 0) {
        throw "No SQLite databases were prepared."
    }

    foreach ($Directory in @(Get-ChildItem -LiteralPath $PayloadDirectory -Directory -Recurse -Force)) {
        if (($Directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "The staged backup contains an unexpected reparse directory: $($Directory.FullName)"
        }
    }
    $ActualFiles = @(Get-ChildItem -LiteralPath $PayloadDirectory -File -Recurse -Force)
    if ($ActualFiles.Count -ne $ExpectedPaths.Count) {
        throw "The staged backup contains a file that is not in the verified database inventory."
    }
    foreach ($File in $ActualFiles) {
        if (-not $ExpectedPaths.Contains((Get-NormalizedFullPath -Path $File.FullName))) {
            throw "The staged backup contains an unexpected file: $($File.FullName)"
        }
    }

    $PortableManifest = [ordered]@{
        format_version = 2
        kind = "chatlog-decrypted-sqlite-backup"
        created_at = [DateTime]::UtcNow.ToString("O")
        mode = if ($Delta) { "delta" } else { "full" }
        sqlite_format = 3
        database_encryption = "none"
        destination_file_system = $DestinationFileSystem
        filesystem_access_control = $FileSystemAccessControl
        account_count = $PortableAccounts.Count
        database_count = $DatabaseCount
        reused_count = $ReusedCount
        changed_count = $ChangedCount
        added_count = $AddedCount
        removed_count = $RemovedCount
        accounts = $PortableAccounts
    }
    $ManifestJSON = $PortableManifest | ConvertTo-Json -Depth 10
    $Utf8WithoutBom = [Text.UTF8Encoding]::new($false)
    [IO.File]::WriteAllText($PortableManifestPath, $ManifestJSON + [Environment]::NewLine, $Utf8WithoutBom)
    Set-PrivateBackupAcl -LiteralPath $PayloadDirectory -SkipAclProtection:$SkipAclProtection

    $NewManifestState = Get-FileState -LiteralPath $PortableManifestPath
    if ($Delta) {
        Assert-PortableBackupUnchanged -Snapshot $BaselineSnapshot
        foreach ($BaselineGuard in $BaselineGuards) {
            $BaselineGuard.Dispose()
        }
        $BaselineGuards.Clear()
        if (-not (Test-Path -LiteralPath $ResolvedOutput -PathType Container)) {
            throw "The existing backup disappeared before delta publication; no replacement was published."
        }
        if (Test-Path -LiteralPath $RollbackDirectory) {
            throw "The delta rollback path appeared before publication: $RollbackDirectory"
        }

        $OldMoved = $false
        $NewMoved = $false
        try {
            [IO.Directory]::Move($ResolvedOutput, $RollbackDirectory)
            $OldMoved = $true
            [IO.Directory]::Move($PayloadDirectory, $ResolvedOutput)
            $NewMoved = $true
            Assert-PrivateBackupAcl -LiteralPath $ResolvedOutput -SkipAclProtection:$SkipAclProtection
            Assert-FileState `
                -Expected $NewManifestState `
                -LiteralPath (Join-Path $ResolvedOutput ".chatlog-sqlite-backup.json") `
                -Description "The published delta manifest"
        } catch {
            $PromotionError = $_.Exception.Message
            $RollbackError = $null
            try {
                if ($NewMoved -and (Test-Path -LiteralPath $ResolvedOutput)) {
                    if (Test-Path -LiteralPath $PayloadDirectory) {
                        throw "the private payload path unexpectedly exists"
                    }
                    [IO.Directory]::Move($ResolvedOutput, $PayloadDirectory)
                }
                if ($OldMoved -and (Test-Path -LiteralPath $RollbackDirectory)) {
                    if (Test-Path -LiteralPath $ResolvedOutput) {
                        throw "the destination is occupied while restoring the prior backup"
                    }
                    [IO.Directory]::Move($RollbackDirectory, $ResolvedOutput)
                }
            } catch {
                $RollbackError = $_.Exception.Message
            }
            if ($null -ne $RollbackError) {
                $PreserveWorkDirectory = $true
                throw "Delta publication failed ($PromotionError), and the prior backup could not be restored ($RollbackError). Preserve and inspect: $ResolvedOutput ; $RollbackDirectory ; $PayloadDirectory"
            }
            throw "Delta publication failed and the prior backup was restored: $PromotionError"
        }
        Remove-BackupRollbackDirectory `
            -LiteralPath $RollbackDirectory `
            -ExpectedParent $OutputParent `
            -ExpectedLeaf $RollbackLeaf
        $Published = $true
    } else {
        if (Test-Path -LiteralPath $ResolvedOutput) {
            throw "The backup destination appeared while staging; no files were replaced: $ResolvedOutput"
        }
        [IO.Directory]::Move($PayloadDirectory, $ResolvedOutput)
        try {
            # A same-volume directory move should retain the protected DACL. Verify
            # that before considering the backup published.
            Assert-PrivateBackupAcl -LiteralPath $ResolvedOutput -SkipAclProtection:$SkipAclProtection
            Assert-FileState `
                -Expected $NewManifestState `
                -LiteralPath (Join-Path $ResolvedOutput ".chatlog-sqlite-backup.json") `
                -Description "The published backup manifest"
        } catch {
            $AclError = $_.Exception.Message
            try {
                [IO.Directory]::Move($ResolvedOutput, $PayloadDirectory)
            } catch {
                throw "The backup was moved into place but its private ACL could not be verified ($AclError), and rollback also failed: $($_.Exception.Message). Inspect: $ResolvedOutput"
            }
            throw "The published backup ACL could not be verified and publication was rolled back: $AclError"
        }
        $Published = $true
    }
} finally {
    if ($HadCgoSetting) {
        $env:CGO_ENABLED = $PreviousCgo
    } else {
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }
    if ($null -ne $BackupKeyGuard) {
        try {
            $BackupKeyGuard.Dispose()
        } catch {
            Write-Warning "Could not release the phone-backup key read guard: $($_.Exception.Message)"
        }
        $BackupKeyGuard = $null
    }
    if ($null -ne $ConfigGuard) {
        try {
            $ConfigGuard.Dispose()
        } catch {
            Write-Warning "Could not release the chatlog.json read guard: $($_.Exception.Message)"
        }
        $ConfigGuard = $null
    }
    foreach ($BaselineGuard in $BaselineGuards) {
        try {
            $BaselineGuard.Dispose()
        } catch {
            Write-Warning "Could not release an existing-backup read guard: $($_.Exception.Message)"
        }
    }
    $BaselineGuards.Clear()
    if ($null -ne $Lock) {
        try {
            $Lock.Dispose()
        } catch {
            Write-Warning "Could not release the backup lock ${LockPath}: $($_.Exception.Message)"
        }
        $Lock = $null
    }
    if ($PreserveWorkDirectory) {
        Write-Warning "Private delta staging was preserved for recovery inspection: $WorkDirectory"
    } else {
        try {
            Remove-BackupWorkDirectory -LiteralPath $WorkDirectory -ExpectedParent $OutputParent
        } catch {
            Write-Warning "Could not remove private backup staging data at ${WorkDirectory}: $($_.Exception.Message)"
        }
    }
}

if ($Published) {
    if ($Delta) {
        Write-Host (
            "SQLite delta backup complete: $ResolvedOutput ($DatabaseCount database files; " +
            "$ReusedCount reused, $ChangedCount changed, $AddedCount added, $RemovedCount removed)"
        ) -ForegroundColor Green
    } else {
        Write-Host "SQLite backup complete: $ResolvedOutput ($DatabaseCount database files)" -ForegroundColor Green
    }
}

$ScriptStopwatch.Stop()
Write-Host "Total elapsed time: $($ScriptStopwatch.Elapsed.ToString('hh\:mm\:ss\.fff'))" -ForegroundColor Cyan
