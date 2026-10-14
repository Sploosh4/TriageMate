param(
    [Parameter(Mandatory=$true)][Guid]$ExpectedMachineGuid,
    [Parameter(Mandatory=$true)][Guid]$ExpectedTenantId,
    [Parameter(Mandatory=$true)][Guid]$ExpectedDeviceId
)
# Read-only inventory. Do not use Win32_Product: querying it can trigger repairs.
# No registry writes, hive loading, package changes, or execution of registry values.
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$started = [DateTime]::UtcNow.ToString('o')
$machine = [Guid](Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid')
$registration = (& "$env:SystemRoot\System32\dsregcmd.exe" /status | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'Device registration inspection failed' }
function RegistrationGuid([string]$field) {
    $matchesFound = [regex]::Matches($registration, "(?m)^\s*${field}\s*:\s*([0-9a-fA-F-]{36})\s*$")
    if ($matchesFound.Count -ne 1) { throw 'Device registration identity is ambiguous' }
    return [Guid]$matchesFound[0].Groups[1].Value
}
$tenant = RegistrationGuid 'TenantId'
$device = RegistrationGuid 'DeviceId'
if ($machine -ne $ExpectedMachineGuid -or $tenant -ne $ExpectedTenantId -or $device -ne $ExpectedDeviceId) {
    throw 'Inventory target differs from the configured device'
}
$roots = [System.Collections.Generic.List[string]]::new()
$roots.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
$roots.Add('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
# Include loaded Entra account hives as well as local/domain account hives.
# Exact SID matching excludes _Classes, service hives and unrelated registry keys.
$loadedSids = @(Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-(?:5-21|12-1)-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | ForEach-Object { $_.PSChildName })
foreach ($sid in $loadedSids) {
    $roots.Add("Registry::HKEY_USERS\$sid\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
    $roots.Add("Registry::HKEY_USERS\$sid\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
}
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$header = [ordered]@{
    contract='triagemate-windows-inventory-v1'; source='Windows inventory';
    started_at=$started;
    machine_guid=$machine.ToString(); tenant_id=$tenant.ToString(); device_id=$device.ToString();
    coverage=[ordered]@{
        registry_roots=@($roots.ToArray()); loaded_user_sids=@($loadedSids);
        appx_scope='all-users'; unloaded_user_hives='not-read';
        appx_package_types=@('Main','Framework','Resource','Bundle','Xap','Optional');
        portable_applications='not-enumerated'; completeness='within-declared-contract'
    }
} | ConvertTo-Json -Depth 8 -Compress
[Console]::Write($header.Substring(0, $header.Length - 1) + ',"records":[')
$script:recordCount = 0
function WriteInventoryJson([string]$json) {
    if ($script:recordCount -gt 0) { [Console]::Write(',') }
    [Console]::Write($json)
    $script:recordCount += 1
}
function WriteInventoryRecord($record) {WriteInventoryJson ($record | ConvertTo-Json -Depth 8 -Compress)}
foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }
    Get-ChildItem -LiteralPath $root | ForEach-Object {
        $key = $_
        $p = Get-ItemProperty -LiteralPath $key.PSPath
        # Keep unnamed entries as observations rather than silently omitting them.
        WriteInventoryRecord ([ordered]@{
            kind='registry'; native_id=$key.Name; name=$p.DisplayName;
            version=$p.DisplayVersion; publisher=$p.Publisher;
            reported_value_names=@($key.GetValueNames());
            localized_name=$p.DisplayName_Localized;
            install_date=$p.InstallDate; system_component=$p.SystemComponent;
            release_type=$p.ReleaseType; parent_key_name=$p.ParentKeyName
        })
    }
}
# Read package identity data only. Never execute registry or manifest references.
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class TriageMatePackageText {
 [DllImport("shlwapi.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 public static extern int SHLoadIndirectString(string source,StringBuilder output,uint count,IntPtr reserved);
}
'@
function PackageResourceUri([string]$reference,[string]$packageName) {
    # Resolve only resource-map names within the fixed installed package PRI.
    # No file references, query strings, fragments or path traversal are accepted.
    if ($reference -notmatch '^ms-resource:(?://([A-Za-z0-9._-]*)/|(/))?([A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*)$') {return $null}
    $authority=$Matches[1];$path=$Matches[3]
    if (@($path.Split('/') | Where-Object {$_ -eq '.' -or $_ -eq '..'}).Count) {return $null}
    if (-not $authority) {$authority=$packageName}
    if (-not $reference.Substring(12).StartsWith('/') -and -not $path.Contains('/')) {$path='resources/'+$path}
    return 'ms-resource://'+$authority+'/'+$path
}
function ReadManifestText($reader) {
    # Bound an individual contract field without limiting manifest/file size.
    # ReadElementContentAsString would allocate the entire source text first.
    if ($reader.IsEmptyElement) {[void]$reader.Read(); return ''}
    $depth=$reader.Depth;$text=[Text.StringBuilder]::new();$buffer=[char[]]::new(1024)
    [void]$reader.Read()
    while (-not $reader.EOF) {
        if ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement -and $reader.Depth -eq $depth) {
            [void]$reader.Read();return $text.ToString()
        }
        if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {throw 'Nested manifest property'}
        if ($reader.NodeType -in @([Xml.XmlNodeType]::Text,[Xml.XmlNodeType]::CDATA,[Xml.XmlNodeType]::Whitespace,[Xml.XmlNodeType]::SignificantWhitespace)) {
            while (($count=$reader.ReadValueChunk($buffer,0,$buffer.Length)) -gt 0) {
                if ($text.Length+$count -gt 4096) {throw 'Manifest property exceeds field contract'}
                [void]$text.Append($buffer,0,$count)
            }
        }
        [void]$reader.Read()
    }
    throw 'Incomplete manifest property'
}
function ReadPackageManifest($package) {
    $result=[ordered]@{
        state='unavailable'; reason='manifest_read_failed'; sha256=$null;
        name=$null; version=$null; publisher=$null; display_name_reference=$null;
        display_name=$null; publisher_display_name=$null; display_name_basis='unresolved';
        signature_kind=$package.SignatureKind.ToString();
        resource_lookup_hresult=$null; resolution_culture=[Globalization.CultureInfo]::CurrentUICulture.Name
    }
    if ($package.IsBundle -or $package.IsResourcePackage) {
        $result.state='not_applicable'; $result.reason='bundle_or_resource_package'; return $result
    }
    $stream=$null; $reader=$null; $hash=$null
    try {
        $path=Join-Path -Path $package.InstallLocation -ChildPath 'AppxManifest.xml'
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $hash=[Security.Cryptography.SHA256]::Create()
        $digest=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
        $stream.Position=0
        $settings=[Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit; $settings.XmlResolver=$null
        $reader=[Xml.XmlReader]::Create($stream,$settings)
        $identity=$null; $properties=@{}; $inProperties=$false; $namespace=$null
        while (-not $reader.EOF) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::Element) {
                if ($reader.Depth -eq 0) {
                    if ($reader.LocalName -ne 'Package') {throw 'Invalid manifest root'}
                    $namespace=$reader.NamespaceURI
                }
                if ($reader.Depth -eq 1 -and $reader.NamespaceURI -eq $namespace) {
                    $inProperties=($reader.LocalName -eq 'Properties')
                    if ($reader.LocalName -eq 'Identity') {
                        if ($null -ne $identity) {throw 'Duplicate manifest identity'}
                        $identity=@{name=$reader.GetAttribute('Name');version=$reader.GetAttribute('Version');publisher=$reader.GetAttribute('Publisher')}
                    }
                }
                if ($inProperties -and $reader.Depth -eq 2 -and $reader.NamespaceURI -eq $namespace -and $reader.LocalName -in @('DisplayName','PublisherDisplayName')) {
                    $key=$reader.LocalName
                    if ($properties.ContainsKey($key)) {throw 'Duplicate manifest property'}
                    $properties[$key]=ReadManifestText $reader
                    continue
                }
            }
            if ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement -and $reader.Depth -eq 1) {$inProperties=$false}
            [void]$reader.Read()
        }
        if ($null -eq $identity -or $identity.name -cne $package.Name -or $identity.version -cne $package.Version.ToString() -or $identity.publisher -cne $package.Publisher) {
            $result.reason='manifest_identity_conflict'; return $result
        }
        $result.state='read';$result.reason='exact_manifest_package_identity';$result.sha256=$digest
        $result.name=$identity.name;$result.version=$identity.version;$result.publisher=$identity.publisher
        $result.display_name_reference=$properties['DisplayName'];$result.publisher_display_name=$properties['PublisherDisplayName']
        $display=$result.display_name_reference
        if ($display -and -not $display.StartsWith('ms-resource:',[StringComparison]::OrdinalIgnoreCase) -and -not $display.StartsWith('@')) {
            $result.display_name=$display;$result.display_name_basis='literal_manifest_value'
        } elseif ($resource=PackageResourceUri $display $package.Name) {
            $pri=Join-Path -Path $package.InstallLocation -ChildPath 'resources.pri'
            $reference='@{'+$pri+'?'+$resource+'}'
            $buffer=[Text.StringBuilder]::new(4096)
            $status=[TriageMatePackageText]::SHLoadIndirectString($reference,$buffer,4096,[IntPtr]::Zero)
            $result.resource_lookup_hresult=$status
            if ($status -eq 0 -and $buffer.Length -gt 0 -and $buffer.Length -lt 4095) {
                $result.display_name=$buffer.ToString();$result.display_name_basis='package_resource_text'
            }
        }
        return $result
    } catch {
        # A name lookup failure must not hide the original package observation.
        # Safe states expose missing optional metadata without leaking raw errors.
        return $result
    } finally {
        if ($null -ne $reader) {$reader.Dispose()}
        if ($null -ne $stream) {$stream.Dispose()}
        if ($null -ne $hash) {$hash.Dispose()}
    }
}

function BundleAttribute($reader,[string]$name,[bool]$required=$true) {
    if (-not $reader.MoveToAttribute($name)) {if ($required) {throw 'Missing bundle attribute'}; return $null}
    try {
        $value=[Text.StringBuilder]::new();$buffer=[char[]]::new(1024)
        while (($length=$reader.ReadValueChunk($buffer,0,$buffer.Length)) -gt 0) {
            if ($value.Length+$length -gt 4096) {throw 'Bundle attribute exceeds field contract'}
            [void]$value.Append($buffer,0,$length)
        }
        return $value.ToString()
    } finally {[void]$reader.MoveToElement()}
}
function ReadBundleManifest($package) {
    $result=[ordered]@{state='unavailable';reason='bundle_manifest_read_failed';sha256=$null;member_count=0}
    $stream=$null;$reader=$null;$hash=$null;$spool=$null;$writer=$null;$lines=$null
    try {
        $path=Join-Path $package.InstallLocation 'AppxMetadata\AppxBundleManifest.xml'
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $hash=[Security.Cryptography.SHA256]::Create()
        $digest=([BitConverter]::ToString($hash.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
        $stream.Position=0
        $temporary=Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
        $spool=[IO.FileStream]::new($temporary,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None,4096,[IO.FileOptions]::DeleteOnClose)
        $writer=[IO.StreamWriter]::new($spool,[Text.UTF8Encoding]::new($false),4096,$true)
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
        $reader=[Xml.XmlReader]::Create($stream,$settings)
        $identity=$false;$packages=$false;$insidePackages=$false;$count=0
        while ($reader.Read()) {
            if ($reader.NodeType -eq [Xml.XmlNodeType]::EndElement -and $reader.Depth -eq 1) {$insidePackages=$false}
            if ($reader.NodeType -ne [Xml.XmlNodeType]::Element) {continue}
            if ($reader.Depth -eq 0 -and ($reader.LocalName -ne 'Bundle' -or $reader.NamespaceURI -ne 'http://schemas.microsoft.com/appx/2013/bundle')) {throw 'Invalid bundle root'}
            if ($reader.NamespaceURI -ne 'http://schemas.microsoft.com/appx/2013/bundle') {continue}
            if ($reader.Depth -eq 1 -and $reader.LocalName -eq 'Identity') {
                if ($identity) {throw 'Duplicate bundle identity'}
                if ((BundleAttribute $reader 'Name') -cne $package.Name -or (BundleAttribute $reader 'Publisher') -cne $package.Publisher -or (BundleAttribute $reader 'Version') -cne $package.Version.ToString()) {
                    $result.reason='bundle_manifest_identity_conflict';return $result
                }
                $identity=$true
            }
            if ($reader.Depth -eq 1 -and $reader.LocalName -eq 'Packages') {
                if ($packages) {throw 'Duplicate bundle package list'}
                $packages=$true;$insidePackages=$true
            }
            if ($reader.Depth -ne 2 -or -not $insidePackages -or $reader.LocalName -ne 'Package') {continue}
            if (-not $identity) {throw 'Bundle members precede identity'}
            $type=BundleAttribute $reader 'Type' $false;if ($null -eq $type) {$type='resource'}
            $architecture=BundleAttribute $reader 'Architecture' $false;if ($null -eq $architecture) {$architecture='neutral'}
            $resource=BundleAttribute $reader 'ResourceId' $false;if ($null -eq $resource) {$resource=''}
            $stub=BundleAttribute $reader 'IsStub' $false
            if ($null -eq $stub) {$stubValue=$false} elseif ($stub -ceq 'true' -or $stub -ceq '1') {$stubValue=$true} elseif ($stub -ceq 'false' -or $stub -ceq '0') {$stubValue=$false} else {throw 'Invalid bundle stub flag'}
            $version=BundleAttribute $reader 'Version'
            if ($type -cnotin @('application','resource') -or $architecture -cnotin @('x86','x64','arm','arm64','neutral','x86a64') -or $resource -cnotmatch '^[A-Za-z0-9.-]{0,30}$' -or $version -cnotmatch '^[0-9]{1,5}(\.[0-9]{1,5}){3}$') {throw 'Invalid bundle member'}
            foreach ($part in $version.Split('.')) {if ([int]$part -gt 65535) {throw 'Invalid bundle member version'}}
            $count++
            $identityJson=ConvertTo-Json -InputObject @($package.PackageFullName,$digest,$count) -Compress
            $memberId=([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($identityJson)))).Replace('-','').ToLowerInvariant()
            $member=[ordered]@{kind='appx_bundle_member';native_id=$memberId;name=$package.Name;version=$version;publisher=$package.Publisher;family_name=$package.PackageFamilyName;bundle_native_id=$package.PackageFullName;bundle_version=$package.Version.ToString();manifest_sha256=$digest;member_index=$count;member_type=$type;architecture=$architecture;resource_id=$resource;is_stub=$stubValue}
            $writer.WriteLine(($member | ConvertTo-Json -Depth 4 -Compress))
        }
        if (-not $identity -or -not $packages) {throw 'Incomplete bundle manifest'}
        $writer.Flush();$spool.Position=0
        $lines=[IO.StreamReader]::new($spool,[Text.Encoding]::UTF8,$true,4096,$true)
        while ($null -ne ($line=$lines.ReadLine())) {WriteInventoryJson $line}
        $result.state='read';$result.reason='exact_bundle_manifest_identity';$result.sha256=$digest;$result.member_count=$count
        return $result
    } catch {return $result}
    finally {
        if ($lines) {$lines.Dispose()};if ($writer) {$writer.Dispose()};if ($spool) {$spool.Dispose()}
        if ($reader) {$reader.Dispose()};if ($stream) {$stream.Dispose()};if ($hash) {$hash.Dispose()}
    }
}

Get-AppxPackage -AllUsers -PackageTypeFilter Main,Framework,Resource,Bundle,Xap,Optional | ForEach-Object {
    $package = $_
    if ($package.IsBundle -isnot [bool]) { throw 'Appx bundle flag is unavailable' }
    $bundleSummary=$null
    if ($package.IsBundle) {$bundleSummary=ReadBundleManifest $package}
    $record=[ordered]@{
        kind='appx'; native_id=$package.PackageFullName; name=$package.Name;
        version=$package.Version.ToString(); publisher=$package.Publisher;
        family_name=$package.PackageFamilyName; architecture=$package.Architecture.ToString();
        is_bundle=$package.IsBundle; manifest=(ReadPackageManifest $package); resource_id=[string]$package.ResourceId;
        is_framework=[bool]$package.IsFramework; is_resource_package=[bool]$package.IsResourcePackage;
        non_removable=[bool]$package.NonRemovable; status=$package.Status.ToString();
        user_states=@($package.PackageUserInformation | ForEach-Object {
            [ordered]@{sid=[string]$_.UserSecurityId.Sid; install_state=$_.InstallState.ToString()}
        })
    }
    if ($package.IsBundle) {$record.bundle_manifest=$bundleSummary}
    WriteInventoryRecord $record
}
$tail = [ordered]@{
    finished_at=[DateTime]::UtcNow.ToString('o'); record_count=$script:recordCount; complete=$true
} | ConvertTo-Json -Compress
[Console]::WriteLine('],' + $tail.Substring(1))
