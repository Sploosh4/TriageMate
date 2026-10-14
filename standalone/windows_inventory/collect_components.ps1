param(
 [Parameter(Mandatory=$true)][Guid]$ExpectedMachineGuid,
 [Parameter(Mandatory=$true)][Guid]$ExpectedTenantId,
 [Parameter(Mandatory=$true)][Guid]$ExpectedDeviceId,
 [Parameter(Mandatory=$true)][string]$ComponentNamesBase64
)
# Read-only selected Appx/servicing evidence; never install or repair packages.
$ErrorActionPreference='Stop';$WarningPreference='Stop';$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$started=[DateTime]::UtcNow.ToString('o')
$parsedNames=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($ComponentNamesBase64)) | ConvertFrom-Json
$names=@($parsedNames)
if(!$names.Count -or @($names|Sort-Object -Unique).Count -ne $names.Count){throw 'Unique component names required'}
foreach($name in $names){if($name -isnot [string] -or $name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$'){throw 'Invalid exact component name'}}
$machine=[Guid](Get-ItemPropertyValue 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid')
$registration=(& "$env:SystemRoot\System32\dsregcmd.exe" /status | Out-String)
if($LASTEXITCODE -ne 0){throw 'Registration query failed'}
function RegistrationGuid([string]$field){
 $found=[regex]::Matches($registration,"(?m)^\s*${field}\s*:\s*([0-9a-fA-F-]{36})\s*$")
 if($found.Count -ne 1){throw 'Ambiguous registration'};return [Guid]$found[0].Groups[1].Value
}
$tenant=RegistrationGuid 'TenantId';$device=RegistrationGuid 'DeviceId'
if($machine -eq [Guid]::Empty -or $machine -ne $ExpectedMachineGuid -or $tenant -ne $ExpectedTenantId -or $device -ne $ExpectedDeviceId){throw 'Unexpected component collection target'}
$os=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$osInfo=Get-CimInstance -ClassName Win32_OperatingSystem
function Digest([byte[]]$bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TriageMateServicingDelta {
 [StructLayout(LayoutKind.Sequential)] public struct Input {public IntPtr Start; public UIntPtr Size; public int Editable;}
 [StructLayout(LayoutKind.Sequential)] public struct Output {public IntPtr Start; public UIntPtr Size;}
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("msdelta.dll",SetLastError=true)] static extern bool ApplyDeltaB(long flags,Input source,Input delta,out Output target);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("msdelta.dll")] static extern bool DeltaFree(IntPtr p);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr LoadLibraryEx(string file,IntPtr reserved,uint flags);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr FindResource(IntPtr module,IntPtr name,IntPtr type);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint SizeofResource(IntPtr module,IntPtr resource);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr LoadResource(IntPtr module,IntPtr resource);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern IntPtr LockResource(IntPtr resource);
 [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
 [DllImport("kernel32.dll")] static extern bool FreeLibrary(IntPtr module);
 public static byte[] Dictionary(string path) {
  IntPtr module=LoadLibraryEx(path,IntPtr.Zero,0x22);if(module==IntPtr.Zero)throw new Exception("Resource load failed");
  try {IntPtr res=FindResource(module,(IntPtr)1,(IntPtr)614);if(res==IntPtr.Zero)throw new Exception("Dictionary absent");
   uint size=SizeofResource(module,res);if(size==0||size>Int32.MaxValue)throw new Exception("Dictionary bound");
   IntPtr ptr=LockResource(LoadResource(module,res));if(ptr==IntPtr.Zero)throw new Exception("Dictionary read failed");
   byte[] result=new byte[size];Marshal.Copy(ptr,result,0,(int)size);return result;
  }finally{FreeLibrary(module);}
 }
 public static byte[] Decode(byte[] bytes,byte[] dictionary) {
  if(bytes.Length<8 || bytes[0]!=68 || bytes[1]!=67 || bytes[2]!=77 || bytes[3]!=1) throw new Exception("Unexpected manifest header");
  byte[] delta=new byte[bytes.Length-4];Array.Copy(bytes,4,delta,0,delta.Length);
  GCHandle sourcePin=GCHandle.Alloc(dictionary,GCHandleType.Pinned);GCHandle pin=GCHandle.Alloc(delta,GCHandleType.Pinned);Output output=new Output();
  try { Input input=new Input{Start=pin.AddrOfPinnedObject(),Size=(UIntPtr)delta.Length,Editable=0};
   if(!ApplyDeltaB(0,new Input{Start=sourcePin.AddrOfPinnedObject(),Size=(UIntPtr)dictionary.Length,Editable=0},input,out output)) throw new Exception("Delta error "+Marshal.GetLastWin32Error());
   long size=(long)output.Size.ToUInt64();if(size>Int32.MaxValue) throw new Exception("Output bound exceeded");
   byte[] result=new byte[size];Marshal.Copy(output.Start,result,0,(int)size);return result;
  } finally {if(output.Start!=IntPtr.Zero)DeltaFree(output.Start);pin.Free();sourcePin.Free();}
 }
}
'@

$wcp=Get-ChildItem ($env:windir+'\WinSxS\amd64_microsoft-windows-servicingstack_*\wcp.dll') | Sort-Object { [version]$_.VersionInfo.FileVersion.Split(' ')[0] } -Descending | Select-Object -First 1
$dictionary=$null;$dictionaryProof=$null
if($wcp){$dictionary=[TriageMateServicingDelta]::Dictionary($wcp.FullName);$dictionaryProof=[ordered]@{path=$wcp.FullName;dll_sha256=(Get-FileHash -LiteralPath $wcp.FullName -Algorithm SHA256).Hash.ToLowerInvariant();dictionary_sha256=(Digest $dictionary)}}
$apps=@(Get-AppxPackage -AllUsers -PackageTypeFilter Main,Framework,Resource,Bundle,Xap,Optional)
$rows=@(foreach($name in $names){
 $matches=@($apps|Where-Object {$_.Name -ceq $name})
 if(!$matches.Count){[ordered]@{name=$name;state='not_observed';observed_at=[DateTime]::UtcNow.ToString('o')};continue}
 foreach($app in $matches){
  $row=[ordered]@{name=$name;state='observed';observed_at=[DateTime]::UtcNow.ToString('o');native_id=[string]$app.PackageFullName;version=$app.Version.ToString();family_name=[string]$app.PackageFamilyName;publisher=[string]$app.Publisher;architecture=$app.Architecture.ToString();status=$app.Status.ToString();is_framework=[bool]$app.IsFramework;is_resource_package=[bool]$app.IsResourcePackage;is_bundle=[bool]$app.IsBundle;user_states=@($app.PackageUserInformation|ForEach-Object {[ordered]@{sid=$_.UserSecurityId.ToString();install_state=$_.InstallState.ToString()}});manifest=$null;assemblies=@();error_code=$null}
  try{
   if(!$app.InstallLocation){throw 'Manifest location absent'}
   $manifest=Join-Path $app.InstallLocation 'AppxManifest.xml';$bytes=[IO.File]::ReadAllBytes($manifest)
   $links=@(& "$env:SystemRoot\System32\fsutil.exe" hardlink list $manifest 2>&1|ForEach-Object {"$_"})
   if($LASTEXITCODE -ne 0){throw 'Hardlink query failed'}
   $row.manifest=[ordered]@{path=$manifest;sha256=(Digest $bytes);base64=[Convert]::ToBase64String($bytes);hardlinks=$links}
   $assemblies=@(foreach($link in $links){
    if($link -notmatch '(?i)^\\Windows\\WinSxS\\([A-Za-z0-9_.-]+)\\'){continue}
    $directory=$Matches[1];if($directory -eq '.' -or $directory -eq '..'){throw 'Invalid component directory'}
    $path=Join-Path $env:windir ('WinSxS\Manifests\'+$directory+'.manifest')
    $compressed=[IO.File]::ReadAllBytes($path)
    if($compressed.Length -ge 4 -and $compressed[0] -eq 68 -and $compressed[1] -eq 67 -and $compressed[2] -eq 77 -and $compressed[3] -eq 1){if(!$dictionary){throw 'No decode dictionary'};$decoded=[TriageMateServicingDelta]::Decode($compressed,$dictionary)}else{$decoded=$compressed}
    [ordered]@{path=$path;active_hardlink=$link;source_sha256=(Digest $compressed);source_base64=[Convert]::ToBase64String($compressed);decoded_sha256=(Digest $decoded);decoded_base64=[Convert]::ToBase64String($decoded);observed_at=[DateTime]::UtcNow.ToString('o')}
   })
   $row.assemblies=$assemblies
   if((Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant() -ne $row.manifest.sha256){throw 'Active manifest changed during read'}
  }catch{$row.error_code='component_evidence_unavailable';$row.assemblies=@()}
  $row
 }
})
$after=@(Get-AppxPackage -AllUsers -PackageTypeFilter Main,Framework,Resource,Bundle,Xap,Optional)
foreach($row in $rows){if($row.state -eq 'observed'){$current=@($after|Where-Object {$_.Name -ceq $row.name -and $_.PackageFullName -ceq $row.native_id});if($current.Count -ne 1 -or $current[0].Version.ToString() -cne $row.version){$row.error_code='package_changed_during_collection';$row.assemblies=@()}}}
[ordered]@{contract='triagemate-windows-component-observations-v1';started_at=$started;finished_at=[DateTime]::UtcNow.ToString('o');machine_guid=$machine.ToString();tenant_id=$tenant.ToString();device_id=$device.ToString();requested_names=$names;os=[ordered]@{caption=[string]$osInfo.Caption;release=[string]$os.DisplayVersion;build=[string]$os.CurrentBuildNumber;ubr=[int]$os.UBR;architecture=[string]$env:PROCESSOR_ARCHITECTURE};dictionary=$dictionaryProof;rows=$rows;complete=$true;scope='selected Appx registrations and active manifest servicing links; not all device software or vulnerability coverage'}|ConvertTo-Json -Depth 12 -Compress
