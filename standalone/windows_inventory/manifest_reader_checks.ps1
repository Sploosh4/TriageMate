# Synthetic checks. Load PackageResourceUri, ReadManifestText and ReadPackageManifest first.
# Creates and removes only its own temporary fixture directory; reads no inventory.
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$directory=Join-Path ([IO.Path]::GetTempPath()) ('triagemate-manifest-test-'+[Guid]::NewGuid().ToString())
[void][IO.Directory]::CreateDirectory($directory)
$results=@()
try {
 $uriCases=@(
  @('ms-resource:Name','ms-resource://Synthetic.App/resources/Name'),
  @('ms-resource:Resources/Name','ms-resource://Synthetic.App/Resources/Name'),
  @('ms-resource:Library/Resources/Name','ms-resource://Synthetic.App/Library/Resources/Name'),
  @('ms-resource:/Manifest/Name','ms-resource://Synthetic.App/Manifest/Name'),
  @('ms-resource:///Resources/Name','ms-resource://Synthetic.App/Resources/Name'),
  @('ms-resource://Other/Resources/Name','ms-resource://Other/Resources/Name'),
  @('MS-RESOURCE:Name','ms-resource://Synthetic.App/resources/Name'),
  @('ms-resource:../Name',$null),@('ms-resource:Resources/./Name',$null),
  @('ms-resource:Name?x=1',$null),@('ms-resource:Name#x',$null),
  @('ms-resource:Resources/%2e%2e/Name',$null),@('@file.exe,-1',$null),
  @('ms-resource://user@Other/Name',$null)
 )
 foreach ($case in $uriCases) {
  $actual=PackageResourceUri $case[0] 'Synthetic.App'
  if ($actual -cne $case[1]) {throw ('Resource URI failed: '+$case[0])}
 }
 $base='<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="Synthetic.App" Version="1.2.3.4" Publisher="Synthetic Publisher"/><Properties><DisplayName>DISPLAY</DisplayName><PublisherDisplayName>Synthetic publisher</PublisherDisplayName></Properties></Package>'
 $package=[pscustomobject]@{Name='Synthetic.App';Version=[Version]'1.2.3.4';Publisher='Synthetic Publisher';IsBundle=$false;IsResourcePackage=$false;SignatureKind='Synthetic';InstallLocation=$directory}
 $cases=@(
  @{label='bounded-property';xml=$base.Replace('DISPLAY',('x'*4096));state='read';basis='literal_manifest_value';name=('x'*4096)},
  @{label='oversized-property';xml=$base.Replace('DISPLAY',('x'*4097));state='unavailable';basis='unresolved';name=$null},
  @{label='split-text';xml=$base.Replace('DISPLAY','Synthetic <![CDATA[app]]> name');state='read';basis='literal_manifest_value';name='Synthetic app name'},
  @{label='nested-property';xml=$base.Replace('DISPLAY','<Nested>not a name</Nested>');state='unavailable';basis='unresolved';name=$null},
  @{label='literal';xml=$base.Replace('DISPLAY','Synthetic &amp; App');state='read';basis='literal_manifest_value';name='Synthetic & App'},
  @{label='unresolved-reference';xml=$base.Replace('DISPLAY','ms-resource:Missing');state='read';basis='unresolved';name=$null},
  @{label='file-reference-not-loaded';xml=$base.Replace('DISPLAY','@arbitrary.exe,-1');state='read';basis='unresolved';name=$null},
  @{label='unsupported-uri-not-loaded';xml=$base.Replace('DISPLAY','ms-resource://Other/Name');state='read';basis='unresolved';name=$null},
  @{label='doctype-prohibited';xml='<!DOCTYPE Package [<!ENTITY x SYSTEM "http://127.0.0.1:9/not-fetched">]>'+$base.Replace('DISPLAY','&x;');state='unavailable';basis='unresolved';name=$null},
  @{label='conflicting-publisher';xml=$base.Replace('Synthetic Publisher','Other Publisher');state='unavailable';basis='unresolved';name=$null},
  @{label='duplicate-identity';xml=$base.Replace('<Properties>','<Identity Name="Synthetic.App" Version="1.2.3.4" Publisher="Synthetic Publisher"/><Properties>');state='unavailable';basis='unresolved';name=$null},
  @{label='duplicate-display-name';xml=$base.Replace('</DisplayName>','</DisplayName><DisplayName>duplicate</DisplayName>');state='unavailable';basis='unresolved';name=$null},
  @{label='malformed-xml';xml='<Package';state='unavailable';basis='unresolved';name=$null}
 )
 foreach ($case in $cases) {
  [IO.File]::WriteAllText((Join-Path $directory 'AppxManifest.xml'),$case.xml,[Text.UTF8Encoding]::new($false))
  $value=ReadPackageManifest $package
  if ($value.state -cne $case.state -or $value.display_name_basis -cne $case.basis -or $value.display_name -cne $case.name) {throw ('Synthetic parser case failed: '+$case.label)}
  if ($value.state -eq 'read' -and $value.sha256 -cne (Get-FileHash -LiteralPath (Join-Path $directory 'AppxManifest.xml') -Algorithm SHA256).Hash.ToLowerInvariant()) {throw 'Manifest fingerprint differs'}
  $results+=@{case=$case.label;passed=$true;state=$value.state;basis=$value.display_name_basis}
 }
 $package.IsBundle=$true;$value=ReadPackageManifest $package
 if ($value.state -ne 'not_applicable') {throw 'Bundle was read as main package'}
 $results+=@{case='bundle-excluded';passed=$true;state=$value.state}
} finally {Remove-Item -LiteralPath $directory -Recurse -Force}
[ordered]@{synthetic=$true;actual_inventory=$false;cases=$results;uri_cases=$uriCases.Count;temporary_files_removed=(-not(Test-Path -LiteralPath $directory))} | ConvertTo-Json -Depth 6 -Compress
