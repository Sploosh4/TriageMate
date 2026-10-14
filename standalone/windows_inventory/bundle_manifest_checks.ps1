# Explicitly synthetic parser checks; no actual package reads or installations.
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$directory=Join-Path ([IO.Path]::GetTempPath()) ('triagemate-bundle-test-'+[Guid]::NewGuid().ToString())
[void][IO.Directory]::CreateDirectory((Join-Path $directory 'AppxMetadata'))
$originalTemp=$env:TEMP;$originalTmp=$env:TMP
$spoolDirectory=Join-Path $directory 'spools'
[void][IO.Directory]::CreateDirectory($spoolDirectory)
$results=@()
function WriteInventoryJson([string]$json) {$script:emitted.Add($json)}
try {
 $env:TEMP=$spoolDirectory;$env:TMP=$spoolDirectory
 if ([IO.Path]::GetTempPath().TrimEnd('\') -cne $spoolDirectory.TrimEnd('\')) {throw 'Synthetic spool isolation failed'}
 $package=[pscustomobject]@{Name='Synthetic.App';Publisher='Synthetic publisher';Version=[version]'1.2.3.4';PackageFamilyName='Synthetic.App_publisher';PackageFullName='synthetic-bundle';InstallLocation=$directory}
 $base='<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle"><Identity Name="Synthetic.App" Publisher="Synthetic publisher" Version="1.2.3.4"/><Packages><Package Type="application" Version="5.6.7.8" Architecture="x64"/><Package Version="2.3.4.5" ResourceId="split.scale-200" IsStub="true"/></Packages></Bundle>'
 $cases=@(
  @{label='valid-different-versions-and-defaults';xml=$base;state='read';count=2},
  @{label='wrong-identity';xml=$base.Replace('Name="Synthetic.App"','Name="Another.App"');state='unavailable';count=0},
  @{label='duplicate-identity';xml=$base.Replace('<Packages>','<Identity Name="Synthetic.App" Publisher="Synthetic publisher" Version="1.2.3.4"/><Packages>');state='unavailable';count=0},
  @{label='missing-identity';xml=$base.Replace('<Identity Name="Synthetic.App" Publisher="Synthetic publisher" Version="1.2.3.4"/>','');state='unavailable';count=0},
  @{label='truncated-after-valid-member';xml=$base.Substring(0,$base.Length-9);state='unavailable';count=0},
  @{label='invalid-second-member';xml=$base.Replace('Version="2.3.4.5"','Version="65536.3.4.5"');state='unavailable';count=0},
  @{label='invalid-resource-id';xml=$base.Replace('split.scale-200','../escape');state='unavailable';count=0},
  @{label='invalid-stub';xml=$base.Replace('IsStub="true"','IsStub="maybe"');state='unavailable';count=0},
  @{label='invalid-namespace';xml=$base.Replace('http://schemas.microsoft.com/appx/2013/bundle','urn:synthetic:wrong');state='unavailable';count=0},
  @{label='dtd';xml='<!DOCTYPE Bundle [<!ENTITY test "value">]>'+$base;state='unavailable';count=0},
  @{label='oversized-field';xml=$base.Replace('Architecture="x64"',('Architecture="'+('x'*5000)+'"'));state='unavailable';count=0},
  @{label='empty-member-list';xml=$base.Replace('<Package Type="application" Version="5.6.7.8" Architecture="x64"/><Package Version="2.3.4.5" ResourceId="split.scale-200" IsStub="true"/>','');state='read';count=0}
 )
 foreach ($case in $cases) {
  [IO.File]::WriteAllText((Join-Path $directory 'AppxMetadata\AppxBundleManifest.xml'),$case.xml,[Text.UTF8Encoding]::new($false))
  $script:emitted=[Collections.Generic.List[string]]::new()
  $summary=ReadBundleManifest $package
  if ($summary.state -cne $case.state -or $summary.member_count -ne $case.count -or $script:emitted.Count -ne $case.count) {throw ('Bundle test failed: '+$case.label)}
  if ($case.count -eq 2) {
   $first=$script:emitted[0] | ConvertFrom-Json;$second=$script:emitted[1] | ConvertFrom-Json
   if ($first.version -cne '5.6.7.8' -or $second.architecture -cne 'neutral' -or $second.member_type -cne 'resource' -or $second.resource_id -cne 'split.scale-200' -or $second.is_stub -ne $true) {throw 'Bundle defaults or original values lost'}
  }
  if (@([IO.Directory]::EnumerateFileSystemEntries($spoolDirectory)).Count -ne 0) {throw ('Bundle spool leaked: '+$case.label)}
  $results+=@{label=$case.label;passed=$true;spool_cleanup_verified=$true}
 }
} finally {
 $env:TEMP=$originalTemp;$env:TMP=$originalTmp
 if ([IO.Directory]::Exists($directory)) {[IO.Directory]::Delete($directory,$true)}
}
ConvertTo-Json -InputObject @{synthetic=$true;actual_inventory=$false;temporary_files_removed=(-not [IO.Directory]::Exists($directory));cases=$results} -Depth 5 -Compress
