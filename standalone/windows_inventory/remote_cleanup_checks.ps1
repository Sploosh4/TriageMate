# Synthetic API observations only: these functions never inspect or kill a process.
$cases=@(
 @{label='exact-start';delta=0;identity=$true;exited=$false;expected=1},
 @{label='sub-microsecond-start';delta=2;identity=$true;exited=$false;expected=1},
 @{label='last-sub-microsecond-tick';delta=9;identity=$true;exited=$false;expected=1},
 @{label='different-start';delta=10;identity=$true;exited=$false;expected=0},
 @{label='earlier-start';delta=-1;identity=$true;exited=$false;expected=0},
 @{label='unrelated-invocation';delta=0;identity=$false;exited=$false;expected=0},
 @{label='already-exited';delta=0;identity=$true;exited=$true;expected=0}
)
function Get-CimInstance {
 param($ClassName,$Filter)
 [pscustomobject]@{CommandLine=$script:commandLine;ProcessId=123;CreationDate=$script:reportedStart}
}
function Get-Process {
 param($Id,$ErrorAction)
 $script:fakeProcess
}
$results=@()
foreach($case in $cases) {
 $script:kills=0;$script:waits=0
 $script:reportedStart=[DateTime]::new(638000000000000000,[DateTimeKind]::Utc)
 $script:commandLine=if($case.identity){'__IDENTITY__'}else{'unrelated synthetic invocation'}
 $script:fakeProcess=[pscustomobject]@{HasExited=$case.exited;StartTime=$script:reportedStart.AddTicks($case.delta)}
 $script:fakeProcess | Add-Member ScriptMethod Kill {$script:kills++}
 $script:fakeProcess | Add-Member ScriptMethod WaitForExit {param($milliseconds) if($milliseconds -ne 2000){throw 'Unexpected wait'};$script:waits++;return $true}
 __CLEANUP__
 if($script:kills -ne $case.expected -or $script:waits -ne $case.expected){throw ('Cleanup identity guard failed: '+$case.label)}
 $results+=@{label=$case.label;passed=$true;kills=$script:kills}
}
ConvertTo-Json -InputObject @{synthetic=$true;actual_processes_terminated=$false;cases=$results} -Depth 4 -Compress
