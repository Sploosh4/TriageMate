Option Explicit
Dim shell, action, result, request, attempt, ready, files, project, dockerDesktop
Dim portFile, portStream, address, addressPattern, applicationUrl
Set shell = CreateObject("WScript.Shell")
Set files = CreateObject("Scripting.FileSystemObject")
project = files.GetParentFolderName(files.GetParentFolderName(WScript.ScriptFullName))
shell.CurrentDirectory = project
action = "open"
If WScript.Arguments.Count > 0 Then action = LCase(WScript.Arguments(0))

result = shell.Run("cmd.exe /d /c docker info >NUL 2>&1", 0, True)
If result <> 0 Then
    dockerDesktop = shell.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\Programs\DockerDesktop\Docker Desktop.exe"
    If files.FileExists(dockerDesktop) Then shell.Run Chr(34) & dockerDesktop & Chr(34), 0, False
    For attempt = 1 To 120
        WScript.Sleep 1000
        result = shell.Run("cmd.exe /d /c docker info >NUL 2>&1", 0, True)
        If result = 0 Then Exit For
    Next
End If
If result <> 0 Then
    ReportFailure "Start Docker Desktop, then open TriageMate again."
    WScript.Quit 1
End If
result = shell.Run("cmd.exe /d /c docker compose up -d --wait --wait-timeout 180 > container-start.log 2>&1", 0, True)
If result <> 0 Then
    ReportFailure "TriageMate could not start. Inspect container-start.log and docs/guides/CONTAINERS.md."
    WScript.Quit result
End If
If action = "background" Then WScript.Quit 0
portFile = files.BuildPath(shell.ExpandEnvironmentStrings("%TEMP%"), files.GetTempName())
result = shell.Run("cmd.exe /d /c docker compose port app 8000 > " & Chr(34) & portFile & Chr(34), 0, True)
address = ""
If files.FileExists(portFile) Then
    Set portStream = files.OpenTextFile(portFile, 1)
    address = Trim(Replace(Replace(portStream.ReadAll, vbCr, ""), vbLf, ""))
    portStream.Close
    files.DeleteFile portFile
End If
Set addressPattern = New RegExp
addressPattern.Pattern = "^127\.0\.0\.1:[0-9]{1,5}$"
If result <> 0 Or Not addressPattern.Test(address) Then
    ReportFailure "Cannot determine TriageMate's local address. Inspect docker compose port app 8000."
    WScript.Quit 1
End If
applicationUrl = "http://" & address
ready = False
For attempt = 1 To 60
    On Error Resume Next
    Set request = CreateObject("MSXML2.ServerXMLHTTP.6.0")
    request.setTimeouts 1000, 1000, 1000, 1000
    request.open "GET", applicationUrl & "/api/session", False
    request.send
    If Err.Number = 0 Then
        If request.status = 200 Then ready = True
    End If
    Err.Clear
    On Error GoTo 0
    If ready Then Exit For
    WScript.Sleep 1000
Next
If Not ready Then
    ReportFailure "TriageMate did not become ready. Run docker compose logs in the project directory."
    WScript.Quit 1
End If
If action = "verify" Then
    WScript.Echo "TriageMate is ready at " & applicationUrl
    WScript.Quit 0
End If
shell.Run applicationUrl, 1, False

Sub ReportFailure(message)
    If action = "open" Then
        MsgBox message, vbExclamation, "TriageMate"
    ElseIf action = "verify" Then
        WScript.Echo message
    End If
End Sub
