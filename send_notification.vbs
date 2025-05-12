Option Explicit

' Create WScript Shell object
Dim shell, fso, strScriptPath, strMessageFile, strConfigFile
Dim strConfig, strSCKEY, jsonFile, msgFile, strMessageContent
Dim portRegEx, portMatches, regEx, matches, rdpPort, ipRegEx, ipMatches
Dim i, potentialIP, strClientIP, strPythonCmd
Dim http, strURL, logFile, logStream
Dim simplifiedContent, strComputerName, strCurrentTime
Dim flagFile, fileAge
Dim strLogFile

' Initialize shell and paths
Set shell = WScript.CreateObject("WScript.Shell")
strScriptPath = Replace(WScript.ScriptFullName, WScript.ScriptName, "")
strMessageFile = strScriptPath & "logs\message.log"
strConfigFile = strScriptPath & "config\config.json"
strLogFile = strScriptPath & "logs\rdp_trigger.log"
rdpPort = "3389" ' Default RDP port

' Create file system object
Set fso = CreateObject("Scripting.FileSystemObject")

' Check if flag file exists and is recent (less than 30 seconds old)
flagFile = strScriptPath & "logs\notification_sent.flag"
If fso.FileExists(flagFile) Then
    fileAge = DateDiff("s", fso.GetFile(flagFile).DateLastModified, Now())
    If fileAge < 30 Then
        ' Skip sending duplicate notification
        WScript.Quit
    End If
End If

' Run batch file
On Error Resume Next
Call shell.Run("cmd.exe /c """ & strScriptPath & "trigger_rdp_login.bat""", 0)
WScript.Sleep 100

' Read config file for RDP port
If fso.FileExists(strConfigFile) Then
    Set jsonFile = fso.OpenTextFile(strConfigFile, 1, False)
    strConfig = jsonFile.ReadAll
    jsonFile.Close
    
    ' Extract RDP port from config
    Set portRegEx = New RegExp
    portRegEx.Pattern = """rdp_port"":\s*(\d+)"
    portRegEx.IgnoreCase = True
    portRegEx.Global = False
    
    Set portMatches = portRegEx.Execute(strConfig)
    If portMatches.Count > 0 Then
        rdpPort = portMatches(0).SubMatches(0)
    End If
    
    ' Extract SCKEY from config
    Set regEx = New RegExp
    regEx.Pattern = """sckey"":\s*""([^""]+)"""
    regEx.IgnoreCase = True
    regEx.Global = False
    
    Set matches = regEx.Execute(strConfig)
    If matches.Count > 0 Then
        strSCKEY = matches(0).SubMatches(0)
    Else
        strSCKEY = "SCT193132TFWL7mLnu8pqgKDBERSDN2RSp" ' Default SCKEY
    End If
Else
    strSCKEY = "SCT193132TFWL7mLnu8pqgKDBERSDN2RSp" ' Default SCKEY
End If

' Read message file
If fso.FileExists(strMessageFile) Then
    Set msgFile = fso.OpenTextFile(strMessageFile, 1, False)
    strMessageContent = msgFile.ReadAll
    msgFile.Close
Else
    strMessageContent = "RDP Login Detected"
End If

' Extract IP address
Set ipRegEx = New RegExp
ipRegEx.Pattern = "(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
ipRegEx.IgnoreCase = True
ipRegEx.Global = True

Set ipMatches = ipRegEx.Execute(strMessageContent)
strClientIP = "External IP"

If ipMatches.Count > 0 Then
    For i = 0 To ipMatches.Count - 1
        potentialIP = ipMatches(i).SubMatches(0)
        ' Filter local IPs
        If Not (Left(potentialIP, 3) = "127" Or Left(potentialIP, 3) = "192" Or Left(potentialIP, 3) = "10." Or potentialIP = "0.0.0.0") Then
            strClientIP = potentialIP
            Exit For
        End If
    Next
End If

' Create or update flag file
Set logStream = fso.CreateTextFile(flagFile, True)
logStream.WriteLine Now()
logStream.Close

' Call Python script for notification
strPythonCmd = "pythonw """ & strScriptPath & "rdp_monitor.py"" --trigger-notify"
shell.Run strPythonCmd, 0, False

' Add delay to avoid duplicate notifications
WScript.Sleep 2000

' If Python fails, use HTTP request as fallback
If Err.Number <> 0 Then
    Err.Clear
    On Error Resume Next
    Set http = CreateObject("MSXML2.XMLHTTP")
    
    If Err.Number = 0 Then
        ' Get computer name and current time
        strComputerName = shell.ExpandEnvironmentStrings("%COMPUTERNAME%")
        strCurrentTime = Now()
        
        ' Create simple notification message
        simplifiedContent = "RDP Login Alert!" & Chr(13) & Chr(10)
        simplifiedContent = simplifiedContent & "Computer: " & strComputerName & Chr(13) & Chr(10)
        simplifiedContent = simplifiedContent & "IP: " & strClientIP & Chr(13) & Chr(10)
        simplifiedContent = simplifiedContent & "Port: " & rdpPort & Chr(13) & Chr(10)
        simplifiedContent = simplifiedContent & "Time: " & strCurrentTime
        
        ' Build URL
        strURL = "https://sctapi.ftqq.com/" & strSCKEY & ".send"
        
        ' Send request
        http.open "POST", strURL, False
        http.setRequestHeader "Content-Type", "application/x-www-form-urlencoded"
        http.send "title=Windows RDP Login&desp=" & URLEncode(simplifiedContent)
        
        ' Log results
        If fso.FolderExists(strScriptPath & "logs") = False Then
            fso.CreateFolder(strScriptPath & "logs")
        End If
        
        logFile = strScriptPath & "logs\vbs_notification.log"
        Set logStream = fso.CreateTextFile(logFile, True)
        logStream.WriteLine "Time: " & Now()
        logStream.WriteLine "Status: " & http.Status
        logStream.WriteLine "Response: " & Left(http.responseText, 100)
        logStream.Close
    End If
End If

' URL Encode function
Function URLEncode(strText)
    Dim i, c, result
    result = ""
    For i = 1 To Len(strText)
        c = Mid(strText, i, 1)
        If c = " " Then
            result = result & "+"
        ElseIf (Asc(c) >= 48 And Asc(c) <= 57) Or _
               (Asc(c) >= 65 And Asc(c) <= 90) Or _
               (Asc(c) >= 97 And Asc(c) <= 122) Then
            result = result & c
        Else
            result = result & "%" & Hex(Asc(c))
        End If
    Next
    URLEncode = result
End Function 