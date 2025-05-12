@echo off
echo RDP连接断开工具 - 以管理员权限运行
echo 当前时间: %date% %time%

REM 检查是否有/silent参数
set SILENT=0
if "%1"=="/silent" set SILENT=1

REM 检查是否有/disconnect参数
set MODE=FULL
if "%1"=="/disconnect" set MODE=DISCONNECT_ONLY

REM 获取脚本所在目录
set SCRIPT_DIR=%~dp0
cd /d %SCRIPT_DIR%

REM 创建断开日志目录
if not exist logs mkdir logs
set LOG_FILE=logs\disconnect_log.txt

REM 记录日志
echo ======================================= >> %LOG_FILE%
echo 开始执行断开操作 - %date% %time% >> %LOG_FILE%
echo ======================================= >> %LOG_FILE%

if %SILENT%==0 (
  echo 正在尝试多种方法断开RDP连接...
  echo 请稍候...
)

REM 使用PowerShell进行高级断开操作
echo 方法0: 使用PowerShell进行高级断开操作 >> %LOG_FILE%
if %SILENT%==0 echo 方法0: 使用PowerShell进行高级断开操作
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "try { $wtsapi = Add-Type -MemberDefinition '[DllImport(\"wtsapi32.dll\")]public static extern bool WTSDisconnectSession(IntPtr hServer, int sessionId, bool bWait);' -Name WTSFunctions -Namespace Win32Functions -PassThru; $wtsapi::WTSDisconnectSession([IntPtr]::Zero, -1, $true) } catch { Write-Error $_.Exception.Message }"

REM 第一组方法: 使用qwinsta和rwinsta命令
echo 方法1: 使用qwinsta和rwinsta命令断开连接 >> %LOG_FILE%
if %SILENT%==0 echo 方法1: 使用qwinsta和rwinsta命令断开连接
for /f "tokens=2" %%s in ('qwinsta ^| findstr "rdp"') do (
  echo 断开会话 %%s >> %LOG_FILE%
  if %SILENT%==0 echo 断开会话 %%s
  rwinsta %%s
  timeout /t 1 /nobreak > nul
)

REM 第二组方法: 使用tsdiscon命令断开连接而不注销
echo 方法2: 使用tsdiscon命令断开连接 >> %LOG_FILE%
if %SILENT%==0 echo 方法2: 使用tsdiscon命令断开连接
for /f "tokens=2" %%s in ('query session ^| findstr "Active"') do (
  echo 断开会话 %%s >> %LOG_FILE%
  if %SILENT%==0 echo 断开会话 %%s
  tsdiscon %%s /v
  timeout /t 1 /nobreak > nul
)

REM 尝试断开所有可能的会话ID
for /l %%i in (0,1,10) do (
  tsdiscon %%i /v
)

REM 第三组方法: 使用tscon命令转移会话到控制台
echo 方法3: 使用tscon命令转移到控制台 >> %LOG_FILE%
if %SILENT%==0 echo 方法3: 使用tscon命令转移到控制台
for /f "tokens=2" %%s in ('query session ^| findstr "Active"') do (
  echo 转移会话 %%s 到控制台 >> %LOG_FILE%
  if %SILENT%==0 echo 转移会话 %%s 到控制台
  tscon %%s /dest:console
  timeout /t 1 /nobreak > nul
)

REM 第四组方法: 使用logoff命令强制注销会话
echo 方法4: 使用reset session命令重置会话 >> %LOG_FILE%
if %SILENT%==0 echo 方法4: 使用reset session命令重置会话
for /f "tokens=2" %%s in ('query session ^| findstr "Active rdp"') do (
  echo 重置会话 %%s >> %LOG_FILE%
  if %SILENT%==0 echo 重置会话 %%s
  reset session %%s /server:localhost
  timeout /t 1 /nobreak > nul
)

REM 第五组方法: 结束远程桌面客户端进程
echo 方法5: 结束远程桌面客户端进程 >> %LOG_FILE%
if %SILENT%==0 echo 方法5: 结束远程桌面客户端进程
taskkill /f /im mstsc.exe
taskkill /f /im rdpclip.exe
taskkill /f /im rdpshell.exe
taskkill /f /im rdpinit.exe
taskkill /f /im dwm.exe
taskkill /f /im LogonUI.exe
timeout /t 1 /nobreak > nul

REM 使用WMIC管理远程会话
echo 方法6: 使用WMIC管理远程会话 >> %LOG_FILE%
if %SILENT%==0 echo 方法6: 使用WMIC管理远程会话
wmic path Win32_LogonSession Where "LogonType=10" Delete
wmic path Win32_ServerSession Where "ClientIPAddress!=''" Call Disconnect

REM 如果使用DISCONNECT_ONLY模式，跳过以下操作
if "%MODE%"=="DISCONNECT_ONLY" goto END_SERVICES

REM 第七组方法: 重启终端服务 (谨慎使用)
echo 方法7: 重启远程桌面服务 >> %LOG_FILE%
if %SILENT%==0 echo 方法7: 重启远程桌面服务
net stop UmRdpService /y
net stop TermService /y
timeout /t 2 /nobreak > nul
net start TermService
net start UmRdpService

:END_SERVICES

REM 第八组方法: 使用WMI断开会话
echo 方法8: 使用PowerShell和WMI断开会话 >> %LOG_FILE%
if %SILENT%==0 echo 方法8: 使用PowerShell和WMI断开会话
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'SilentlyContinue'; Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\cimv2\terminalservices -ComputerName localhost -Authentication 6 | Invoke-WmiMethod -Name DisconnectSession; Get-WmiObject -Class Win32_TSLogonSession -Namespace root\cimv2\terminalservices | Where-Object {$_.State -eq 4} | ForEach-Object { $_ | Remove-WmiObject }; Get-CimInstance -ClassName Win32_Session | Where-Object {$_.LogonType -eq 10} | Remove-CimInstance"

REM 第九组方法: 使用COM对象直接操作RDP会话
echo 方法9: 使用COM对象断开会话 >> %LOG_FILE%
if %SILENT%==0 echo 方法9: 使用COM对象断开会话
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'SilentlyContinue'; try { $shell = New-Object -ComObject Shell.Application; $shell.WindowSwitcher.CloseAll(); } catch {}"

REM 第十组方法: 禁用RDP服务然后再启用
echo 方法10: 禁用RDP服务然后再启用 >> %LOG_FILE%
if %SILENT%==0 echo 方法10: 禁用RDP服务然后再启用
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
timeout /t 2 /nobreak > nul
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

REM 第十一组方法: 使用系统策略断开连接
echo 方法11: 使用系统策略断开连接 >> %LOG_FILE%
if %SILENT%==0 echo 方法11: 使用系统策略断开连接
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "$ErrorActionPreference = 'SilentlyContinue'; $process = Start-Process 'gpupdate.exe' -ArgumentList '/force','/logoff' -Wait -PassThru -WindowStyle Hidden"

echo ======================================= >> %LOG_FILE%
echo 断开连接操作完成 - %date% %time% >> %LOG_FILE%
echo ======================================= >> %LOG_FILE%

REM 最后强制执行断开操作
sc stop SessionEnv
sc stop TermService
sc stop UmRdpService
timeout /t 2 /nobreak > nul
sc start TermService
sc start SessionEnv
sc start UmRdpService

if %SILENT%==0 (
  echo 断开连接操作完成，请查看日志文件 %LOG_FILE%
  echo 按任意键退出...
  pause > nul
) 