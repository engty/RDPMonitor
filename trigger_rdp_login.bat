@echo off
setlocal enabledelayedexpansion

:: 设置脚本路径
set SCRIPT_PATH=%~dp0
cd /d "%SCRIPT_PATH%"

:: 读取配置中的RDP端口
set RDP_PORT=3389
if exist "%SCRIPT_PATH%config\config.json" (
    for /f "tokens=*" %%a in ('powershell -Command "(Get-Content -Raw '%SCRIPT_PATH%config\config.json' | ConvertFrom-Json).rdp_port"') do (
        set RDP_PORT=%%a
    )
)

:: 如果端口为空，使用默认3389
if "!RDP_PORT!"=="" set RDP_PORT=3389

:: 记录日志
if not exist "%~dp0logs" mkdir "%~dp0logs"
echo 检测到RDP登录事件 > "%~dp0logs\message.log"
date /t >> "%~dp0logs\message.log"
time /t >> "%~dp0logs\message.log"
hostname >> "%~dp0logs\message.log"
whoami >> "%~dp0logs\message.log"
echo RDP端口: %RDP_PORT% >> "%~dp0logs\message.log"

:: 记录网络连接
echo --- NETSTAT 输出 --- >> "%~dp0logs\message.log"
netstat -n | findstr ":%RDP_PORT% ESTABLISHED" >> "%~dp0logs\message.log"

:: 记录登录日志
date /t >> "%~dp0logs\rdp_login.log"
time /t >> "%~dp0logs\rdp_login.log"
whoami >> "%~dp0logs\rdp_login.log"
echo 远程连接信息： >> "%~dp0logs\rdp_login.log"
netstat -n | findstr ":%RDP_PORT% ESTABLISHED" >> "%~dp0logs\rdp_login.log"
echo ---------------------------------------- >> "%~dp0logs\rdp_login.log"

:: 触发通知发送
start /min cscript //nologo //B "%~dp0send_notification.vbs"

:: 等待1秒再启动验证
ping 127.0.0.1 -n 2 > nul

:: 启动Python脚本进行PIN验证
start /min pythonw "%~dp0rdp_trigger.py" --verify-pin

endlocal 