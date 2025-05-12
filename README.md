# Windows RDP登录监控工具

## 目录
1. [简介](#简介)
2. [主要功能](#主要功能)
3. [快速开始](#快速开始)
4. [安装指南](#安装指南)
   - [系统要求](#系统要求)
   - [安装步骤](#安装步骤)
   - [目录结构](#目录结构)
5. [配置说明](#配置说明)
   - [基本配置](#基本配置)
   - [自定义RDP端口](#自定义rdp端口)
   - [PIN码验证](#pin码验证)
6. [使用方法](#使用方法)
   - [直接启动](#直接启动)
   - [Windows服务](#windows服务)
   - [任务计划触发器](#任务计划触发器)
7. [常见问题解决](#常见问题解决)
8. [更新日志](#更新日志)
9. [附录](#附录)
    - [命令行参数](#命令行参数)
    - [测试功能](#测试功能)

## 简介

这个工具用于监控Windows系统中的RDP（远程桌面）登录事件，当检测到外网IP登录时，会自动发送通知到指定的推送渠道（默认使用Server酱推送服务）。支持智能区分内外网IP，并可以通过PIN码验证增强安全性。支持自定义RDP端口，适用于修改了默认远程桌面端口的服务器。

## 主要功能

- 实时监控RDP远程登录事件（成功登录、失败尝试、注销等）
- 智能区分内外网IP地址，只对外网登录IP发送通知
- 支持登录PIN码验证，防止未授权访问
- 美观的PIN码验证界面，带倒计时进度条和现代化UI设计
- 支持自定义RDP端口，适配非标准远程桌面配置
- 提取登录账户、源IP地址、登录时间等详细信息
- 自动记录所有登录事件到JSON数据文件
- 生成详细日志记录，支持自动按日期归档
- 日志保留天数可配置
- 多种命令行参数支持（调试模式、测试通知、IP类型检测等）
- 支持通过Windows任务计划程序实时触发RDP登录检测和通知
- IP黑、白名单功能，自动放行白名单或阻止多次登录失败的IP

## 快速开始

1. 安装依赖：
   ```
   pip install -r requirements.txt
   ```

2. 以管理员权限运行：
   ```
   python rdp_monitor.py --admin
   ```

3. 或注册为Windows服务：
   ```
   python setup_service.py install
   ```

## 安装指南

### 系统要求
- Windows操作系统
- Python 3.6或更高版本
- 管理员权限（读取Windows安全日志需要）

### 安装步骤
1. 下载或克隆此仓库到本地目录
2. 安装依赖包：
   ```
   pip install -r requirements.txt
   ```
3. 配置文件已经提供：
   项目包含默认的`config/config.json`文件，您可以直接修改其中的配置项。这个文件在Git中被标记为忽略，所以您的本地修改不会被提交到代码库。
   
   主要配置项包括：
   - `sckey`: 修改为您的Server酱推送密钥
   - `pin_code`: 设置您自己的PIN验证码
   - `rdp_port`: 如果修改了默认远程桌面端口，请在这里设置
   
4. 以管理员权限运行Python脚本，设置并启动监控服务

### 目录结构
```
rdp_monitor/
  ├── rdp_monitor.py          # 主程序，实现RDP登录监控核心功能
  ├── rdp_trigger.py          # 登录触发Python处理程序，任务计划调用
  ├── setup_service.py        # Windows服务安装程序，用于注册Windows服务
  ├── debug_notification.py   # 调试通知工具，用于测试推送功能
  ├── send_notification.vbs   # 通知发送VBS脚本，用于实时触发推送
  ├── trigger_rdp_login.bat   # RDP登录触发批处理脚本，任务计划使用
  ├── force_disconnect.bat    # 强制断开RDP连接的批处理脚本
  ├── requirements.txt        # 依赖包列表，包含程序运行所需的Python库
  ├── README.md               # 项目简介文档
  ├── .gitignore              # Git忽略文件配置
  ├── logs/                   # 日志目录
  │   ├── rdp_monitor.log     # 主程序日志文件，记录运行状态和事件
  │   ├── rdp_monitor_service.log # 服务日志文件，记录服务状态
  │   ├── rdp_trigger.log     # 触发器日志文件，记录触发事件
  │   ├── disconnect_log.txt  # 断开连接操作日志文件
  │   ├── message.log         # 消息日志文件，记录RDP连接事件的信息
  │   ├── rdp_login.log       # RDP登录历史日志，包含详细的登录记录
  │   ├── vbs_notification.log # VBS脚本通知日志
  │   ├── pin_verification_result.txt # PIN验证结果文件
  │   ├── rdp_monitor.log.{日期} # 按日期归档的日志文件
  │   ├── rdp_monitor_service.log.{日期} # 按日期归档的服务日志
  │   ├── notification_sent.flag # 通知发送标志文件，防止短时间内重复发送
  │   ├── notification_debug.log # 通知调试日志
  │   ├── error.log           # 错误日志文件
  │   ├── service_start.log   # 服务启动日志
  │   └── .gitkeep            # Git空目录占位文件
  ├── data/                   # 数据存储目录
  │   ├── rdp_events.json     # 登录事件记录文件，包含所有检测到的RDP事件
  │   ├── failed_attempts.json # 失败尝试记录文件，用于防暴力破解
  │   ├── verification_history.json # PIN验证历史记录
  │   ├── processed_events.json # 已处理事件ID记录，避免重复处理
  │   ├── pin_verification_result.txt # PIN验证结果文件
  │   ├── ip_blacklist.txt    # IP黑名单文件，存储被禁止的IP地址
  │   ├── ip_whitelist.txt    # IP白名单文件，存储允许访问的IP地址
  │   ├── README.md           # 数据目录说明文档
  │   └── .gitkeep            # Git空目录占位文件
  └── config/                 # 配置目录
      ├── config.json         # 配置文件，存储通知URL、SCKEY、PIN码等设置
      └── config.json.example # 示例配置文件，用于首次设置参考
```

## 配置说明

### 基本配置
配置文件位于`config/config.json`，包含以下设置：
```json
{
  "notification_url": "https://sctapi.ftqq.com/{sckey}.send",
  "sckey": "YOUR_SCKEY",
  "pin_code": "123456",
  "rdp_port": 3389,
  "log_retention_days": 90,
  "ip_whitelist": "192.168.1.1",
  "max_failed_attempts": 3,
  "blacklist_cooldown": 24,
  "verification_timeout": 60,
  "verification_cooldown": 60,
  "ip_blacklistfile": "data/ip_blacklist.txt",
  "ip_whitelistfile": "data/ip_whitelist.txt"
}
```

- `notification_url`: 通知推送URL，默认使用Server酱
- `sckey`: Server酱的推送密钥，可在[Server酱](https://sct.ftqq.com/)网站获取
- `pin_code`: RDP登录验证PIN码，远程连接时需要验证
- `rdp_port`: RDP远程桌面端口，默认3389，如修改过系统RDP端口请在此处同步设置
- `log_retention_days`: 日志保留天数，0表示仅保留当天日志
- `max_failed_attempts`: 登录失败的最大尝试次数，超过后将加入黑名单
- `blacklist_cooldown`: 黑名单冷却时间（小时）
- `verification_timeout`: 验证超时时间（秒）
- `verification_cooldown`: 验证冷却时间（秒），防止重复验证
- `ip_blacklistfile`: 黑名单文件路径
- `ip_whitelistfile`: 白名单文件路径，IP白名单文件存储路径，每行一个IP或CIDR

### 自定义RDP端口
如果您修改了Windows默认的远程桌面端口（3389），请务必在配置中设置相同的端口号：

1. 通过命令行设置：
   ```
   python rdp_monitor.py --port 您的RDP端口
   ```

2. 或直接编辑配置文件`config/config.json`：
   ```json
   {
     "rdp_port": 您的RDP端口
   }
   ```

## 使用方法

### 任务计划触发器
使用Windows任务计划程序设置在RDP登录时自动触发监控，这种方法及时可靠：

#### 配置步骤：

1. **确认文件准备**
   确保以下文件已经存在于程序目录中：
   - `trigger_rdp_login.bat` - RDP登录触发批处理脚本
   - `send_notification.vbs` - 发送通知的VBS脚本
   - `rdp_trigger.py` - 登录触发Python处理程序
   - `rdp_monitor.py` - 主监控程序

2. **创建任务计划**
   - 按下 `Win + R`，输入 `taskschd.msc` 并回车，打开任务计划程序
   - 在右侧面板中，点击"创建任务"
   - 在"常规"选项卡中：
     - 名称：输入 `RDP登录监控触发器`
     - 描述：输入 `当检测到RDP远程登录时触发监控程序`
     - 选择"使用最高权限运行"
     - 在"配置"下拉菜单中选择您的Windows版本

   - 在"触发器"选项卡中：
     - 点击"新建"按钮
     - 在"开始任务"下拉菜单中选择"当连接到用户会话时"
     - 确保"已启用"选项被勾选
     - 点击"确定"

   - 在"操作"选项卡中：
     - 点击"新建"按钮
     - 操作：选择"启动程序"
     - 程序/脚本：输入 `cscript`
     - 添加参数：输入 `//nologo //B "完整路径\send_notification.vbs"`（请将路径替换为实际安装路径，必须使用完整路径）
     - 起始位置：输入程序安装的完整路径
     - 点击"确定"

   - 在"条件"和"设置"选项卡中按需配置，然后点击"确定"按钮保存任务

## 常见问题解决

### 1. 程序未检测到登录事件
- 确保程序以管理员权限运行
- 检查系统事件查看器中的安全日志是否有记录（Event Viewer -> Windows Logs -> Security）
- 查看`logs/rdp_monitor.log`文件是否有错误信息
- 尝试配置任务计划触发器方式进行检测

### 2. 推送通知未收到
- 检查网络连接是否正常
- 验证Server酱SCKEY是否正确
- 尝试使用`--test-push`参数测试推送功能
- 查看日志文件中是否有推送失败的错误信息

### 3. 中文乱码问题
如果日志或通知中出现中文乱码，可以手动将Python脚本文件保存为UTF-8编码格式。

### 4. 服务未自动启动
- 如果使用Windows服务方式安装，请检查服务管理器中服务的状态
- 确认服务配置为自动启动
- 检查系统日志中是否有服务启动失败的错误信息

### 5. 任务计划触发器未工作
- 查看任务计划程序中的历史记录
- 确认任务权限设置正确（需要管理员权限）
- 检查脚本路径是否配置正确
- 查看`logs/rdp_trigger.log`日志文件

### 6. PIN码验证对话框未显示
- 检查脚本权限（需要管理员权限）
- 确认Python环境正确配置
- 查看事件查看器中的应用程序错误日志

### 7. 断开连接功能不工作
- 请确保`force_disconnect.bat`文件位于程序目录中
- 检查是否有足够的权限执行断开操作
- 查看日志文件中是否有关于断开连接的错误信息

## 附录

### 命令行参数
`rdp_monitor.py`支持多种命令行参数：

- `--debug`: 启用调试模式，输出详细日志
- `--url URL`: 设置自定义通知URL
- `--sckey KEY`: 设置Server酱SCKEY
- `--pin CODE`: 设置登录验证PIN码
- `--port PORT`: 设置RDP端口（默认3389）
- `--test`: 测试模式 - 仅检查配置
- `--test-ip IP`: 测试IP地址是否为内网/外网
- `--test-push`: 测试推送功能
- `--test-pin`: 测试PIN码验证对话框
- `--admin`: 尝试获取管理员权限运行
- `--trigger-notify`: 由任务计划触发时发送通知（供内部使用）
- `--fix`: 尝试修复验证后通知问题
- `--verify-pin-only`: 仅进行PIN验证并将结果保存到文件

### 测试功能

测试推送通知：
```
python rdp_monitor.py --test-push
```

测试PIN码验证对话框：
```
python rdp_monitor.py --test-pin
```

测试IP地址类型（内外网判断）：
```
python rdp_monitor.py --test-ip 8.8.8.8
``` 