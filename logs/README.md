# 日志目录 (Logs Directory)

此目录用于存储RDP监控系统的各种日志文件。

## 文件说明

- `rdp_monitor.log`: 主程序日志
- `rdp_trigger.log`: 触发器日志
- `rdp_login.log`: 登录记录日志
- `message.log`: 消息日志
- `disconnect_log.txt`: 断开连接日志
- `notification_debug.log`: 通知调试日志
- `rdp_monitor_service.log`: 服务日志
- `service_start.log`: 服务启动日志
- `error.log`: 错误日志

**注意**：实际运行时，这些日志文件会被动态生成和更新。日志文件不应提交到Git仓库。 