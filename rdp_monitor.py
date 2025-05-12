import win32evtlog
import win32evtlogutil
import win32con
import win32security
import win32api
import requests
import time
import re
import socket
import logging
import os
import json
import argparse
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
from datetime import datetime, timedelta
from logging.handlers import TimedRotatingFileHandler
from typing import Optional, Dict, Any
import ctypes
import uuid
from pathlib import Path

# 配置日志级别变量，默认INFO
log_level = logging.INFO

# 将日志配置移动到函数中，便于后续调用
def setup_logging(debug_mode=False):
    global log_level
    if debug_mode:
        log_level = logging.DEBUG
    
    # 确保日志目录存在
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, 'logs')
    
    # 如果logs目录不存在，则创建它
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        print(f"已创建日志目录: {log_dir}")
    
    log_file = os.path.join(log_dir, 'rdp_monitor.log')
    
    # 读取日志保留天数配置
    config = load_config()
    log_retention_days = config.get("log_retention_days", 90)  # 默认保留90天
    
    # 创建根日志记录器
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # 清除现有处理器
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # 如果log_retention_days为0，则只保留当天日志，设置backupCount为0
    backup_count = 0 if log_retention_days == 0 else log_retention_days
    
    # 创建一个按天滚动的文件处理器
    file_handler = TimedRotatingFileHandler(
        filename=log_file,
        when='midnight',    # 每天午夜滚动
        interval=1,         # 每1天滚动一次
        backupCount=backup_count,  # 根据配置保留备份
        encoding='utf-8'    # 使用UTF-8编码
    )
    
    # 设置日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # 添加控制台处理器，便于调试
    if debug_mode:
        console = logging.StreamHandler()
        console.setLevel(logging.DEBUG)
        console.setFormatter(formatter)
        root_logger.addHandler(console)
    
    # 删除超过指定天数的老日志文件
    clean_old_logs(log_dir, log_retention_days if log_retention_days > 0 else 1)
    
    logging.info(f"日志级别设置为: {'DEBUG' if debug_mode else 'INFO'}")
    logging.info(f"日志文件路径: {log_file}")
    if log_retention_days == 0:
        logging.info(f"日志保留策略: 仅保留当天日志")
    else:
        logging.info(f"日志保留策略: 保留最近{log_retention_days}天")

def clean_old_logs(log_dir: str, days: int) -> None:
    """删除超过指定天数的日志文件"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # 查找目录中所有日志文件
        for filename in os.listdir(log_dir):
            if filename.startswith('rdp_monitor.log.') or filename.startswith('rdp_monitor_old_'):
                file_path = os.path.join(log_dir, filename)
                file_time = os.path.getmtime(file_path)
                file_date = datetime.fromtimestamp(file_time)
                
                # 如果文件早于截止日期，删除它
                if file_date < cutoff_date:
                    os.remove(file_path)
                    print(f"已删除过期日志文件: {filename}")
    except Exception as e:
        print(f"清理旧日志文件时出错: {e}")

class RDPMonitor:
    """监控Windows RDP登录事件并发送通知"""
    
    def __init__(self, notification_url: str = "", sckey: str = "", pin_code: str = ""):
        self.notification_url = notification_url
        self.sckey = sckey
        self.pin_code = pin_code
        self.server = 'localhost'
        self.logtype = 'Security'
        # 相关事件ID: 4624(登录成功), 4625(登录失败), 4634(注销), 4647(主动注销)
        self.rdp_event_ids = [4624, 4625, 4634, 4647]
        # 记录已处理的事件ID，避免重复处理
        self.processed_events = set()
        # 缓存本地主机名和IP
        self.hostname = socket.gethostname()
        self.local_ip = self._get_local_ip()
        
        # 读取RDP端口配置
        config = load_config()
        rdp_port_config = config.get("rdp_port", None)
        
        # 如果rdp_port为空、None或""，则使用默认端口3389
        if rdp_port_config is None or rdp_port_config == "" or (isinstance(rdp_port_config, str) and not rdp_port_config.strip()):
            self.rdp_port = 3389
            logging.info(f"RDP端口配置为空，使用默认端口: {self.rdp_port}")
        else:
            self.rdp_port = rdp_port_config
            logging.info(f"RDP端口设置为: {self.rdp_port}")
        
    def _get_local_ip(self) -> str:
        """获取本机IP地址"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logging.error(f"获取本地IP失败: {e}")
            return "unknown"
            
    def is_private_ip(self, ip: str) -> bool:
        """判断是否是内网IP地址"""
        # 检查IP是否属于内网网段
        try:
            # 192.168.0.0/16 网段
            if ip.startswith('192.168.'):
                return True
            # 10.0.0.0/8 网段
            if ip.startswith('10.'):
                return True
            # 172.16.0.0/12 网段
            if ip.startswith('172.'):
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            # 169.254.0.0/16 自动私有IP地址
            if ip.startswith('169.254.'):
                return True
            # 本地回环地址
            if ip.startswith('127.'):
                return True
            return False
        except Exception as e:
            logging.error(f"检查IP地址类型失败: {e}")
            return True  # 出错时当作内网IP处理
            
    def extract_client_ip(self, event_data: str) -> Optional[str]:
        """从事件数据中提取客户端IP地址"""
        try:
            # 方法1: 使用netstat命令获取当前RDP连接 - 最可靠的方法
            try:
                # 执行netstat命令
                result = subprocess.run(['netstat', '-n'], capture_output=True, text=True)
                
                # 检查命令是否成功执行
                if result.returncode == 0:
                    # 查找ESTABLISHED状态的RDP连接
                    for line in result.stdout.splitlines():
                        # 检查是否包含RDP端口且状态为ESTABLISHED
                        if f':{self.rdp_port}' in line and 'ESTABLISHED' in line:
                            logging.debug(f"发现RDP连接: {line}")
                            
                            # 提取远程IP地址 - 这是我们需要的客户端IP
                            # 格式: TCP 本地IP:本地端口 远程IP:远程端口 ESTABLISHED
                            pattern = r'TCP\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+'
                            match = re.search(pattern, line)
                            
                            if match:
                                # 提取匹配的IP地址
                                ip = match.group(1)
                                if self._is_valid_client_ip(ip):
                                    logging.info(f"从netstat找到客户端IP: {ip}")
                                    return ip
                            
                            # 如果正则匹配失败，尝试简单提取IP
                            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                            if len(ips) >= 2:  # 应该有至少两个IP (本地IP和远程IP)
                                # 第二个IP通常是客户端IP
                                ip = ips[1]
                                if self._is_valid_client_ip(ip):
                                    logging.info(f"从netstat中提取的第二个IP: {ip}")
                                    return ip
            except Exception as e:
                logging.error(f"使用netstat获取RDP连接失败: {e}")
            
            # 方法2: 从事件数据中提取IP地址
            logging.debug("netstat方法失败，尝试从事件数据中提取IP")
            ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', event_data)
            
            if ips:
                # 过滤掉无效IP
                valid_ips = [ip for ip in ips if self._is_valid_client_ip(ip)]
                if valid_ips:
                    ip = valid_ips[0]
                    logging.info(f"从事件数据中找到有效客户端IP: {ip}")
                    return ip
            
            # 如果所有方法都失败
            logging.warning("未能找到有效的客户端IP地址")
            return None
            
        except Exception as e:
            logging.error(f"提取客户端IP失败: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
            return None
    
    def _is_valid_client_ip(self, ip: str) -> bool:
        """验证IP地址是否为有效的客户端IP"""
        try:
            # 检查IP地址格式
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                return False
            
            # 检查是否为本地IP
            if ip in ['127.0.0.1', '::1', 'localhost']:
                return False
            
            # 检查是否为内网IP
            ip_parts = [int(x) for x in ip.split('.')]
            if (ip_parts[0] == 10 or
                (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or
                (ip_parts[0] == 192 and ip_parts[1] == 168)):
                return True
            
            # 检查是否为公网IP
            if (ip_parts[0] != 0 and ip_parts[0] != 127 and
                ip_parts[0] != 169 and ip_parts[0] != 172 and
                ip_parts[0] != 192 and ip_parts[0] != 224 and
                ip_parts[0] != 240):
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"验证IP地址时发生错误: {e}")
            return False
    
    def is_rdp_logon(self, event_data: str, event_id: int) -> bool:
        """检查是否是RDP登录事件"""
        # 检查登录类型是否为10(RemoteInteractive)或7(解锁)
        logon_type_match = re.search(r'登录类型:\s*(10|7)\s*', event_data, re.IGNORECASE) or \
                          re.search(r'Logon Type:\s*(10|7)\s*', event_data, re.IGNORECASE)
        
        # 查找更多RDP相关关键词
        rdp_keywords = ['远程桌面', 'Remote Desktop', 'RDP', 'TermService', 'Microsoft-Windows-TerminalServices',
                       '远程交互式', 'RemoteInteractive']
        
        # 添加自定义端口检测
        if self.rdp_port != 3389:
            rdp_port_str = str(self.rdp_port)
            rdp_keywords.extend([f":{rdp_port_str}", f"端口 {rdp_port_str}"])
        
        rdp_match = False
        for keyword in rdp_keywords:
            if keyword in event_data:
                rdp_match = True
                break
        
        # 对事件ID 4624(登录成功)，需要验证登录类型
        if event_id == 4624:
            return bool(logon_type_match or rdp_match)
        # 对于其他事件ID，只要包含RDP相关关键词即可
        elif event_id in [4625, 4634, 4647]:
            return bool(rdp_match)
        
        return False
    
    def extract_username(self, event_data: str) -> str:
        """提取登录用户名"""
        # 尝试匹配中文系统格式
        username_match = re.search(r'帐户名称:\s*(.*?)\s*帐户域', event_data, re.IGNORECASE)
        if username_match:
            return username_match.group(1).strip()
            
        # 尝试匹配英文系统格式
        username_match = re.search(r'Account Name:\s*(.*?)\s*Account Domain', event_data, re.IGNORECASE)
        if username_match:
            return username_match.group(1).strip()
            
        # 尝试匹配带有账户用户名的格式
        username_match = re.search(r'帐户.*?用户名:(?:\s*)([^\s]+)', event_data, re.IGNORECASE)
        if username_match:
            return username_match.group(1).strip()
        
        # 尝试匹配英文账户用户名的格式
        username_match = re.search(r'Account.*?User Name:(?:\s*)([^\s]+)', event_data, re.IGNORECASE)
        if username_match:
            return username_match.group(1).strip()
        
        return "unknown"
    
    def send_notification(self, event_data: Dict[str, Any]) -> bool:
        """发送通知"""
        # 获取客户端IP
        client_ip = event_data.get("client_ip", "")
        
        # 加载配置
        config = load_config()
        
        # 检查IP是否在白名单中，只有不在白名单中的IP才发送通知
        if is_ip_in_whitelist(client_ip, config) and not event_data.get("force_notification", False):
            logging.info(f"IP {client_ip} 在白名单中，跳过通知")
            return False
            
        # 构建推送消息
        event_time = event_data.get("event_time", "")
        verification_result = event_data.get("verification_result", "无需验证")
        
        # 按照用户指定的格式构建简单的推送内容
        simple_message = f"检测到白名单外IP登录！\n\n"
        simple_message += f"主机：{self.hostname}\n\n"
        simple_message += f"登陆者IP: {client_ip}\n\n"
        simple_message += f"用户: {event_data.get('username', '未知')}\n\n"
        simple_message += f"时间：{event_time}\n\n"
        
        # 添加验证结果信息（始终包含验证状态，无论是否进行了验证）
        if verification_result:
            simple_message += f"\n\n验证状态: {verification_result}"
        else:
            simple_message += f"\n\n验证状态: 无需验证"
        
        # 添加自定义消息
        if "message" in event_data:
            simple_message += f"\n{event_data['message']}"
        
        # 使用sckey而不是硬编码的值
        sckey = self.sckey if self.sckey else config.get("sckey", "")
        
        # 如果sckey为空，不发送通知
        if not sckey:
            logging.info("SCKEY为空，跳过发送通知")
            return False
        
        try:
            # 构建参数，避免URL长度问题
            title = f"Windows远程登录 - {event_data.get('event_type', '未知事件')}"
            if verification_result:
                # 在标题中添加验证结果
                if verification_result == "成功":
                    title += f" (验证通过)"
                elif verification_result == "失败":
                    title += f" (验证失败)"
                else:
                    title += f" ({verification_result})"
                
            params = {
                'title': title,
                'desp': simple_message
            }
            
            # 构建完整推送URL
            url_template = config.get("notification_url", "https://sctapi.ftqq.com/{sckey}.send")
            push_url = url_template.replace("{sckey}", sckey)
            
            if not self.notification_url:
                # 如果没有配置通知URL，使用从配置中构建的推送URL
                self.notification_url = push_url
                logging.info(f"使用配置的推送URL模板: {push_url}")
            
            # 使用POST请求而不是GET，避免URL长度限制
            logging.info(f"发送通知到: {self.notification_url}")
            logging.info(f"通知内容: 标题={title}, 验证状态={verification_result}")
            
            response = requests.post(
                self.notification_url,
                data=params,
                timeout=10
            )
            
            logging.info(f"通知已发送，状态码: {response.status_code}")
            if response.status_code == 200:
                logging.info(f"推送成功！响应: {response.text[:100]}")
                return True
            else:
                logging.error(f"推送失败，状态码: {response.status_code}, 响应: {response.text[:100]}")
                return False
        except Exception as e:
            logging.error(f"发送通知失败: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
            return False
    
    def format_event_data(self, event_id: int, username: str, client_ip: str, 
                          event_time: str, raw_data: str) -> Dict[str, Any]:
        """格式化事件数据用于通知"""
        event_type = "未知事件"
        if event_id == 4624:
            event_type = "登录成功"
        elif event_id == 4625:
            event_type = "登录失败"
        elif event_id == 4634 or event_id == 4647:
            event_type = "用户注销"
        
        return {
            "event_type": event_type,
            "event_id": event_id,
            "username": username,
            "client_ip": client_ip if client_ip else "未知IP",
            "hostname": self.hostname,
            "local_ip": self.local_ip,
            "event_time": event_time,
            "raw_data": raw_data[:500]  # 限制长度
        }
    
    def process_event(self, event) -> None:
        """处理单个事件"""
        event_id = event.EventID
        
        # 创建唯一标识，避免重复处理
        record_id = f"{event_id}_{event.RecordNumber}"
        
        # 检查是否已处理该事件 - 用于防止重复处理
        if record_id in self.processed_events:
            logging.debug(f"事件已处理，跳过: {record_id}")
            return
        
        # 提取事件数据
        try:
            event_data = win32evtlogutil.SafeFormatMessage(event, self.logtype)
            if not event_data:
                logging.debug(f"事件 {record_id} 无数据")
                return
        except Exception as e:
            logging.error(f"提取事件数据失败: {e}")
            return
        
        # 检查是否为RDP登录相关事件
        if not self.is_rdp_logon(event_data, event_id):
            logging.debug(f"事件 {record_id} 不是RDP登录相关事件")
            return
        
        logging.info(f"检测到RDP相关事件: ID={event_id}, 记录号={event.RecordNumber}")
        logging.debug(f"事件数据: {event_data[:200]}...")  # 记录部分事件数据用于调试
            
        # 提取客户端IP
        client_ip = self.extract_client_ip(event_data)
        
        # 提取用户名 - 所有事件类型都需要
        username = self.extract_username(event_data)
        
        # 提取事件时间 - 所有事件类型都需要
        try:
            event_time = datetime.fromtimestamp(
                event.TimeGenerated.timestamp()
            ).strftime('%Y-%m-%d %H:%M:%S')
        except Exception as e:
            logging.error(f"时间戳转换失败: {e}")
            # 使用当前时间作为备选
            event_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # 创建通知数据基本对象 - 所有事件类型都使用
        notification_data = self.format_event_data(
            event_id, username, client_ip if client_ip else "未知IP", 
            event_time, event_data
        )
        
        # 加载全局配置
        config = load_config()
        
        # 检查是否是登录失败事件（4625），可能需要添加到黑名单
        if event_id == 4625 and client_ip:
            logging.info(f"检测到登录失败事件，IP: {client_ip}")
            
            # 如果IP不在白名单中，检查失败次数
            if not is_ip_in_whitelist(client_ip, config):
                allowed, attempt_count = check_allowed_failed_attempts(client_ip, config)
                
                # 如果达到最大失败次数限制，添加到黑名单
                max_failed = config.get("max_failed_attempts", 3)
                if attempt_count >= max_failed:
                    logging.warning(f"IP {client_ip} 已达到最大失败尝试次数({max_failed})，添加到黑名单")
                    add_ip_to_blacklist(client_ip)
                    
                    # 更新通知数据
                    notification_data["message"] = f"IP已添加到黑名单 - 失败尝试次数: {attempt_count}/{max_failed}"
                    notification_data["verification_result"] = "IP已拉黑"
                    notification_data["force_notification"] = True
                    
                    # 发送通知
                    self.send_notification(notification_data)
                    
                    # 断开连接
                    disconnect_rdp_sessions()
                    
                    # 记录事件
                    self.save_event_to_file(notification_data)
                    
                    # 标记事件已处理
                    self.processed_events.add(record_id)
                    return
        
        # 对于登录成功事件(4624)，需要特殊处理
        if event_id == 4624:
            logging.info(f"检测到RDP登录尝试 - 用户: {username}, IP: {client_ip if client_ip else '未知IP'}")
            
            # 标记是否已发送通知 - 默认未发送
            notification_sent = False
            
            # 如果IP为空，跳过后续处理
            if not client_ip:
                logging.warning("无法获取客户端IP，跳过验证")
                notification_data["verification_result"] = "无法获取IP"
                self.save_event_to_file(notification_data)
                self.processed_events.add(record_id)
                return
            
            # 首先检查IP是否在黑名单中
            if is_ip_in_blacklist(client_ip, config):
                logging.warning(f"IP {client_ip} 在黑名单中，执行断开连接")
                
                # 更新通知数据
                notification_data["verification_result"] = "黑名单拒绝"
                notification_data["event_type"] = "黑名单IP登录尝试"
                notification_data["message"] = "IP在黑名单中，自动断开连接"
                notification_data["force_notification"] = True
                
                # 记录事件到文件
                self.save_event_to_file(notification_data)
                
                # 发送通知
                self.send_notification(notification_data)
                
                # 断开连接
                disconnect_rdp_sessions()
                
                # 标记事件已处理
                self.processed_events.add(record_id)
                return
            
            # 检查IP是否在白名单中
            if is_ip_in_whitelist(client_ip, config):
                # 白名单内IP，跳过PIN验证，直接允许登录
                logging.info(f"IP {client_ip} 在白名单中，跳过PIN验证")
                
                # 更新通知数据
                notification_data["verification_result"] = "白名单免验证"
                notification_data["event_type"] = "登录成功(白名单)"
                notification_data["message"] = "IP在白名单中，无需PIN验证，自动允许登录"
                
                # 记录事件到文件
                self.save_event_to_file(notification_data)
                
                # 如果启用了强制通知，发送通知
                if notification_data.get("force_notification", False):
                    self.send_notification(notification_data)
                    notification_sent = True
                    logging.info(f"已发送白名单登录通知 - IP: {client_ip}")
                
                # 标记事件已处理
                self.processed_events.add(record_id)
                return
            
            # 检查是否需要PIN码验证 - 只有在配置了PIN码且IP不在白名单中时才验证
            if self.pin_code:
                # 检查是否在验证冷却期内（防止频繁验证）
                verification_history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verification_history.json")
                verification_history = {}
                current_time = datetime.now()
                
                # 读取验证历史记录
                if os.path.exists(verification_history_file):
                    try:
                        with open(verification_history_file, 'r', encoding='utf-8') as f:
                            verification_history = json.load(f)
                    except Exception as e:
                        logging.error(f"读取验证历史记录失败: {e}")
                
                # 清理过期的历史记录
                for ip in list(verification_history.keys()):
                    if ip in verification_history:
                        try:
                            record_time = datetime.fromisoformat(verification_history[ip]['time'])
                            # 检查是否已过期
                            cooldown = config.get("verification_cooldown", 60)  # 默认60秒
                            if (current_time - record_time).total_seconds() > cooldown:
                                del verification_history[ip]
                        except Exception as e:
                            logging.error(f"处理验证历史记录时出错: {e}")
                            # 出错时删除记录
                            del verification_history[ip]
                
                # 检查当前IP是否在冷却期内
                if client_ip in verification_history:
                    record = verification_history[client_ip]
                    record_time = datetime.fromisoformat(record['time'])
                    
                    # 为失败验证使用短冷却时间，成功验证使用正常冷却时间
                    if record.get('result') == 'failed' or record.get('use_short_cooldown', False):
                        # 失败验证的短冷却时间,默认5秒,避免频繁验证窗口弹出
                        cooldown = config.get("failed_verification_cooldown", 5)
                    else:
                        # 成功验证的正常冷却时间
                        cooldown = config.get("verification_cooldown", 60)  # 默认60秒
                    
                    # 如果在冷却期内，检查之前的验证结果
                    if (current_time - record_time).total_seconds() <= cooldown:
                        logging.info(f"IP {client_ip} 在验证冷却期内(冷却时间:{cooldown}秒)，验证结果: {record['result']}")
                        
                        # 修复漏洞：只有之前验证成功的才能复用验证结果
                        # 验证失败的必须重新验证
                        if record['result'] == 'success':
                            # 之前验证成功，直接放行
                            notification_data["verification_result"] = "成功(复用)"
                            notification_data["event_type"] = "登录验证成功(复用)"
                            notification_data["message"] = "使用之前的验证结果，允许登录"
                            
                            # 记录事件到文件
                            self.save_event_to_file(notification_data)
                            
                            # 标记事件已处理
                            self.processed_events.add(record_id)
                            return
                        else:
                            # 验证失败记录即使在冷却期内也不复用，仍然需要重新验证
                            # 但记录短时间内的验证失败，可以用于防止暴力破解
                            logging.info(f"IP {client_ip} 之前验证失败，忽略冷却期，必须重新验证")
                            # 清除之前的验证记录以强制重新验证
                            del verification_history[client_ip]
                
                # 默认验证结果为None，表示未验证
                verification_result = None
                
                # 显示PIN验证对话框并等待用户输入
                logging.info(f"弹出PIN码验证对话框，等待用户输入...")
                try:
                    # 限制验证超时时间
                    original_timeout = self.remaining_time if hasattr(self, 'remaining_time') else 10
                    # 从配置中读取PIN验证倒计时秒数
                    pin_countdown = config.get("pin_countdown_seconds", 10)
                    
                    pin_dialog = PinDialog(self.pin_code)
                    pin_dialog.remaining_time = pin_countdown  # 设置PIN验证倒计时秒数
                    
                    # PIN验证成功返回True，失败或超时返回False
                    if pin_dialog.show_dialog():
                        # PIN验证成功
                        logging.info("PIN码验证成功，允许继续登录")
                        verification_result = "成功"
                        
                        # 更新验证历史记录
                        verification_history[client_ip] = {
                            'result': 'success',
                            'time': current_time.isoformat()
                        }
                        
                        # 更新通知数据
                        notification_data["verification_result"] = "成功"
                        notification_data["event_type"] = "登录验证成功"
                        notification_data["message"] = "PIN码验证成功，允许继续登录"
                        
                        # 记录事件到文件
                        self.save_event_to_file(notification_data)
                        
                        # 发送通知 - 只对白名单外的IP发送
                        if not client_ip in ["127.0.0.1", "::1", self.local_ip]:
                            if not is_ip_in_whitelist(client_ip, config) or notification_data.get("force_notification", False):
                                # 发送成功验证通知
                                self.send_notification(notification_data)
                                notification_sent = True
                                logging.info(f"已发送验证成功通知 - IP: {client_ip}")
                    else:
                        # PIN验证失败，记录日志并断开连接
                        logging.warning(f"PIN码验证失败或超时，断开连接操作已在PinDialog中执行")
                        verification_result = "失败"
                        
                        # 更新验证历史记录 - 使用专门的失败验证冷却时间（比正常的验证冷却时间短）
                        verification_history[client_ip] = {
                            'result': 'failed',
                            'time': current_time.isoformat(),
                            # 添加冷却时间标志，指示这是失败验证，需使用短冷却时间
                            'use_short_cooldown': True
                        }
                        
                        # 断开连接操作
                        try:
                            logging.info("执行额外的断开连接操作")
                            
                            # 使用force_disconnect.bat脚本
                            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "force_disconnect.bat")
                            if os.path.exists(script_path):
                                logging.info(f"执行断开连接脚本: {script_path}")
                                startupinfo = subprocess.STARTUPINFO()
                                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                                startupinfo.wShowWindow = subprocess.SW_HIDE
                                
                                # 使用/silent参数执行批处理脚本，并等待完成
                                subprocess.run(
                                    [script_path, "/silent"],
                                    startupinfo=startupinfo,
                                    creationflags=subprocess.CREATE_NO_WINDOW,
                                    check=True
                                )
                                logging.info("断开连接脚本执行完成")
                            else:
                                logging.warning(f"断开连接脚本不存在: {script_path}")
                            
                            # 使用断开连接的基本函数
                            disconnect_rdp_sessions()
                        except Exception as e:
                            logging.error(f"执行断开连接操作失败: {e}")
                        
                        # 更新通知数据
                        notification_data["verification_result"] = "失败"
                        notification_data["event_type"] = "登录验证失败"
                        notification_data["message"] = "PIN码验证失败，已断开连接！"
                        notification_data["force_notification"] = True
                        
                        # 记录事件到文件
                        self.save_event_to_file(notification_data)
                        
                        # 发送验证失败通知 - 无论内外网IP，都发送通知
                        self.send_notification(notification_data)
                        notification_sent = True
                        logging.info(f"已发送验证失败通知 - IP: {client_ip if client_ip else '未知IP'}")
                except Exception as e:
                    # PIN验证过程出错
                    logging.error(f"PIN码验证过程发生错误: {e}")
                    import traceback
                    logging.error(f"详细错误: {traceback.format_exc()}")
                    verification_result = "错误"
                    
                    # 验证过程出错也断开连接
                    try:
                        logging.warning("PIN验证过程出错，执行断开连接")
                        disconnect_rdp_sessions()
                    except Exception as disconnect_error:
                        logging.error(f"断开连接失败: {disconnect_error}")
                    
                    # 更新通知数据
                    notification_data["verification_result"] = "错误"
                    notification_data["event_type"] = "登录验证错误"
                    notification_data["message"] = "PIN码验证过程出错，已断开连接"
                    notification_data["force_notification"] = True
                    
                    # 记录事件到文件
                    self.save_event_to_file(notification_data)
                    
                    # 发送通知
                    self.send_notification(notification_data)
                    notification_sent = True
                    logging.info(f"已发送验证错误通知 - IP: {client_ip if client_ip else '未知IP'}")
                
                # 保存验证历史记录
                try:
                    with open(verification_history_file, 'w', encoding='utf-8') as f:
                        json.dump(verification_history, f, indent=2)
                except Exception as e:
                    logging.error(f"保存验证历史记录失败: {e}")
            else:
                # 无需PIN验证 - 直接标记为无需验证
                notification_data["verification_result"] = "无需验证"
                
                # 记录事件到文件
                self.save_event_to_file(notification_data)
                
                # 如果通知尚未发送，且是外网IP，发送通知
                if not notification_sent and not client_ip in ["127.0.0.1", "::1", self.local_ip]:
                    if not self.is_private_ip(client_ip) or notification_data.get("force_notification", False):
                        self.send_notification(notification_data)
                        notification_sent = True
                        logging.info(f"已发送登录通知(无需验证) - IP: {client_ip}")
        else:
            # 处理非登录成功事件（如登录失败、注销等）
            # 添加验证状态，确保所有通知都包含此信息
            notification_data["verification_result"] = "不适用"
            
            # 记录事件到文件
            self.save_event_to_file(notification_data)
            
            # 只对外网IP发送通知
            if client_ip and not client_ip in ["127.0.0.1", "::1", self.local_ip]:
                if not self.is_private_ip(client_ip) or notification_data.get("force_notification", False):
                    # 发送通知 
                    self.send_notification(notification_data)
                    logging.info(f"已发送事件通知 - 类型: {notification_data['event_type']}, IP: {client_ip}")
        
        # 事件处理完成，标记为已处理
        self.processed_events.add(record_id)
        logging.debug(f"事件 {record_id} 处理完成")
    
    def save_event_to_file(self, event_data: Dict[str, Any]) -> None:
        """将事件保存到JSON文件"""
        try:
            # 使用绝对路径
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # 确保data目录存在
            data_dir = os.path.join(current_dir, 'data')
            if not os.path.exists(data_dir):
                os.makedirs(data_dir)
                logging.info(f"已创建数据目录: {data_dir}")
            
            filename = os.path.join(data_dir, "rdp_events.json")
            logging.info(f"尝试将事件保存到: {filename}")
            
            events = []
            
            # 读取现有事件（如果文件存在）
            if os.path.exists(filename):
                try:
                    with open(filename, 'r', encoding='utf-8') as f:
                        events = json.load(f)
                        logging.info(f"已读取现有事件文件，包含 {len(events)} 个事件")
                except Exception as read_error:
                    logging.error(f"读取现有事件文件失败: {read_error}")
            else:
                logging.info(f"事件文件不存在，将创建新文件")
            
            # 添加新事件
            events.append(event_data)
            logging.info(f"添加新事件: {event_data['event_type']} - 用户: {event_data['username']}")
            
            # 保存到文件
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(events, f, ensure_ascii=False, indent=2)
            logging.info(f"事件已成功保存到文件")
                
        except Exception as e:
            logging.error(f"保存事件到文件失败: {e}")
            # 打印详细错误信息
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
    
    def monitor(self) -> None:
        """开始监控安全日志"""
        logging.info(f"RDP监控服务已启动，监控主机: {self.hostname} ({self.local_ip})")
        logging.info(f"当前工作目录: {os.path.abspath('.')}")
        logging.info(f"脚本所在目录: {os.path.dirname(os.path.abspath(__file__))}")
        
        # 获取初始的事件处理位置
        try:
            h = win32evtlog.OpenEventLog(self.server, self.logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        except Exception as e:
            logging.error(f"无法打开事件日志，请确保程序以管理员权限运行: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
            print(f"错误: 无法访问安全日志。请以管理员权限运行程序。({e})")
            return
        
        try:
            # 记录启动信息到事件文件
            startup_info = {
                "event_type": "服务启动",
                "event_id": 0,
                "username": "system",
                "client_ip": "local",
                "hostname": self.hostname,
                "local_ip": self.local_ip,
                "event_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "raw_data": "RDP监控服务启动"
            }
            self.save_event_to_file(startup_info)
            
            # 初始化最新记录号，仅处理新事件
            latest_record_number = self._get_latest_record_number(h)
            logging.info(f"初始化最新记录号: {latest_record_number}，将忽略所有历史记录")
            
            while True:
                try:
                    events = win32evtlog.ReadEventLog(h, flags, 0)
                    if events:
                        logging.debug(f"读取到 {len(events)} 个事件")
                        for event in events:
                            # 只处理比启动时记录的记录号更新的事件
                            if event.RecordNumber > latest_record_number and event.EventID in self.rdp_event_ids:
                                logging.debug(f"处理新事件 ID: {event.EventID}, 记录号: {event.RecordNumber}")
                                self.process_event(event)
                            else:
                                logging.debug(f"跳过事件 ID: {event.EventID}, 记录号: {event.RecordNumber}")
                except Exception as e:
                    logging.error(f"读取事件日志时出错: {e}")
                    import traceback
                    logging.error(f"详细错误: {traceback.format_exc()}")
                    # 尝试重新打开事件日志
                    try:
                        win32evtlog.CloseEventLog(h)
                        h = win32evtlog.OpenEventLog(self.server, self.logtype)
                    except Exception as reopen_error:
                        logging.error(f"重新打开事件日志失败: {reopen_error}")
                        # 短暂休眠后再尝试
                        time.sleep(5)
                        continue
                
                # 短暂休眠，避免高CPU使用率
                time.sleep(1)
        except Exception as e:
            logging.error(f"监控过程中出错: {e}")
            # 打印详细错误信息
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
        finally:
            try:
                win32evtlog.CloseEventLog(h)
            except:
                pass
    
    def _get_latest_record_number(self, event_log_handle) -> int:
        """获取最新的事件记录号"""
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            events = win32evtlog.ReadEventLog(event_log_handle, flags, 0)
            if events and len(events) > 0:
                return events[0].RecordNumber
        except Exception as e:
            logging.error(f"获取最新记录号失败: {e}")
        return 0

def update_notification_url(url: str) -> bool:
    """更新通知URL"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(current_dir, 'config')
    config_file = os.path.join(config_dir, "config.json")
    
    # 读取现有配置
    config = load_config()
    
    if not url:
        # 如果URL为空，使用默认模板URL
        sckey = config.get("sckey", "")
        url_template = "https://sctapi.ftqq.com/{sckey}.send"
        if sckey:
            url = url_template.replace("{sckey}", sckey)
            logging.info(f"通知URL为空，使用默认URL模板: {url_template}")
        else:
            url = url_template  # 保留带占位符的模板
            logging.info(f"通知URL和SCKEY均为空，使用默认URL模板带占位符: {url}")
    
    # 更新配置
    config["notification_url"] = url
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logging.info(f"通知URL已更新为: {url}")
        return True
    except Exception as e:
        logging.error(f"更新通知URL失败: {e}")
        return False

def load_config() -> dict:
    """加载配置"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 确保config目录存在
    config_dir = os.path.join(current_dir, 'config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
        print(f"已创建配置目录: {config_dir}")
    
    config_file = os.path.join(config_dir, "config.json")
    example_file = os.path.join(config_dir, "config.json.example")
    
    # 首先检查配置文件是否存在
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                logging.info(f"已加载配置文件: {config_file}")
                return json.load(f)
        except Exception as e:
            logging.error(f"加载配置文件失败: {e}")
    
    # 如果配置文件不存在，检查是否有example文件
    if os.path.exists(example_file):
        try:
            # 从example文件复制创建配置文件
            with open(example_file, 'r', encoding='utf-8') as src:
                example_config = json.load(src)
                
            with open(config_file, 'w', encoding='utf-8') as dst:
                json.dump(example_config, dst, indent=2, ensure_ascii=False)
                
            logging.info(f"已从example文件创建配置文件: {config_file}")
            return example_config
        except Exception as e:
            logging.error(f"从example文件创建配置文件失败: {e}")
    else:
        # 如果example文件也不存在，创建一个基本的example文件和配置文件
        default_config = {
            "notification_url": "https://sctapi.ftqq.com/{sckey}.send",
            "sckey": "",  # 默认SCKEY
            "pin_code": "123456",  # 默认PIN码
            "rdp_port": 3389,    # 默认RDP端口
            "max_failed_attempts": 3,  # 黑名单触发的最大失败尝试次数
            "blacklist_cooldown": 24,  # 黑名单冷却时间(小时)
            "verification_timeout": 60,  # 验证超时时间(秒)，防止重复验证
            "verification_cooldown": 60, # 验证冷却时间(秒)，防止频繁验证
            "ip_blacklistfile": "data/ip_blacklist.txt",  # 黑名单文件路径
            "ip_whitelistfile": "data/ip_whitelist.txt",  # 白名单文件路径
            "log_retention_days": 7,  # 默认保留7天
            "pin_countdown_seconds": 10,  # PIN验证框倒计时秒数
            "ip_whitelist": "",  # IP白名单
            "auto_blacklist": True  # 自动黑名单
        }
        
        try:
            # 创建example文件
            with open(example_file, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            logging.info(f"已创建配置示例文件: {example_file}")
            
            # 创建配置文件
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2, ensure_ascii=False)
            logging.info(f"已创建默认配置文件: {config_file}")
        except Exception as e:
            logging.error(f"创建配置文件失败: {e}")
    
    # 返回默认配置，以确保程序能够继续运行
    return default_config

def update_sckey(sckey: str) -> bool:
    """更新Server酱SCKEY"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(current_dir, 'config')
    config_file = os.path.join(config_dir, "config.json")
    
    # 读取现有配置
    config = load_config()
    
    # 更新SCKEY
    config["sckey"] = sckey
    
    # 如果notification_url使用的是默认格式，也更新它
    current_url = config.get("notification_url", "")
    if current_url and "{sckey}" in current_url:
        config["notification_url"] = current_url  # 保留URL模板
        logging.info(f"保留URL模板: {current_url}")
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logging.info(f"SCKEY已更新")
        return True
    except Exception as e:
        logging.error(f"更新SCKEY失败: {e}")
        return False

def update_pin_code(pin_code: str) -> bool:
    """更新PIN码"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(current_dir, 'config')
    config_file = os.path.join(config_dir, "config.json")
    
    # 读取现有配置
    config = load_config()
    
    # 更新PIN码
    config["pin_code"] = pin_code
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logging.info(f"PIN码已更新")
        return True
    except Exception as e:
        logging.error(f"更新PIN码失败: {e}")
        return False

def disconnect_rdp_sessions():
    """断开所有远程桌面会话而不注销用户"""
    try:
        logging.info("尝试断开RDP会话")
        success = False
        
        # 创建隐藏窗口的启动信息
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        
        # 方法1: 使用Windows API断开会话
        try:
            logging.info("使用Windows API断开连接")
            import ctypes
            from ctypes import wintypes
            
            # 加载WTS API
            wtsapi32 = ctypes.WinDLL('wtsapi32.dll')
            
            # 定义常量
            WTS_CURRENT_SERVER_HANDLE = 0
            
            # 枚举所有会话
            ppSessionInfo = ctypes.POINTER(ctypes.c_void_p)()
            pCount = ctypes.c_int(0)
            
            # 定义WTSEnumerateSessions函数
            wtsapi32.WTSEnumerateSessionsW.argtypes = [
                wintypes.HANDLE,  # hServer
                wintypes.DWORD,   # Reserved
                wintypes.DWORD,   # Version
                ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)),  # ppSessionInfo
                ctypes.POINTER(ctypes.c_int)  # pCount
            ]
            wtsapi32.WTSEnumerateSessionsW.restype = wintypes.BOOL
            
            # 定义WTSDisconnectSession函数
            wtsapi32.WTSDisconnectSession.argtypes = [
                wintypes.HANDLE,  # hServer
                wintypes.DWORD,   # SessionId
                wintypes.BOOL     # bWait
            ]
            wtsapi32.WTSDisconnectSession.restype = wintypes.BOOL
            
            # 枚举会话
            res = wtsapi32.WTSEnumerateSessionsW(
                WTS_CURRENT_SERVER_HANDLE,
                0,
                1,
                ctypes.byref(ppSessionInfo),
                ctypes.byref(pCount)
            )
            
            if res:
                for i in range(pCount.value):
                    sessionId = ctypes.cast(ppSessionInfo.contents, ctypes.POINTER(wintypes.DWORD))[i]
                    try:
                        # 尝试断开会话
                        result = wtsapi32.WTSDisconnectSession(
                            WTS_CURRENT_SERVER_HANDLE,
                            sessionId,
                            True  # 等待断开完成
                        )
                        if result:
                            logging.info(f"成功使用API断开会话 {sessionId}")
                            success = True
                    except Exception as session_error:
                        logging.debug(f"无法断开会话 {sessionId}: {session_error}")
                
                # 释放会话信息内存
                wtsapi32.WTSFreeMemory(ppSessionInfo)
            
            # 如果上面的方法失败，尝试断开所有可能的会话ID
            if not success:
                for session_id in range(10):
                    try:
                        result = wtsapi32.WTSDisconnectSession(
                            WTS_CURRENT_SERVER_HANDLE,
                            session_id,
                            True
                        )
                        if result:
                            logging.info(f"成功使用API断开会话ID {session_id}")
                            success = True
                    except Exception as e:
                        logging.debug(f"无法断开会话ID {session_id}: {e}")
        except Exception as e:
            logging.error(f"使用Windows API断开连接失败: {e}")
        
        # 方法2: 使用qwinsta和rwinsta命令
        if not success:
            try:
                logging.info("使用qwinsta和rwinsta命令断开连接")
                # 获取所有会话
                qwinsta_output = subprocess.check_output(
                    ["qwinsta"],
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stderr=subprocess.STDOUT
                ).decode('gbk', errors='ignore')
                
                # 查找活动的RDP会话
                for line in qwinsta_output.splitlines():
                    if "rdp" in line.lower() or "active" in line.lower():
                        parts = line.split()
                        if len(parts) >= 2:
                            session_id = parts[1]
                            if session_id.isdigit():
                                # 使用rwinsta断开会话
                                result = subprocess.run(
                                    ["rwinsta", session_id],
                                    startupinfo=startupinfo,
                                    creationflags=subprocess.CREATE_NO_WINDOW,
                                    capture_output=True
                                )
                                logging.info(f"已使用rwinsta断开会话 {session_id}, 返回码: {result.returncode}")
                                if result.returncode == 0:
                                    success = True
                                    # 等待断开生效
                                    time.sleep(1)
            except Exception as e:
                logging.error(f"使用qwinsta和rwinsta命令断开连接失败: {e}")
        
        # 方法3: 使用wmic命令
        if not success:
            try:
                logging.info("使用wmic命令断开RDP会话")
                
                # 使用wmic查询并断开RDP会话
                wmic_cmd = "wmic path Win32_LogonSession Where \"LogonType=10\" Delete"
                result = subprocess.run(
                    wmic_cmd,
                    shell=True,
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    capture_output=True
                )
                logging.info(f"wmic命令执行结果: {result.returncode}")
                if result.returncode == 0:
                    success = True
                    time.sleep(1)
            except Exception as e:
                logging.error(f"使用wmic命令断开会话失败: {e}")
        
        # 方法4: 使用PowerShell断开连接
        if not success:
            try:
                logging.info("使用PowerShell断开连接")
                ps_commands = [
                    # 方法1: 使用Win32_TSLogonSession
                    """
                    $ErrorActionPreference = 'SilentlyContinue'
                    # 方法1: 使用Win32_TSLogonSession
                    $sessions = Get-WmiObject -Class Win32_TSLogonSession -Namespace root\\cimv2\\terminalservices
                    foreach ($session in $sessions) {
                        if ($session.State -eq 4) {  # 4表示活动状态
                            $sessionID = $session.SessionId
                            # 停止RDP剪贴板进程
                            Get-Process -Name rdpclip -ErrorAction SilentlyContinue | Stop-Process -Force
                            Start-Sleep -Milliseconds 500
                            # 断开会话
                            $session | Remove-WmiObject
                        }
                    }
                    """,
                    
                    # 方法2: 使用Win32_TerminalServiceSetting
                    """
                    $ErrorActionPreference = 'SilentlyContinue'
                    Get-WmiObject -Class Win32_TerminalServiceSetting -Namespace root\\cimv2\\terminalservices -ComputerName localhost -Authentication 6 | Invoke-WmiMethod -Name DisconnectSession
                    """,
                    
                    # 方法3: 使用CIM命令
                    """
                    $ErrorActionPreference = 'SilentlyContinue'
                    Get-CimInstance -ClassName Win32_Session | Where-Object {$_.LogonType -eq 10} | Remove-CimInstance
                    """
                ]
                
                for ps_command in ps_commands:
                    try:
                        result = subprocess.run(
                            ["powershell", "-WindowStyle", "Hidden", "-Command", ps_command],
                            startupinfo=startupinfo,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            capture_output=True,
                            timeout=15  # 添加超时限制
                        )
                        logging.info(f"PowerShell命令执行完成，返回码: {result.returncode}")
                        if result.returncode == 0:
                            success = True
                            # 等待命令生效
                            time.sleep(1)
                    except Exception as cmd_error:
                        logging.error(f"PowerShell命令执行失败: {cmd_error}")
            except Exception as e:
                logging.error(f"使用PowerShell断开连接失败: {e}")
        
        # 方法5: 使用tsdiscon和tscon命令
        if not success:
            try:
                logging.info("使用tsdiscon和tscon命令断开会话")
                
                # 获取所有会话
                sessions = subprocess.check_output(
                    ["query", "session"],
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stderr=subprocess.STDOUT
                ).decode('gbk', errors='ignore')
                
                active_sessions = []
                # 查找活动会话
                for line in sessions.splitlines():
                    if "Active" in line or "活动" in line:
                        parts = line.split()
                        if len(parts) >= 2:
                            session_id = parts[1]
                            active_sessions.append(session_id)
                
                # 如果找到活动会话
                if active_sessions:
                    for session_id in active_sessions:
                        # 先尝试tsdiscon
                        try:
                            result = subprocess.run(
                                ["tsdiscon", session_id, "/v"],
                                startupinfo=startupinfo,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                capture_output=True
                            )
                            logging.info(f"已执行tsdiscon {session_id}，返回码: {result.returncode}")
                            if result.returncode == 0:
                                success = True
                                # 等待断开生效
                                time.sleep(1)
                        except Exception as tsd_error:
                            logging.error(f"tsdiscon {session_id} 失败: {tsd_error}")
                            
                        # 如果tsdiscon失败，尝试tscon转移到控制台
                        if not success:
                            try:
                                result = subprocess.run(
                                    ["tscon", session_id, "/dest:console"],
                                    startupinfo=startupinfo,
                                    creationflags=subprocess.CREATE_NO_WINDOW,
                                    capture_output=True
                                )
                                logging.info(f"已执行tscon {session_id}，返回码: {result.returncode}")
                                if result.returncode == 0:
                                    success = True
                                    time.sleep(1)
                            except Exception as tsc_error:
                                logging.error(f"tscon {session_id} 失败: {tsc_error}")
                else:
                    # 如果未找到活动会话，尝试断开所有可能的会话ID
                    for session_id in range(5):  # 通常会话ID为0,1,2,3,4
                        try:
                            result = subprocess.run(
                                ["tsdiscon", str(session_id), "/v"],
                                startupinfo=startupinfo,
                                creationflags=subprocess.CREATE_NO_WINDOW,
                                capture_output=True
                            )
                            logging.info(f"已尝试tsdiscon会话ID {session_id}，返回码: {result.returncode}")
                        except Exception as e:
                            logging.debug(f"尝试断开会话ID {session_id} 失败: {e}")
                    
                    # 等待命令生效
                    time.sleep(1)
            except Exception as e:
                logging.error(f"使用tsdiscon/tscon命令失败: {e}")
        
        # 方法6: 结束远程桌面相关进程
        try:
            logging.info("尝试结束远程桌面相关进程")
            processes_to_kill = ["mstsc.exe", "rdpclip.exe", "rdpshell.exe", "rdpinit.exe"]
            
            for process in processes_to_kill:
                try:
                    result = subprocess.run(
                        ["taskkill", "/f", "/im", process],
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        capture_output=True
                    )
                    logging.info(f"已尝试终止进程 {process}，返回码: {result.returncode}")
                except Exception as proc_error:
                    logging.debug(f"终止进程 {process} 失败: {proc_error}")
            
            # 等待进程结束
            time.sleep(1)
        except Exception as e:
            logging.error(f"终止远程桌面相关进程失败: {e}")
        
        # 方法7: 如果所有方法都失败，尝试重启终端服务
        if not success:
            try:
                logging.warning("常规断开方法失败，尝试重启终端服务")
                
                # 停止终端服务相关进程
                services_to_restart = [
                    ("net stop UmRdpService /y", 10),  # 服务名, 超时秒数
                    ("net stop TermService /y", 10),
                    ("sc stop UmRdpService", 5),
                    ("sc stop TermService", 5)
                ]
                
                for cmd, timeout in services_to_restart:
                    try:
                        result = subprocess.run(
                            cmd,
                            shell=True,
                            startupinfo=startupinfo,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            capture_output=True,
                            timeout=timeout
                        )
                        logging.info(f"执行命令: {cmd}，返回码: {result.returncode}")
                    except subprocess.TimeoutExpired:
                        logging.warning(f"命令 {cmd} 执行超时")
                    except Exception as cmd_error:
                        logging.error(f"执行命令 {cmd} 失败: {cmd_error}")
                
                # 等待服务完全停止
                time.sleep(2)
                
                # 启动终端服务
                start_services = [
                    "net start TermService",
                    "net start UmRdpService",
                    "sc start TermService",
                    "sc start UmRdpService"
                ]
                
                for cmd in start_services:
                    try:
                        result = subprocess.run(
                            cmd,
                            shell=True,
                            startupinfo=startupinfo,
                            creationflags=subprocess.CREATE_NO_WINDOW,
                            capture_output=True,
                            timeout=10
                        )
                        logging.info(f"执行命令: {cmd}，返回码: {result.returncode}")
                    except Exception as start_error:
                        logging.error(f"执行命令 {cmd} 失败: {start_error}")
                
                logging.info("已完成终端服务重启")
                success = True
            except Exception as e:
                logging.error(f"重启终端服务失败: {e}")
        
        # 关键修复：在断开连接后，清空验证历史记录文件，确保下次连接必须重新验证
        try:
            verification_history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verification_history.json")
            if os.path.exists(verification_history_file):
                with open(verification_history_file, 'w', encoding='utf-8') as f:
                    json.dump({}, f)
                logging.info("断开连接：已清空验证历史记录，确保下次连接重新验证")
        except Exception as e:
            logging.error(f"断开连接时清理验证历史记录失败: {e}")
        
        # 同时清空RDP事件记录文件
        clear_rdp_events_file()
        
        return success
    except Exception as e:
        logging.error(f"断开RDP连接失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return False

class PinDialog:
    def __init__(self, correct_pin: str):
        """初始化PIN码验证对话框"""
        # 如果传入了correct_pin，则使用它，否则从配置文件读取
        config = load_config()
        self.correct_pin = correct_pin if correct_pin else config.get("pin_code", "123456")
        self.result = False
        # 从配置文件读取PIN验证倒计时秒数，如果没有则使用默认值10秒
        config = load_config()
        self.remaining_time = config.get("pin_countdown_seconds", 10)
        self.dialog = None
        self.countdown_label = None
        self.pin_entry = None
        self.countdown_running = False
        # 记录验证时间，用于防止重复验证
        self.verification_time = datetime.now()
        # 最大验证尝试次数设为1（无容错）
        self.max_attempts = 1
        self.attempt_count = 0
        
    def show_dialog(self) -> bool:
        """显示PIN码验证对话框"""
        try:
            # 创建主窗口
            self.dialog = tk.Tk()
            self.dialog.title("RDP登录安全验证")
            
            # 设置窗口属性
            self.dialog.attributes('-topmost', True)  # 置顶
            self.dialog.attributes('-fullscreen', False)  # 非全屏
            self.dialog.resizable(False, False)  # 禁止调整大小
            self.dialog.protocol("WM_DELETE_WINDOW", self.disconnect)  # 点击关闭按钮时断开连接
            self.dialog.overrideredirect(True)  # 去掉标题栏和边框
            
            # 设置窗口大小和位置
            window_width = 400
            window_height = 350
            screen_width = self.dialog.winfo_screenwidth()
            screen_height = self.dialog.winfo_screenheight()
            x = (screen_width // 2) - (window_width // 2)
            y = (screen_height // 2) - (window_height // 2)
            self.dialog.geometry(f"{window_width}x{window_height}+{x}+{y}")
            
            # 设置窗口整体背景颜色为透明
            self.dialog.configure(bg='#F0F0F0')
            self.dialog.wm_attributes('-transparentcolor', '#F0F0F0')
            
            # 主内容框尺寸
            content_width = window_width - 20
            content_height = window_height - 20
            
            # 创建带圆角和阴影效果的主框架背景 - 使用渐变色阴影
            # 创建多层阴影效果，从外到内逐渐变淡
            shadow_colors = ['#555555', '#666666', '#777777', '#888888', '#999999']
            shadow_frames = []
            for i, color in enumerate(shadow_colors):
                offset = 5 - i
                shadow_frame = tk.Frame(
                    self.dialog, 
                    bg=color, 
                    bd=0, 
                    highlightthickness=0
                )
                shadow_frame.place(
                    x=(window_width - content_width) // 2 + offset,
                    y=(window_height - content_height) // 2 + offset,
                    width=content_width,
                    height=content_height
                )
                shadow_frames.append(shadow_frame)
            
            # 创建主内容框 - 纯白背景，带圆角
            radius = 15  # 增大圆角半径
            main_frame = tk.Frame(
                self.dialog, 
                bg='white', 
                bd=0, 
                highlightthickness=0
            )
            main_frame.place(
                x=(window_width - content_width) // 2,
                y=(window_height - content_height) // 2,
                width=content_width,
                height=content_height
            )
            
            # 创建红色顶部横幅 - 完全填充顶部，不带圆角
            header_height = 60
            header_frame = tk.Frame(
                main_frame, 
                bg='#E53935', 
                bd=0, 
                highlightthickness=0
            )
            header_frame.place(
                x=0, 
                y=0, 
                width=content_width, 
                height=header_height
            )
            
            # 移除左上和右上圆角遮罩，使顶部保持直角
            
            # 只创建底部的左下和右下圆角遮罩
            bottom_left_corner = tk.Canvas(
                main_frame, 
                width=radius, 
                height=radius, 
                bg='white',
                bd=0, 
                highlightthickness=0
            )
            bottom_left_corner.place(x=0, y=content_height-radius)
            bottom_left_corner.create_arc(
                0, -radius, 2*radius, radius, 
                start=180, extent=90, 
                fill='white', outline='white'
            )
            
            bottom_right_corner = tk.Canvas(
                main_frame, 
                width=radius, 
                height=radius, 
                bg='white',
                bd=0, 
                highlightthickness=0
            )
            bottom_right_corner.place(x=content_width-radius, y=content_height-radius)
            bottom_right_corner.create_arc(
                -radius, -radius, radius, radius, 
                start=270, extent=90, 
                fill='white', outline='white'
            )
            
            # 创建锁图标 - 使用Unicode字符
            lock_label = tk.Label(
                header_frame,
                text="🔒",  # Unicode锁图标
                font=("Segoe UI Symbol", 24),
                bg='#E53935',
                fg='white'
            )
            lock_label.pack(side=tk.LEFT, padx=(20, 0), pady=10)
            
            # 标题标签 - 使用更美观的字体
            title_label = tk.Label(
                header_frame,
                text="RDP登录安全验证",
                font=("Microsoft YaHei UI", 16, "bold"),
                bg='#E53935',
                fg='white'
            )
            title_label.pack(side=tk.LEFT, padx=(10, 0), pady=10)
            
            # 内容区域
            content_frame = tk.Frame(main_frame, bg='white', bd=0, highlightthickness=0)
            content_frame.place(x=0, y=header_height, width=content_width, height=content_height-header_height)
            
            # 提示标签 - 使用更美观的字体和更好的字体平滑效果
            hint_label = tk.Label(
                content_frame,
                text="请输入安全PIN码以继续登录\n验证失败将立即断开连接",
                font=("Microsoft YaHei UI", 12),
                bg='white',
                fg='#424242',
                justify=tk.CENTER
            )
            hint_label.pack(pady=(25, 20))
            
            # PIN码输入框容器
            entry_frame = tk.Frame(content_frame, bg='white')
            entry_frame.pack(pady=(0, 5))
            
            # PIN码图标
            pin_icon_label = tk.Label(
                entry_frame,
                text="🔑",  # Unicode钥匙图标
                font=("Segoe UI Symbol", 18),
                bg='white',
                fg='#757575'
            )
            pin_icon_label.pack(side=tk.LEFT, padx=(0, 5))
            
            # PIN码输入框 - 改进样式
            self.pin_entry = tk.Entry(
                entry_frame,
                show="●",  # 使用圆点替代星号，更现代
                font=("Microsoft YaHei UI", 14),
                width=15,
                bd=1,
                relief='solid',
                justify=tk.CENTER
            )
            self.pin_entry.pack(side=tk.LEFT)
            self.pin_entry.focus()
            
            # 底部分割线
            separator = tk.Frame(entry_frame, height=2, bg='#E0E0E0')
            separator.pack(fill=tk.X, pady=(5, 0))
            
            # 倒计时标签 - 使用红色突出显示
            self.countdown_label = tk.Label(
                content_frame,
                text=f"剩余时间: {self.remaining_time}秒",
                font=("Microsoft YaHei UI", 10, "bold"),
                bg='white',
                fg='#E53935'
            )
            self.countdown_label.pack(pady=(15, 20))
            
            # 按钮框架
            button_frame = tk.Frame(content_frame, bg='white')
            button_frame.pack(pady=(0, 20))
            
            # 创建自定义圆角按钮函数
            def create_rounded_button(parent, text, command, bg_color, active_bg_color):
                button_height = 36  # 增加按钮高度
                button_width = 120
                
                # 创建按钮容器框架
                btn_container = tk.Frame(parent, bg='white', bd=0, highlightthickness=0)
                
                # 创建按钮
                btn = tk.Canvas(
                    btn_container,
                    width=button_width,
                    height=button_height,
                    bg=bg_color,
                    bd=0,
                    highlightthickness=0
                )
                btn.pack()
                
                # 绘制圆角矩形
                btn_radius = 6
                btn.create_rectangle(
                    btn_radius, 0,
                    button_width - btn_radius, button_height,
                    fill=bg_color, outline=bg_color
                )
                btn.create_rectangle(
                    0, btn_radius,
                    button_width, button_height - btn_radius,
                    fill=bg_color, outline=bg_color
                )
                
                # 绘制四个圆角
                btn.create_arc(
                    0, 0, btn_radius*2, btn_radius*2,
                    start=90, extent=90, fill=bg_color, outline=bg_color
                )
                btn.create_arc(
                    button_width - btn_radius*2, 0, button_width, btn_radius*2,
                    start=0, extent=90, fill=bg_color, outline=bg_color
                )
                btn.create_arc(
                    0, button_height - btn_radius*2, btn_radius*2, button_height,
                    start=180, extent=90, fill=bg_color, outline=bg_color
                )
                btn.create_arc(
                    button_width - btn_radius*2, button_height - btn_radius*2, button_width, button_height,
                    start=270, extent=90, fill=bg_color, outline=bg_color
                )
                
                # 添加文本
                text_id = btn.create_text(
                    button_width // 2,
                    button_height // 2,
                    text=text,
                    fill='white',
                    font=('Microsoft YaHei UI', 11, 'bold')
                )
                
                # 点击事件处理
                def on_click(event):
                    command()
                
                # 鼠标悬停效果
                def on_enter(event):
                    btn.config(bg=active_bg_color)
                    btn.itemconfig('all', fill=active_bg_color)
                    btn.itemconfig(text_id, fill='white')
                
                def on_leave(event):
                    btn.config(bg=bg_color)
                    btn.itemconfig('all', fill=bg_color)
                    btn.itemconfig(text_id, fill='white')
                
                btn.bind('<Button-1>', on_click)
                btn.bind('<Enter>', on_enter)
                btn.bind('<Leave>', on_leave)
                
                return btn_container
            
            # 创建确认按钮
            confirm_button = create_rounded_button(
                button_frame,
                "确认",
                self.verify_pin,
                '#4CAF50',  # 绿色
                '#388E3C'   # 深绿色
            )
            confirm_button.pack(side=tk.LEFT, padx=10)
            
            # 创建断开按钮
            disconnect_button = create_rounded_button(
                button_frame,
                "断开",
                self.disconnect,
                '#E53935',  # 红色
                '#C62828'   # 深红色
            )
            disconnect_button.pack(side=tk.LEFT, padx=10)
            
            # 底部状态信息
            status_label = tk.Label(
                content_frame,
                text="安全验证 | 防止未授权访问",
                font=("Microsoft YaHei UI", 8),
                bg='white',
                fg='#9E9E9E'
            )
            status_label.pack(side=tk.BOTTOM, pady=10)
            
            # 支持拖动窗口
            self.dialog.bind("<ButtonPress-1>", self._start_drag)
            self.dialog.bind("<ButtonRelease-1>", self._stop_drag)
            self.dialog.bind("<B1-Motion>", self._on_drag)
            
            # 绑定回车键
            self.pin_entry.bind('<Return>', lambda e: self.verify_pin())
            
            # 开始倒计时
            self.countdown_running = True
            self.update_countdown()
            
            # 运行对话框
            self.dialog.mainloop()
            
            return self.result
            
        except Exception as e:
            logging.error(f"显示PIN码验证对话框时发生错误: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
            return False
        finally:
            if self.dialog:
                try:
                    self.dialog.destroy()
                except:
                    pass
                    
    def _start_drag(self, event):
        """开始拖动窗口"""
        self._drag_data = {"x": event.x, "y": event.y}
    
    def _stop_drag(self, event):
        """停止拖动窗口"""
        self._drag_data = None
    
    def _on_drag(self, event):
        """拖动窗口时执行"""
        if self._drag_data:
            x = self.dialog.winfo_x() + (event.x - self._drag_data["x"])
            y = self.dialog.winfo_y() + (event.y - self._drag_data["y"])
            self.dialog.geometry(f"+{x}+{y}")
    
    def update_countdown(self):
        """更新倒计时"""
        if not self.countdown_running:
            return
            
        if self.remaining_time > 0:
            self.remaining_time -= 1
            self.countdown_label.config(text=f"剩余时间: {self.remaining_time}秒")
            self.dialog.after(1000, self.update_countdown)
        else:
            self.disconnect()
    
    def verify_pin(self):
        """验证PIN码"""
        self.attempt_count += 1
        entered_pin = self.pin_entry.get().strip()
        if entered_pin == self.correct_pin:
            self.result = True
            self.countdown_running = False
            self.dialog.quit()
        else:
            # PIN码错误显示错误信息
            self.pin_entry.delete(0, tk.END)
            self.pin_entry.config(bg="#FFCCCC")
            
            # 立即写入验证失败结果
            try:
                logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
                result_file = os.path.join(logs_dir, 'pin_verification_result.txt')
                with open(result_file, 'w') as f:
                    f.write("失败")  # PIN码验证失败
                    # 确保文件写入完成
                    os.fsync(f.fileno())
                logging.info("已写入PIN验证结果：验证失败")
                
                # 关键修复：清空验证历史记录，确保下次一定重新验证
                verification_history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verification_history.json")
                if os.path.exists(verification_history_file):
                    try:
                        # 清空验证历史内容
                        with open(verification_history_file, 'w', encoding='utf-8') as f:
                            json.dump({}, f)
                        logging.info("验证失败：已清空验证历史记录，确保下次连接重新验证")
                    except Exception as e:
                        logging.error(f"清理验证历史记录失败: {e}")
                
                # 清空RDP事件记录文件
                clear_rdp_events_file()
            except Exception as e:
                logging.error(f"写入验证结果失败: {e}")
                import traceback
                logging.error(f"详细错误: {traceback.format_exc()}")
            
            # PIN码错误直接断开连接
            self.countdown_label.config(text="PIN码错误，即将断开连接...", fg="#FF0000", font=("Microsoft YaHei UI", 10, "bold"))
            # 1秒后断开连接
            self.dialog.after(1000, self.disconnect)
    
    def disconnect(self):
        """断开连接"""
        self.result = False
        self.countdown_running = False
        
        # 立即将验证结果写入文件，确保rdp_trigger.py能读取到
        try:
            logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            result_file = os.path.join(logs_dir, 'pin_verification_result.txt')
            # 区分用户点击断开和PIN验证失败的情况
            with open(result_file, 'w') as f:
                f.write("断开")  # 用户主动断开的结果
            logging.info("已写入PIN验证结果：用户主动断开")
            
            # 确保文件写入完成
            os.fsync(f.fileno())
            
            # 关键修复：强制删除验证历史记录文件，确保下次连接一定会重新验证
            verification_history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verification_history.json")
            if os.path.exists(verification_history_file):
                try:
                    # 清空验证历史内容但保留文件
                    with open(verification_history_file, 'w', encoding='utf-8') as f:
                        json.dump({}, f)
                    logging.info("已清空验证历史记录，确保下次连接重新验证")
                except Exception as e:
                    logging.error(f"清理验证历史记录失败: {e}")
            
            # 同时清空RDP事件记录文件
            clear_rdp_events_file()
        except Exception as e:
            logging.error(f"写入验证结果失败: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
        
        # 不要在此处关闭窗口，先完成文件写入和日志记录
        try:
            # 在退出前先确保结果已写入并可以被读取
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    content = f.read().strip()
                logging.info(f"确认结果文件已写入: {content}")
        except Exception as e:
            logging.error(f"确认结果文件失败: {e}")
        
        # 确保将此IP的验证失败记录到验证历史中
        try:
            # 获取客户端IP
            client_ip = None
            try:
                # 尝试使用rdp_trigger.py中的方法获取IP
                import subprocess
                import re
                
                # 读取RDP端口配置
                config = load_config()
                rdp_port = config.get("rdp_port", 3389)
                
                # 读取message.log文件获取连接信息
                logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
                message_file = os.path.join(logs_dir, 'message.log')
                
                if os.path.exists(message_file):
                    # 尝试以不同编码读取文件
                    encodings = ['utf-8', 'gbk', 'gb2312', 'ansi']
                    content = None
                    
                    for encoding in encodings:
                        try:
                            with open(message_file, 'r', encoding=encoding) as f:
                                content = f.read()
                                logging.debug(f"成功使用 {encoding} 编码读取message.log")
                                break
                        except UnicodeDecodeError:
                            continue
                    
                    if content is None:
                        # 如果所有编码都失败，尝试二进制读取
                        with open(message_file, 'rb') as f:
                            content = f.read().decode('utf-8', errors='ignore')
                    
                    # 使用多种模式提取IP地址
                    ip_patterns = [
                        fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):{rdp_port}',  # IP:port
                        fr'TCP\s+\S+:{rdp_port}\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+',  # TCP *:port IP:port
                        fr'TCP\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+\s+\S+:{rdp_port}'   # TCP IP:port *:port
                    ]
                    
                    all_ips = []
                    for pattern in ip_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            # 确保我们获取的是IP地址字符串
                            for match in matches:
                                if isinstance(match, tuple):
                                    all_ips.append(match[0])  # 取正则表达式捕获组的第一个
                                else:
                                    all_ips.append(match)
                    
                    # 去重
                    all_ips = list(dict.fromkeys(all_ips))
                    
                    # 过滤本地IP
                    local_ip = socket.gethostbyname(socket.gethostname())
                    filtered_ips = [ip for ip in all_ips if not (ip.startswith('127.') or 
                                                               ip.startswith('0.') or 
                                                               ip == local_ip or 
                                                               ip == "0.0.0.0" or 
                                                               ip == "255.255.255.255")]
                    
                    logging.debug(f"找到的所有RDP连接IP: {all_ips}")
                    logging.debug(f"过滤后的IP: {filtered_ips}")
                    
                    # 如果找到了有效IP，使用第一个
                    if filtered_ips:
                        client_ip = filtered_ips[0]
                        logging.info(f"从message.log找到客户端IP: {client_ip}")
                else:
                    logging.warning(f"message.log文件不存在，尝试其他方法获取IP")
                
                # 如果从message.log没找到IP，尝试使用netstat
                if not client_ip:
                    # 使用netstat获取所有活动连接
                    netstat_cmd = f"netstat -n | findstr ESTABLISHED | findstr :{rdp_port}"
                    netstat_output = subprocess.check_output(netstat_cmd, shell=True).decode('utf-8', errors='ignore')
                    
                    # 从netstat输出提取IP
                    ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', netstat_output)
                    filtered_netstat_ips = [ip for ip in ip_matches if not (ip.startswith('127.') or 
                                                                        ip.startswith('0.') or 
                                                                        ip == local_ip)]
                    
                    if filtered_netstat_ips:
                        client_ip = filtered_netstat_ips[0]
                        logging.info(f"从netstat找到客户端IP: {client_ip}")
                
                # 检查rtm_trigger.log中的IP记录作为最后的备选方案
                if not client_ip:
                    trigger_log = os.path.join(logs_dir, 'rdp_trigger.log')
                    if os.path.exists(trigger_log):
                        try:
                            with open(trigger_log, 'r', encoding='utf-8', errors='ignore') as f:
                                log_content = f.read()
                                # 查找"检测到RDP连接: IP="后面的IP地址
                                ip_match = re.search(r'检测到RDP连接: IP=(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})', log_content)
                                if ip_match:
                                    client_ip = ip_match.group(1)
                                    logging.info(f"从rdp_trigger.log找到客户端IP: {client_ip}")
                        except Exception as e:
                            logging.error(f"读取rdp_trigger.log失败: {e}")
            except Exception as e:
                logging.error(f"获取客户端IP失败: {e}")
                import traceback
                logging.error(f"获取IP详细错误: {traceback.format_exc()}")
            
            # 如果找到了客户端IP，将其添加到验证历史中和失败尝试中
            if client_ip:
                # 读取验证历史记录
                verification_history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verification_history.json")
                verification_history = {}
                
                if os.path.exists(verification_history_file):
                    try:
                        with open(verification_history_file, 'r', encoding='utf-8') as f:
                            verification_history = json.load(f)
                    except Exception as e:
                        logging.error(f"读取验证历史记录失败: {e}")
                
                # 记录验证失败原因（区分倒计时超时和用户主动断开）
                disconnect_reason = 'timeout' if self.remaining_time <= 0 else 'user_disconnect'
                
                # 添加验证失败记录
                verification_history[client_ip] = {
                    'result': 'failed',
                    'time': datetime.now().isoformat(),
                    'reason': disconnect_reason,
                    # 添加冷却时间标志，指示这是失败验证，需使用短冷却时间
                    'use_short_cooldown': True
                }
                
                # 保存验证历史记录
                try:
                    with open(verification_history_file, 'w', encoding='utf-8') as f:
                        json.dump(verification_history, f, indent=2)
                    logging.info(f"IP {client_ip} 验证失败记录已保存，原因: {disconnect_reason}")
                except Exception as e:
                    logging.error(f"保存验证历史记录失败: {e}")
                    
                # 记录PIN验证失败到失败尝试记录中，以便黑名单检查
                try:
                    config = load_config()
                    allowed, attempt_count = check_allowed_failed_attempts(client_ip, config)
                    
                    # 如果达到失败次数限制，添加到黑名单
                    max_failed = config.get("max_failed_attempts", 3)
                    if attempt_count >= max_failed:
                        logging.warning(f"PIN验证: IP {client_ip} 已达到最大失败尝试次数({max_failed})，添加到黑名单")
                        add_ip_to_blacklist(client_ip)
                        
                        # 记录黑名单添加日志
                        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "blacklist.log"), 'a', encoding='utf-8') as f:
                            f.write(f"{datetime.now().isoformat()} - IP {client_ip} 已添加到黑名单，失败尝试次数: {attempt_count}/{max_failed}\n")
                            
                    # 发送倒计时超时验证失败通知
                    try:
                        if disconnect_reason == 'timeout':
                            # 获取配置信息用于发送通知
                            notification_url = config.get("notification_url", "")
                            
                            # 使用Server酱SCKEY替换URL中的占位符，如果有
                            sckey = config.get("sckey", "")
                            if "{sckey}" in notification_url and sckey:
                                notification_url = notification_url.replace("{sckey}", sckey)
                            
                            # 构建通知数据
                            notification_data = {
                                "event_type": "登录验证超时",
                                "event_id": 0,
                                "username": "未知用户",
                                "client_ip": client_ip,
                                "hostname": socket.gethostname(),
                                "local_ip": socket.gethostbyname(socket.gethostname()),
                                "event_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                "verification_result": "验证超时",
                                "message": "PIN码验证超时，已自动断开连接",
                                "force_notification": True  # 强制发送通知，无论IP是否在白名单
                            }
                            
                            # 创建RDPMonitor实例来发送通知
                            rdp_monitor = RDPMonitor(notification_url, sckey, "")
                            
                            # 发送通知
                            rdp_monitor.send_notification(notification_data)
                            logging.info(f"IP {client_ip} 验证超时通知已发送")
                            
                            # 保存事件到事件记录文件
                            try:
                                rdp_monitor.save_event_to_file(notification_data)
                                logging.info(f"IP {client_ip} 验证超时事件已保存到记录文件")
                            except Exception as save_error:
                                logging.error(f"保存验证超时事件到文件失败: {save_error}")
                    except Exception as e:
                        logging.error(f"发送验证超时通知失败: {e}")
                        import traceback
                        logging.error(f"通知错误详情: {traceback.format_exc()}")
                except Exception as e:
                    logging.error(f"记录PIN验证失败到failed_attempts.json失败: {e}")
        except Exception as e:
            logging.error(f"处理验证历史记录时出错: {e}")
        
        # 显示断开连接中的提示
        try:
            # 创建断开连接提示窗口
            if self.dialog:
                for widget in self.dialog.winfo_children():
                    widget.destroy()
                
                # 设置背景
                self.dialog.configure(bg='#F0F0F0')
                
                # 窗口大小
                window_width = 400
                window_height = 300
                
                # 创建阴影效果 - 在主框架下方创建一个偏移的深色框架
                shadow_frame = tk.Frame(self.dialog, bg='#888888', bd=0, highlightthickness=0)
                shadow_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=window_width-30, height=window_height-30, x=5, y=5)
                
                # 创建主框架，使用圆角效果
                main_frame = tk.Frame(self.dialog, bg='white', bd=0, highlightthickness=0)
                main_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=window_width-40, height=window_height-40)
                
                # 创建一个圆角主内容框
                content_width = window_width - 50
                content_height = window_height - 50
                
                # 绘制顶部红色横幅（带圆角）
                header_frame = tk.Frame(main_frame, bg='#E53935', height=60)
                header_frame.place(x=5, y=5, width=content_width-10, height=60)
                
                # 左上圆角
                radius = 10
                top_left_corner = tk.Canvas(main_frame, width=radius, height=radius, bg='white', 
                                          highlightthickness=0)
                top_left_corner.place(x=5, y=5)
                top_left_corner.create_arc(0, 0, 2*radius, 2*radius, start=90, extent=90, fill='#E53935', outline='#E53935')
                
                # 右上圆角
                top_right_corner = tk.Canvas(main_frame, width=radius, height=radius, bg='white', 
                                           highlightthickness=0)
                top_right_corner.place(x=content_width-radius, y=5)
                top_right_corner.create_arc(-radius, 0, radius, 2*radius, start=0, extent=90, fill='#E53935', outline='#E53935')
                
                # 创建警告图标
                warning_label = tk.Label(
                    header_frame,
                    text="⚠️",  # Unicode警告图标
                    font=("Segoe UI Symbol", 24),
                    bg='#E53935',
                    fg='white'
                )
                warning_label.pack(side=tk.LEFT, padx=(20, 0), pady=10)
                
                # 标题标签
                title_label = tk.Label(
                    header_frame,
                    text="正在断开连接",
                    font=("Microsoft YaHei UI", 16, "bold"),
                    bg='#E53935',
                    fg='white'
                )
                title_label.pack(side=tk.LEFT, padx=(10, 0), pady=10)
                
                # 内容区域（带圆角）
                content_frame = tk.Frame(main_frame, bg='white')
                content_frame.place(x=5, y=65, width=content_width-10, height=content_height-70)
                
                # 添加左下和右下圆角
                bottom_left_corner = tk.Canvas(main_frame, width=radius, height=radius, bg='white', 
                                             highlightthickness=0)
                bottom_left_corner.place(x=5, y=content_height-radius)
                bottom_left_corner.create_arc(0, -radius, 2*radius, radius, start=180, extent=90, fill='white', outline='white')
                
                bottom_right_corner = tk.Canvas(main_frame, width=radius, height=radius, bg='white', 
                                              highlightthickness=0)
                bottom_right_corner.place(x=content_width-radius, y=content_height-radius)
                bottom_right_corner.create_arc(-radius, -radius, radius, radius, start=270, extent=90, fill='white', outline='white')
                
                # 断开连接提示
                disconnect_label = tk.Label(
                    content_frame,
                    text="安全验证失败\n正在终止远程桌面连接",
                    font=("Microsoft YaHei UI", 12, "bold"),
                    bg='white',
                    fg='#E53935',
                    justify=tk.CENTER
                )
                disconnect_label.pack(pady=(40, 20))
                
                # 添加进度指示器
                progress_frame = tk.Frame(content_frame, bg='white')
                progress_frame.pack(pady=10)
                
                progress_var = tk.DoubleVar()
                progress_bar = ttk.Progressbar(
                    progress_frame,
                    variable=progress_var,
                    maximum=100,
                    mode='indeterminate',
                    length=300
                )
                progress_bar.pack()
                progress_bar.start(10)
                
                # 底部状态信息
                status_label = tk.Label(
                    content_frame,
                    text="安全保护 | 正在执行断开操作",
                    font=("Microsoft YaHei UI", 8),
                    bg='white',
                    fg='#9E9E9E'
                )
                status_label.pack(side=tk.BOTTOM, pady=15)
                
                # 支持拖动窗口
                self.dialog.bind("<ButtonPress-1>", self._start_drag)
                self.dialog.bind("<ButtonRelease-1>", self._stop_drag)
                self.dialog.bind("<B1-Motion>", self._on_drag)
                
                # 更新界面
                self.dialog.update()
                
                # 在后台线程中执行断开连接操作
                threading.Thread(target=self._execute_disconnect, daemon=True).start()
                
                # 2秒后关闭对话框
                self.dialog.after(2000, self.dialog.quit)
        except Exception as e:
            logging.error(f"显示断开连接提示时发生错误: {e}")
    
    def _execute_disconnect(self):
        """执行断开连接操作"""
        try:
            logging.info("PIN验证失败，执行断开连接操作")
            
            # 先尝试使用force_disconnect.bat脚本
            script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "force_disconnect.bat")
            if os.path.exists(script_path):
                logging.info(f"执行断开连接脚本: {script_path}")
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
                
                # 使用/silent参数执行批处理脚本，并等待完成
                subprocess.run(
                    [script_path, "/silent"],
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    check=True
                )
                logging.info("断开连接脚本执行完成")
            else:
                logging.warning(f"断开连接脚本不存在: {script_path}")
            
            # 使用断开连接的基本函数
            success = disconnect_rdp_sessions()
            if success:
                logging.info("成功断开RDP连接")
            else:
                logging.warning("常规断开方法失败，尝试使用Windows API断开")
                try:
                    # 尝试使用Windows API直接断开
                    self._force_disconnect_api()
                except Exception as e:
                    logging.error(f"API断开连接失败: {e}")
            
            # 最后一次尝试使用系统命令强制断开
            try:
                # 执行多重强制断开
                self._force_disconnect_multiple()
            except Exception as e:
                logging.error(f"强制断开失败: {e}")
            
            # 关键修复：确保多次清理验证历史文件，不留死角
            try:
                verification_history_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "verification_history.json")
                if os.path.exists(verification_history_file):
                    # 清空验证历史
                    with open(verification_history_file, 'w', encoding='utf-8') as f:
                        json.dump({}, f)
                    logging.info("执行断开连接操作：已清空验证历史记录，确保下次连接重新验证")
            except Exception as e:
                logging.error(f"清理验证历史记录失败: {e}")
                
            # 同时清空RDP事件记录文件
            clear_rdp_events_file()
        except Exception as e:
            logging.error(f"执行断开连接操作时发生错误: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
    
    def _force_disconnect_api(self):
        """使用Windows API断开远程桌面连接"""
        try:
            logging.info("尝试使用Windows API断开连接")
            
            # 使用WTSDisconnectSession API
            # 需要先导入必要的库
            import ctypes
            from ctypes import wintypes
            
            # 加载必要的DLL
            wtsapi32 = ctypes.WinDLL('wtsapi32.dll')
            
            # 定义常量
            WTS_CURRENT_SERVER_HANDLE = 0
            
            # 定义函数原型
            wtsapi32.WTSDisconnectSession.argtypes = [
                wintypes.HANDLE,  # hServer
                wintypes.DWORD,   # SessionId
                wintypes.BOOL     # bWait
            ]
            wtsapi32.WTSDisconnectSession.restype = wintypes.BOOL
            
            # 断开所有可能的会话
            for session_id in range(10):  # 尝试更多会话ID
                try:
                    result = wtsapi32.WTSDisconnectSession(
                        WTS_CURRENT_SERVER_HANDLE,
                        session_id,
                        True  # 等待断开完成
                    )
                    if result:
                        logging.info(f"成功使用API断开会话 {session_id}")
                except Exception as e:
                    logging.debug(f"API断开会话 {session_id} 失败: {e}")
            
            logging.info("API断开连接尝试完成")
            return True
            
        except Exception as e:
            logging.error(f"使用API断开连接失败: {e}")
            return False
    
    def _force_disconnect_multiple(self):
        """使用多种系统命令断开RDP连接"""
        try:
            logging.info("开始执行多重系统命令断开连接")
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            
            # 使用quser获取会话信息
            try:
                logging.info("使用quser获取会话信息")
                quser_output = subprocess.check_output(
                    ["quser"], 
                    startupinfo=startupinfo,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    stderr=subprocess.STDOUT
                ).decode('gbk', errors='ignore')
                
                for line in quser_output.splitlines()[1:]:  # 跳过标题行
                    parts = line.split()
                    if len(parts) >= 2:
                        session_id = parts[1].strip()
                        if session_id.isdigit():
                            # 使用logoff命令断开
                            logging.info(f"尝试注销会话 {session_id}")
                            subprocess.run(
                                ["logoff", session_id, "/v"],
                                startupinfo=startupinfo,
                                creationflags=subprocess.CREATE_NO_WINDOW
                            )
            except Exception as e:
                logging.error(f"quser获取会话失败: {e}")
            
            # 使用最直接的系统命令断开连接
            commands = [
                # 使用WMI批处理命令（更直接的语法）
                '''powershell -WindowStyle Hidden -Command "(gwmi -Class Win32_TerminalServiceSetting -Namespace root\\cimv2\\terminalservices -ComputerName localhost -Authentication 6).InvokeMethod('DisconnectSession', $null)"''',
                
                # 使用Query和Reset命令
                "query session > %TEMP%\\sessions.txt",
                '''for /f "tokens=2,3" %i in ('type %TEMP%\\sessions.txt ^| findstr "Active"') do reset session %i /server:localhost''',
                
                # 强制重启终端服务
                "net stop UmRdpService /y",
                "net stop TermService /y",
                "net start TermService",
                "net start UmRdpService"
            ]
            
            for cmd in commands:
                try:
                    logging.info(f"执行命令: {cmd}")
                    subprocess.run(
                        cmd,
                        shell=True,
                        startupinfo=startupinfo,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=10  # 添加超时限制
                    )
                except Exception as e:
                    logging.error(f"命令执行失败: {cmd}, 错误: {e}")
            
            logging.info("多重系统命令执行完成")
            return True
            
        except Exception as e:
            logging.error(f"多重系统命令断开失败: {e}")
            return False

def extract_ip_from_event(message):
    """从事件消息中提取IP地址"""
    # 尝试多种正则表达式模式来匹配IP地址
    
    # 尝试匹配源网络地址 - 中文系统
    ip_match = re.search(r'源.*?地址:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|::1)', message, re.IGNORECASE)
    if ip_match:
        return ip_match.group(1)
        
    # 尝试匹配源网络地址 - 英文系统
    ip_match = re.search(r'Source.*?Address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|::1)', message, re.IGNORECASE)
    if ip_match:
        return ip_match.group(1)
    
    # 尝试匹配工作站名称中的IP - 某些情况下会这样显示
    ip_match = re.search(r'工作站名称:.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', message, re.IGNORECASE)
    if ip_match:
        return ip_match.group(1)
        
    # 尝试匹配工作站名称（英文）
    ip_match = re.search(r'Workstation Name:.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', message, re.IGNORECASE)
    if ip_match:
        return ip_match.group(1)
    
    # 尝试匹配任意出现的IP地址格式 - 最后的尝试
    all_ips = re.findall(r'(?<!\.)(?:\d{1,3}\.){3}\d{1,3}(?!\.)', message)
    if all_ips:
        # 过滤掉本地IP和私有链路地址
        filtered_ips = [ip for ip in all_ips if ip not in ['127.0.0.1', '::1', '169.254.0.0']]
        if filtered_ips:
            return filtered_ips[0]
    
    return None

def extract_username_from_event(message):
    """提取登录用户名"""
    # 尝试匹配中文系统格式
    username_match = re.search(r'帐户名称:\s*(.*?)\s*帐户域', message, re.IGNORECASE)
    if username_match:
        return username_match.group(1).strip()
        
    # 尝试匹配英文系统格式
    username_match = re.search(r'Account Name:\s*(.*?)\s*Account Domain', message, re.IGNORECASE)
    if username_match:
        return username_match.group(1).strip()
        
    # 尝试匹配带有账户用户名的格式
    username_match = re.search(r'帐户.*?用户名:(?:\s*)([^\s]+)', message, re.IGNORECASE)
    if username_match:
        return username_match.group(1).strip()
    
    # 尝试匹配英文账户用户名的格式
    username_match = re.search(r'Account.*?User Name:(?:\s*)([^\s]+)', message, re.IGNORECASE)
    if username_match:
        return username_match.group(1).strip()
    
    return "unknown"

def is_internal_ip(ip, allowed_networks):
    """检查是否是内网IP"""
    if not ip:
        return True
    
    # 检查常见内网IP范围
    if ip.startswith('127.') or ip.startswith('::1'):
        return True
    
    # 检查自定义的允许网络
    for network in allowed_networks:
        # 处理IP范围格式，如192.168.0.0/16
        if '/' in network:
            try:
                import ipaddress
                network_obj = ipaddress.IPv4Network(network, strict=False)
                ip_obj = ipaddress.IPv4Address(ip)
                if ip_obj in network_obj:
                    return True
            except Exception as e:
                logging.error(f"检查IP网络范围时出错: {e}")
        # 简单前缀匹配
        elif ip.startswith(network.split('/')[0].rsplit('.', 1)[0]):
            return True
    
    # 检查常见内网IP范围
    if (ip.startswith('10.') or 
        ip.startswith('192.168.') or 
        (ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31) or
        ip.startswith('169.254.')):
        return True
    
    return False

def is_ip_in_whitelist(ip, config):
    """检查IP是否在白名单中"""
    # 如果IP为unknown，则不在白名单中
    if ip == "unknown":
        return False
        
    # 读取白名单文件
    whitelist = load_ip_whitelist()
    
    # 精确匹配
    if ip in whitelist:
        logging.info(f"IP {ip} 在白名单中")
        return True
    
    # CIDR匹配
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        for item in whitelist:
            if '/' in item:  # CIDR格式
                try:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        logging.info(f"IP {ip} 匹配白名单CIDR规则: {item}")
                        return True
                except Exception as e:
                    logging.error(f"检查CIDR白名单规则 {item} 时出错: {e}")
    except Exception as e:
        logging.error(f"检查IP {ip} 是否在白名单中时发生错误: {e}")
    
    # 检查配置文件中的白名单（保留向后兼容性）
    whitelist_str = config.get("ip_whitelist", "")
    
    # 如果是字符串格式，转换为列表
    if isinstance(whitelist_str, str):
        config_whitelist = [x.strip() for x in whitelist_str.split(",") if x.strip()]
    else:
        # 兼容旧格式的数组
        config_whitelist = whitelist_str if isinstance(whitelist_str, list) else []
    
    # 检查IP是否在配置文件白名单中
    for whitelist_item in config_whitelist:
        # 检查是否为CIDR格式（包含"/"）
        if "/" in whitelist_item:
            try:
                import ipaddress
                network = ipaddress.ip_network(whitelist_item, strict=False)
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj in network:
                    logging.info(f"IP {ip} 在CIDR白名单 {whitelist_item} 中")
                    return True
            except Exception as e:
                logging.error(f"检查CIDR白名单 {whitelist_item} 出错: {e}")
        # 精确IP匹配
        elif ip == whitelist_item:
            logging.info(f"IP {ip} 在精确白名单中")
            return True
    
    return False

def update_ip_whitelist(ip, add=True, config=None):
    """更新IP白名单配置
    
    Args:
        ip: IP地址
        add: 是否添加到白名单，False表示从白名单移除
        config: 配置对象，如果为None则加载当前配置
    
    Returns:
        bool: 操作是否成功
    """
    if not config:
        config = load_config()
    
    # 添加或移除IP到白名单文件
    if add:
        add_result = add_ip_to_whitelist(ip)
    else:
        # 从配置文件获取白名单文件路径
        whitelist_path = config.get("ip_whitelistfile", "data/ip_whitelist.txt")
        
        # 使用绝对路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 如果路径是相对路径，转换为绝对路径
        if not os.path.isabs(whitelist_path):
            whitelist_path = os.path.join(current_dir, whitelist_path)
        
        # 加载现有白名单
        whitelist = load_ip_whitelist()
        
        # 从白名单中移除IP
        if ip in whitelist:
            whitelist.remove(ip)
            logging.info(f"IP {ip} 已从白名单文件中移除")
            
            # 写回白名单文件
            try:
                with open(whitelist_path, 'w', encoding='utf-8') as f:
                    f.write("# IP白名单文件，每行一个IP地址或CIDR网段\n")
                    for whitelist_ip in whitelist:
                        f.write(f"{whitelist_ip}\n")
                add_result = True
            except Exception as e:
                logging.error(f"更新白名单文件失败: {e}")
                add_result = False
        else:
            logging.info(f"IP {ip} 不在白名单文件中，无需移除")
            add_result = True
    
    # 向后兼容：同时更新config.json中的白名单配置
    # 从配置中获取当前白名单
    whitelist_str = config.get("ip_whitelist", "")
    
    # 如果是字符串格式，转换为列表
    if isinstance(whitelist_str, str):
        whitelist = [x.strip() for x in whitelist_str.split(",") if x.strip()]
    else:
        # 兼容旧格式的数组
        whitelist = whitelist_str if isinstance(whitelist_str, list) else []
    
    if add:
        # 添加IP到白名单
        if ip not in whitelist:
            whitelist.append(ip)
            logging.info(f"IP {ip} 已添加到配置文件白名单")
    else:
        # 从白名单移除IP
        if ip in whitelist:
            whitelist.remove(ip)
            logging.info(f"IP {ip} 已从配置文件白名单中移除")
    
    # 将列表转换回字符串格式
    new_whitelist_str = ",".join(whitelist)
    
    # 更新配置
    config["ip_whitelist"] = new_whitelist_str
    
    # 保存配置
    config_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
        
    config_file = os.path.join(config_dir, "config.json")
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        return add_result and True
    except Exception as e:
        logging.error(f"更新IP白名单配置文件失败: {e}")
        return False

def check_allowed_failed_attempts(ip, config):
    """检查IP是否允许失败尝试
    
    Args:
        ip: IP地址
        config: 配置信息
    
    Returns:
        (allowed, count): 元组，allowed表示是否允许，count表示当前失败次数
    """
    max_attempts = config.get("max_failed_attempts", 3)
    cooldown_period = config.get("blacklist_cooldown", 24) * 60  # 黑名单冷却期转换为分钟
    
    # 使用绝对路径
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    # 确保data目录存在
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        logging.info(f"已创建数据目录: {data_dir}")
        
    # 如果传入的IP为空或"unknown"，尝试从rdp_trigger.log中获取
    if not ip or ip == "unknown":
        trigger_log = os.path.join(logs_dir, 'rdp_trigger.log')
        if os.path.exists(trigger_log):
            try:
                with open(trigger_log, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                    # 获取最近的一条IP记录
                    ip_match = re.search(r'检测到RDP连接: IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_content)
                    if ip_match:
                        ip = ip_match.group(1)
                        logging.info(f"从rdp_trigger.log获取IP: {ip}")
            except Exception as e:
                logging.error(f"从rdp_trigger.log读取IP失败: {e}")
        
        # 如果仍然没有有效IP，尝试从message.log中获取
        if not ip or ip == "unknown":
            message_file = os.path.join(logs_dir, 'message.log')
            if os.path.exists(message_file):
                try:
                    with open(message_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 使用端口号从message.log中提取IP
                    rdp_port = config.get("rdp_port", 3389)
                    ip_patterns = [
                        fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):{rdp_port}',  # IP:port
                        fr'TCP\s+\S+:{rdp_port}\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+',  # TCP *:port IP:port
                        fr'TCP\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+\s+\S+:{rdp_port}'   # TCP IP:port *:port
                    ]
                    
                    for pattern in ip_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            if isinstance(matches[0], tuple):
                                ip = matches[0][0]  # 获取捕获组
                            else:
                                ip = matches[0]
                            logging.info(f"从message.log获取IP: {ip}")
                            break
                except Exception as e:
                    logging.error(f"从message.log读取IP失败: {e}")
    
    # 如果仍然没有有效IP，无法记录失败尝试
    if not ip or ip == "unknown":
        logging.error("无法获取有效的IP地址，无法记录失败尝试")
        return True, 0
        
    attempts_file = os.path.join(data_dir, "failed_attempts.json")
    
    # 加载失败尝试记录
    attempts_data = {}
    if os.path.exists(attempts_file):
        try:
            with open(attempts_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    logging.warning(f"失败尝试记录文件为空: {attempts_file}")
                else:
                    try:
                        attempts_data = json.loads(content)
                    except json.JSONDecodeError as e:
                        logging.error(f"解析失败尝试记录文件失败: {e}")
                        # 备份损坏的文件
                        backup_file = f"{attempts_file}.bak.{int(time.time())}"
                        try:
                            import shutil
                            shutil.copy2(attempts_file, backup_file)
                            logging.info(f"已备份损坏的失败尝试记录文件: {backup_file}")
                        except Exception as backup_error:
                            logging.error(f"备份失败尝试记录文件失败: {backup_error}")
        except Exception as e:
            logging.error(f"读取失败尝试记录文件失败: {e}")
    
    # 清理过期记录
    now = datetime.now()
    for ip_addr in list(attempts_data.keys()):
        if "expiry" in attempts_data[ip_addr]:
            expiry_time = datetime.fromisoformat(attempts_data[ip_addr]["expiry"])
            if now > expiry_time:
                del attempts_data[ip_addr]
    
    # 如果IP不在记录中，添加记录
    if ip not in attempts_data:
        expiry_time = now + timedelta(minutes=cooldown_period)
        attempts_data[ip] = {
            "count": 1,
            "expiry": expiry_time.isoformat()
        }
        try:
            with open(attempts_file, 'w', encoding='utf-8') as f:
                json.dump(attempts_data, f, indent=2)
        except Exception as e:
            logging.error(f"保存失败尝试记录失败: {e}")
        
        logging.info(f"IP {ip} 首次失败尝试，计数 1/{max_attempts}")
        return True, 1
    
    # 检查冷却期
    expiry_time = datetime.fromisoformat(attempts_data[ip]["expiry"])
    
    if now > expiry_time:
        # 冷却期已过，重置计数
        expiry_time = now + timedelta(minutes=cooldown_period)
        attempts_data[ip] = {
            "count": 1,
            "expiry": expiry_time.isoformat()
        }
        try:
            with open(attempts_file, 'w', encoding='utf-8') as f:
                json.dump(attempts_data, f, indent=2)
        except Exception as e:
            logging.error(f"保存失败尝试记录失败: {e}")
        
        logging.info(f"IP {ip} 冷却期已过，重置计数 1/{max_attempts}")
        return True, 1
    
    # 增加失败计数
    count = attempts_data[ip]["count"] + 1
    attempts_data[ip]["count"] = count
    
    try:
        with open(attempts_file, 'w', encoding='utf-8') as f:
            json.dump(attempts_data, f, indent=2)
    except Exception as e:
        logging.error(f"保存失败尝试记录失败: {e}")
    
    # 检查是否超过最大尝试次数
    if count > max_attempts:
        logging.warning(f"IP {ip} 已达到最大失败尝试次数 {count}/{max_attempts}")
        # 检查是否应该添加到黑名单
        if config.get("auto_blacklist", True) and count == max_attempts + 1:
            # 只在刚好超过次数限制时添加到黑名单
            logging.warning(f"IP {ip} 失败尝试次数超限，添加到黑名单")
            add_ip_to_blacklist(ip)
        return False, count
    
    logging.info(f"IP {ip} 失败尝试计数 {count}/{max_attempts}")
    return True, count

def send_push_notification(url, data):
    """发送推送通知"""
    try:
        logging.info(f"发送推送通知: {url}")
        
        # 如果URL是Server酱格式
        if "sctapi.ftqq.com" in url:
            # 构建Server酱消息
            message = f"检测到{data.get('status', '未知')}登录！\n"
            message += f"主机: {data.get('system', 'unknown')}\n"
            message += f"用户: {data.get('username', 'unknown')}\n"
            message += f"IP地址: {data.get('ip', 'unknown')}\n"
            message += f"时间: {data.get('time', 'unknown')}\n"
            message += f"状态: {data.get('message', '无详细信息')}"
            
            payload = {
                "text": "Windows远程登录",
                "desp": message
            }
            response = requests.post(url, data=payload, timeout=10)
        else:
            # 通用JSON格式推送
            headers = {"Content-Type": "application/json"}
            response = requests.post(url, json=data, headers=headers, timeout=10)
        
        if response.status_code == 200:
            logging.info(f"推送成功: {response.text[:100]}")
            return True
        else:
            logging.error(f"推送失败: 状态码 {response.status_code}, 响应: {response.text[:100]}")
            return False
    except Exception as e:
        logging.error(f"发送推送通知失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return False

def load_processed_events():
    """加载已处理的事件ID"""
    # 使用绝对路径
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    # 确保data目录存在
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        logging.info(f"已创建数据目录: {data_dir}")
        
    events_file = os.path.join(data_dir, "processed_events.json")
    
    if os.path.exists(events_file):
        try:
            with open(events_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    logging.warning(f"已处理事件文件为空: {events_file}")
                    return []
                    
                try:
                    events = json.loads(content)
                    return events
                except json.JSONDecodeError as e:
                    logging.error(f"解析已处理事件文件失败: {e}")
                    # 备份损坏的文件
                    backup_file = f"{events_file}.bak.{int(time.time())}"
                    try:
                        import shutil
                        shutil.copy2(events_file, backup_file)
                        logging.info(f"已备份损坏的已处理事件文件: {backup_file}")
                    except Exception as backup_error:
                        logging.error(f"备份已处理事件文件失败: {backup_error}")
        except Exception as e:
            logging.error(f"读取已处理事件文件失败: {e}")
    else:
        # 创建默认已处理事件文件
        try:
            with open(events_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
            logging.info(f"已创建默认已处理事件文件: {events_file}")
        except Exception as e:
            logging.error(f"创建默认已处理事件文件失败: {e}")
    
    return []

def save_processed_events(events):
    """保存已处理的事件ID"""
    # 使用绝对路径
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    # 确保data目录存在
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        logging.info(f"已创建数据目录: {data_dir}")
        
    events_file = os.path.join(data_dir, "processed_events.json")
    try:
        with open(events_file, 'w', encoding='utf-8') as f:
            json.dump(events, f, indent=2)
        return True
    except Exception as e:
        logging.error(f"保存已处理事件失败: {e}")
        return False

def check_windows_security_log(config, processed_events, rdp_monitor=None):
    """检查Windows安全日志中的远程桌面登录事件"""
    try:
        # 运行PowerShell命令获取安全日志中的RDP登录事件
        cmd = '''
        powershell -Command "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 20 | 
        Select-Object TimeCreated, Id, @{Name='Message';Expression={$_.Message}}, @{Name='RecordId';Expression={$_.RecordId}} | 
        ConvertTo-Json -Depth 3"
        '''
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
        
        if result.returncode != 0:
            logging.error(f"获取Windows安全日志失败: {result.stderr}")
            return processed_events
        
        # 检查PowerShell命令输出是否为空
        if not result.stdout.strip():
            logging.warning("PowerShell命令返回空结果，可能没有找到相关事件")
            return processed_events
            
        try:
            events = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logging.error(f"解析事件JSON失败: {e}")
            logging.debug(f"原始输出: {result.stdout[:500]}")
            return processed_events
        
        # 如果只有一个事件，PowerShell返回的可能不是数组
        if not isinstance(events, list):
            events = [events]
        
        # 按时间排序，确保按顺序处理
        events.sort(key=lambda x: x["TimeCreated"])
        
        new_processed_events = processed_events.copy()
        
        # 处理RDP登录事件
        for event in events:
            event_id = event.get("RecordId")
            event_type = event.get("Id")
            
            # 跳过已处理的事件
            if event_id in processed_events and config.get("check_new_events_only", True):
                continue
            
            message = event.get("Message", "")
            time_created = event.get("TimeCreated")
            
            # 创建一个标志，表示是否应该处理此事件
            should_process = True
            
            # 提取IP地址
            ip_address = extract_ip_from_event(message)
            
            # 检查是否是成功登录事件 (4624)
            if event_type == 4624 and "登录类型:\t\t10" in message or "Logon Type:\t\t10" in message:
                logging.info(f"检测到远程桌面成功登录事件 (ID: {event_id})")
                
                # 提取用户名和来源IP
                username = extract_username_from_event(message)
                
                # 格式化事件时间
                event_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                if time_created:
                    try:
                        # 尝试解析PowerShell返回的时间字符串
                        event_time = datetime.fromisoformat(time_created.rstrip('Z')).strftime('%Y-%m-%d %H:%M:%S')
                    except Exception as e:
                        logging.debug(f"无法解析事件时间: {e}")
                
                # 如果有RDPMonitor实例并且配置了PIN码，则进行PIN验证
                if rdp_monitor and config.get("pin_code"):
                    logging.info(f"检测到需要PIN码验证")
                    
                    # 创建事件对象用于验证 (模拟Windows事件日志对象)
                    mock_event = type('obj', (object,), {
                        'EventID': event_type,
                        'RecordNumber': event_id,
                        'TimeGenerated': type('obj', (object,), {
                            'timestamp': lambda: datetime.now().timestamp()
                        }),
                        'StringInserts': [],
                        # 添加关键属性
                        'Message': message  # 确保添加完整消息内容
                    })
                    
                    # 为RDPMonitor实例添加一些调试信息
                    logging.debug(f"使用PIN验证处理器处理登录事件，事件ID={event_id}, 类型={event_type}, IP={ip_address}")
                    
                    # 确保RDPMonitor实例中的logtype属性正确设置
                    if not hasattr(rdp_monitor, 'logtype') or not rdp_monitor.logtype:
                        rdp_monitor.logtype = "Security"  # 明确设置日志类型
                    
                    try:
                        # 调用RDPMonitor的process_event方法进行PIN验证和通知
                        logging.info(f"开始调用PIN验证处理器处理登录事件")
                        rdp_monitor.process_event(mock_event)
                        logging.info(f"PIN验证处理完成")
                    except Exception as e:
                        logging.error(f"PIN验证处理失败: {e}")
                        import traceback
                        logging.error(f"详细错误信息: {traceback.format_exc()}")
                    
                    # PIN验证处理完后，直接跳过后续的处理
                    continue
                
                # 没有PIN验证需求 或 没有RDPMonitor实例，直接处理
                # 如果是成功登录，添加IP到白名单，允许连接
                if ip_address:
                    # 添加到白名单
                    update_ip_whitelist(ip_address, add=True, config=config)
                    logging.info(f"成功登录，IP {ip_address} 已添加到白名单")
                
                # 准备推送消息
                push_data = {
                    "event": "rdp_login",
                    "status": "success", 
                    "time": time_created,
                    "username": username,
                    "ip": ip_address,
                    "system": socket.gethostname(),
                    "message": f"RDP成功登录: {username} 从 {ip_address}",
                    "verification_result": "无需验证"  # 标记为无需验证
                }
                
                # 检查IP是否是外网IP
                if ip_address and not is_internal_ip(ip_address, config.get("allowed_networks", [])):
                    # 外网IP登录，发送推送通知
                    if config.get("push_url"):
                        send_push_notification(config.get("push_url"), push_data)
                        logging.info(f"已发送外网登录成功推送通知: {username} 从 {ip_address}")
                
            # 检查是否是登录失败事件 (4625)
            elif event_type == 4625:
                logging.info(f"检测到远程桌面登录失败事件 (ID: {event_id})")
                
                # 提取用户名
                username = extract_username_from_event(message)
                
                # 检查IP是否在白名单中
                if ip_address and is_ip_in_whitelist(ip_address, config):
                    logging.info(f"IP {ip_address} 在白名单中，允许失败尝试")
                    continue
                
                # 检查IP是否允许失败尝试
                if ip_address:
                    allowed, attempt_count = check_allowed_failed_attempts(ip_address, config)
                    
                    # 准备推送消息
                    push_data = {
                        "event": "rdp_login",
                        "status": "failed",
                        "time": time_created,
                        "username": username, 
                        "ip": ip_address,
                        "attempts": attempt_count,
                        "system": socket.gethostname(),
                        "message": f"RDP登录失败: {username} 从 {ip_address} (第{attempt_count}次尝试)",
                        "verification_result": "失败"  # 标记为验证失败
                    }
                    
                    # 发送登录失败通知
                    if config.get("alert_on_failed_login") and config.get("push_url"):
                        # 检查IP是否是外网IP
                        if not is_internal_ip(ip_address, config.get("allowed_networks", [])):
                            send_push_notification(config.get("push_url"), push_data)
                            logging.info(f"已发送外网登录失败推送通知: {username} 从 {ip_address}")
                    
                    # 如果不允许更多失败尝试，断开连接
                    if not allowed and config.get("disconnect_on_failed_login", True):
                        logging.warning(f"IP {ip_address} 已达最大失败尝试次数，断开连接")
                        
                        # 断开所有RDP连接
                        if disconnect_rdp_sessions():
                            logging.info("已断开所有RDP连接")
                            
                            # 添加IP到白名单，避免持续踢出
                            update_ip_whitelist(ip_address, add=True, config=config)
                            logging.info(f"IP {ip_address} 已添加到白名单，允许重新尝试")
                            
                            # 发送断开连接通知
                            disconnect_data = {
                                "event": "rdp_disconnect",
                                "time": datetime.now().isoformat(),
                                "ip": ip_address,
                                "system": socket.gethostname(),
                                "message": f"已断开RDP连接: IP {ip_address} 登录失败次数过多",
                                "verification_result": "拒绝连接"  # 添加验证状态
                            }
                            
                            if config.get("push_url"):
                                send_push_notification(config.get("push_url"), disconnect_data)
                                logging.info(f"已发送断开连接推送通知")
            
            # 如果应该处理此事件，记录为已处理
            if should_process and event_id not in new_processed_events:
                new_processed_events.append(event_id)
        
        return new_processed_events
    except Exception as e:
        logging.error(f"检查Windows安全日志失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return processed_events

def main():
    """主函数"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description='RDP登录监控服务')
    parser.add_argument('-d', '--debug', action='store_true', help='启用调试模式')
    parser.add_argument('-u', '--url', type=str, help='设置通知URL')
    parser.add_argument('-k', '--sckey', type=str, help='设置Server酱SCKEY')
    parser.add_argument('-p', '--pin', type=str, help='设置登录验证PIN码')
    parser.add_argument('--port', type=int, help='设置RDP端口（默认3389）')
    parser.add_argument('-t', '--test', action='store_true', help='测试模式 - 仅检查配置')
    parser.add_argument('--test-ip', type=str, help='测试IP地址是否为内网/外网')
    parser.add_argument('--test-push', action='store_true', help='测试推送功能')
    parser.add_argument('--test-pin', action='store_true', help='测试PIN码验证对话框')
    parser.add_argument('--admin', action='store_true', help='尝试获取管理员权限运行')
    parser.add_argument('--trigger-notify', action='store_true', help='由任务计划触发时发送通知')
    parser.add_argument('--force', action='store_true', help='强制发送通知，即使是内网IP')
    parser.add_argument('--fix', action='store_true', help='尝试修复验证后通知问题')
    parser.add_argument('--verify-pin-only', action='store_true', help='仅进行PIN验证并将结果保存到文件')
    args = parser.parse_args()
    
    # 测试IP地址类型 - 在设置日志前处理
    if args.test_ip:
        # 简单初始化RDPMonitor类，无需日志系统
        monitor = RDPMonitor("", "", "")
        is_private = monitor.is_private_ip(args.test_ip)
        ip_type = "内网" if is_private else "外网"
        print(f"IP地址 {args.test_ip} 是{ip_type}IP")
        # 测试网络连接
        try:
            response = requests.get("https://www.baidu.com", timeout=5)
            print(f"网络连接测试: 成功 (状态码: {response.status_code})")
        except Exception as e:
            print(f"网络连接测试: 失败 ({e})")
        sys.exit(0)
    
    # 设置日志级别
    setup_logging(args.debug)
    print("RDP登录监控服务启动中...")
    
    # 如果指定了要获取管理员权限
    if args.admin and not is_admin():
        try:
            print("尝试以管理员权限重新启动程序...")
            # 使用pythonw.exe而不是python.exe，这样管理员权限窗口不会一闪而过
            admin_cmd = f'powershell -Command "Start-Process -FilePath \'{sys.executable}\' -ArgumentList \'{" ".join(sys.argv)}\' -Verb RunAs"'
            subprocess.run(admin_cmd, shell=True)
            sys.exit(0)
        except Exception as e:
            print(f"获取管理员权限失败: {e}")
    
    # 如果指定了PIN码，更新配置
    if args.pin:
        update_pin_code(args.pin)
        print(f"PIN码已更新")
    
    # 如果指定了SCKEY，更新配置
    if args.sckey:
        update_sckey(args.sckey)
        print(f"Server酱SCKEY已更新")
    
    # 如果指定了URL，更新配置
    if args.url:
        update_notification_url(args.url)
        print(f"通知URL已更新为: {args.url}")
    
    # 如果指定了RDP端口，更新配置
    if args.port:
        update_rdp_port(args.port)
        print(f"RDP端口已更新为: {args.port}")
    
    # 加载配置
    config = load_config()
    notification_url = config.get("notification_url", "")
    sckey = config.get("sckey", "")
    pin_code = config.get("pin_code", "")
    
    # 如果仅进行PIN验证
    if args.verify_pin_only:
        # 创建data目录，如果不存在
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)
        
        # 验证结果保存文件
        result_file = os.path.join(logs_dir, 'pin_verification_result.txt')
        
        try:
            logging.info("执行PIN码验证")
            
            # 显示PIN验证对话框
            if pin_code:
                # 重要：此处使用新的逻辑，无论验证结果如何，确保返回到rdp_trigger.py进行通知
                # 创建PIN验证对话框但不立即显示
                pin_dialog = PinDialog(pin_code)
                result = pin_dialog.show_dialog()
                
                # 此处检查result_file是否已经存在
                # 这是因为在验证失败或断开时，可能已经由dialog中的方法写入了结果文件
                if not os.path.exists(result_file):
                    logging.info(f"验证对话框已关闭，但未找到结果文件，使用对话框返回结果: {result}")
                    with open(result_file, 'w') as f:
                        if result:
                            f.write("成功")
                        else:
                            # 如果没有找到结果文件，且对话框返回False，判定为验证失败
                            f.write("失败")
                else:
                    logging.info("已找到验证结果文件，使用文件中的结果")
            else:
                # 没有配置PIN码
                logging.info("未配置PIN码，跳过验证")
                with open(result_file, 'w') as f:
                    f.write("无需验证")
        except Exception as e:
            logging.error(f"PIN验证过程出错: {e}")
            import traceback
            logging.error(f"详细错误: {traceback.format_exc()}")
            with open(result_file, 'w') as f:
                f.write("错误")
        
        # 确保结果文件已经被正确写入，并有足够时间被rdp_trigger.py读取
        if os.path.exists(result_file):
            try:
                with open(result_file, 'r') as f:
                    result_content = f.read().strip()
                logging.info(f"验证结果已写入文件: {result_content}")
                # 稍微延迟退出，确保文件完全写入并能被rdp_trigger.py读取
                time.sleep(0.5)
            except Exception as e:
                logging.error(f"读取结果文件失败: {e}")
        
        sys.exit(0)
    
    # 测试PIN码验证对话框
    if args.test_pin:
        print(f"测试PIN码验证对话框，正确PIN码: {pin_code}")
        pin_dialog = PinDialog(pin_code)
        if pin_dialog.show_dialog():
            print("PIN码验证成功")
        else:
            print("PIN码验证失败或超时")
        sys.exit(0)
    
    # 测试推送功能
    if args.test_push:
        print("测试推送功能...")
        # 使用最简单的消息格式
        push_data = {
            "event": "rdp_login",
            "status": "success", 
            "time": datetime.now().isoformat(),
            "username": "test_user",
            "ip": "8.8.8.8",
            "system": socket.gethostname(),
            "message": f"RDP监控测试推送",
            "verification_result": "测试"  # 添加验证结果字段进行测试
        }
        
        # 如果用户配置了推送URL
        if config.get("push_url"):
            push_url = config.get("push_url")
            try:
                print(f"正在发送推送请求到: {push_url}")
                if send_push_notification(push_url, push_data):
                    print("推送成功！请检查您的设备是否收到通知")
                else:
                    print("推送失败，请检查网络或推送URL配置")
            except Exception as e:
                print(f"推送过程中发生错误: {e}")
        else:
            # 使用Server酱推送
            push_url = f'https://sctapi.ftqq.com/{sckey}.send'
            try:
                print(f"正在使用Server酱推送到: {push_url}")
                
                # 构建参数
                params = {
                    'title': 'Windows远程登录测试 (验证测试)',
                    'desp': f"这是一条测试消息\n主机: {socket.gethostname()}\n时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n验证结果: PIN码验证测试"
                }
                
                response = requests.post(push_url, data=params, timeout=10)
                print(f"推送结果: 状态码={response.status_code}")
                print(f"响应内容: {response.text[:200]}")
                if response.status_code == 200:
                    print("推送成功！请检查您的设备是否收到通知")
                else:
                    print("推送失败，请检查网络或密钥配置")
            except Exception as e:
                print(f"推送过程中发生错误: {e}")
        sys.exit(0)
    
    # 如果是由任务计划触发的通知
    if args.trigger_notify:
        try:
            # 检查重复通知标志
            logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            flag_file = os.path.join(logs_dir, 'notification_sent.flag')
            should_send = True
            
            if os.path.exists(flag_file):
                # 检查文件时间戳
                flag_time = os.path.getmtime(flag_file)
                current_time = time.time()
                
                # 如果标志文件在30秒内创建，跳过通知
                if current_time - flag_time < 30:
                    print(f"检测到30秒内已发送过通知，跳过本次通知")
                    should_send = False
            
            # 更新标志文件
            with open(flag_file, 'w') as f:
                f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            
            # 如果决定不发送通知，直接退出
            if not should_send:
                sys.exit(0)
                
            # 读取连接信息
            data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
            logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
            message_file = os.path.join(logs_dir, 'message.log')
            
            if os.path.exists(message_file):
                # 尝试以不同编码读取文件
                encodings = ['utf-8', 'gbk', 'gb2312', 'ansi']
                content = None
                
                for encoding in encodings:
                    try:
                        with open(message_file, 'r', encoding=encoding) as f:
                            content = f.read()
                            print(f"成功使用 {encoding} 编码读取文件")
                            break
                    except UnicodeDecodeError:
                        continue
                
                if content is None:
                    # 如果所有编码都失败，尝试二进制读取
                    with open(message_file, 'rb') as f:
                        content = f.read().decode('utf-8', errors='ignore')
                
                # 从连接内容中提取必要信息 - 增强版
                # 使用多种模式提取IP地址
                # 从配置中读取RDP端口
                rdp_port = config.get("rdp_port", 3389)
                ip_patterns = [
                    fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):{rdp_port}',  # IP:port
                    fr'TCP\s+\S+:{rdp_port}\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+', # TCP *:port IP:port
                    fr'TCP\s+(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):\d+\s+\S+:{rdp_port}', # TCP IP:port *:port
                    fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}})\s+.*{rdp_port}', # 任何包含IP和端口的行
                    r'ESTABLISHED\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', # 已建立的连接
                    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # 最后尝试匹配任何IP
                ]
                
                all_ips = []
                for pattern in ip_patterns:
                    matches = re.findall(pattern, content)
                    if matches:
                        print(f"找到IP匹配: {matches}")
                        all_ips.extend(matches)
                
                # 去重
                all_ips = list(dict.fromkeys(all_ips))
                print(f"所有找到的IP: {all_ips}")
                
                # 过滤本地IP
                local_ip = socket.gethostbyname(socket.gethostname())
                filtered_ips = [ip for ip in all_ips if not (ip.startswith('127.') or 
                                                           ip.startswith('0.') or 
                                                           ip == local_ip or 
                                                           ip == "0.0.0.0" or 
                                                           ip == "255.255.255.255")]
                
                print(f"过滤后的IP: {filtered_ips}")
                
                if filtered_ips:
                    # 创建connection_info字典
                    connection_info = {}
                    # 创建临时RDPMonitor实例用于检测IP类型
                    rdp_monitor_instance = RDPMonitor("", "", "")
                    # 优先使用外网IP
                    external_ips = [ip for ip in filtered_ips if not rdp_monitor_instance.is_private_ip(ip)]
                    if external_ips:
                        connection_info["client_ip"] = external_ips[0]
                        logging.info(f"使用外网IP: {connection_info['client_ip']}")
                    else:
                        connection_info["client_ip"] = filtered_ips[0]
                        logging.info(f"使用内网IP: {connection_info['client_ip']}")
                    
                    # 修改为始终使用过滤后列表的第一个IP（即netstat中的连接IP）
                    client_ip = filtered_ips[0]
                    logging.info(f"使用RDP连接IP: {client_ip}")
                    
                    # 检查IP是否在白名单中
                    is_in_whitelist = is_ip_in_whitelist(client_ip, config)
                    
                    # 如果不在白名单中或强制通知，发送通知
                    if not is_in_whitelist or args.force:
                        # 检查是否存在PIN验证结果
                        verification_result = "任务触发"
                        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
                        pin_result_file = os.path.join(logs_dir, 'pin_verification_result.txt')
                        if os.path.exists(pin_result_file):
                            try:
                                with open(pin_result_file, 'r') as f:
                                    verification_result = f.read().strip()
                                print(f"找到PIN验证结果: {verification_result}")
                            except Exception as e:
                                print(f"读取PIN验证结果失败: {e}")
                        
                        # 构造通知数据
                        push_data = {
                            "event": "rdp_login",
                            "status": "success",
                            "time": datetime.now().isoformat(),
                            "username": "任务计划触发",
                            "ip": client_ip,
                            "system": socket.gethostname(),
                            "message": f"RDP成功登录: 任务计划触发 从 {client_ip}",
                            "verification_result": verification_result  # 添加验证状态标记
                        }
                        
                        # 发送通知
                        if config.get("push_url"):
                            if send_push_notification(config.get("push_url"), push_data):
                                print(f"已发送RDP登录通知: {client_ip}")
                            else:
                                print(f"发送通知失败")
                        else:
                            print("未配置推送URL，无法发送通知")
                    else:
                        print(f"IP {client_ip} 在白名单中，跳过通知")
                else:
                    print("未找到有效IP地址，无法发送通知")
            else:
                print("未找到消息文件，无法发送通知")
                
        except Exception as e:
            print(f"触发通知失败: {e}")
            import traceback
            print(traceback.format_exc())
        sys.exit(0)
    
    if args.test:
        # 确保目录结构存在
        base_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(base_dir, 'logs')
        data_dir = os.path.join(base_dir, 'data')
        config_dir = os.path.join(base_dir, 'config')
        
        for directory in [log_dir, data_dir, config_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
                print(f"已创建目录: {directory}")
        
        print("测试模式：")
        print(f"- 工作目录: {os.path.abspath('.')}")
        print(f"- 脚本目录: {os.path.dirname(os.path.abspath(__file__))}")
        print(f"- 通知URL: {notification_url}")
        print(f"- Server酱SCKEY: {sckey[:5]}...{sckey[-5:] if len(sckey) > 10 else ''}")
        print(f"- 登录PIN码: {pin_code}")
        print(f"- 日志文件: {os.path.join(log_dir, 'rdp_monitor.log')}")
        print(f"- 配置文件: {os.path.join(config_dir, 'config.json')}")
        print(f"- 事件文件: {os.path.join(data_dir, 'rdp_events.json')}")
        
        # 测试管理员权限
        if is_admin():
            print("- 当前以管理员权限运行: 是")
        else:
            print("- 当前以管理员权限运行: 否 (需要管理员权限才能访问安全日志)")
        
        print("配置测试完成。如无错误信息，则配置正确。")
        sys.exit(0)
    
    # 标记程序启动日志
    logging.info("==================== RDP监控服务启动 ====================")
    logging.info(f"使用配置: 主机名={socket.gethostname()}, PIN码={pin_code != ''}, SCKEY={sckey[:5]}...")
    
    # 如果启用了修复模式
    if args.fix:
        logging.info("启用修复模式 - 尝试修复验证后通知问题")
        print("启用修复模式 - 尝试修复验证后通知问题")
        
        # 创建具有更详细日志的RDPMonitor实例
        monitor = RDPMonitor(notification_url, sckey, pin_code)
        
        # 打印调试信息
        print(f"已创建RDPMonitor实例，PIN码: {pin_code != ''}, 通知URL: {notification_url}")
        print("按Ctrl+C停止监控")
        
        try:
            # 直接使用新的监控逻辑，但传入RDPMonitor实例
            processed_events = load_processed_events()
            while True:
                try:
                    new_processed_events = check_windows_security_log(config, processed_events, monitor)
                    if new_processed_events != processed_events:
                        processed_events = new_processed_events
                        save_processed_events(processed_events)
                        logging.debug(f"已处理事件数: {len(processed_events)}")
                    time.sleep(2)  # 降低检查频率，避免错过事件
                except Exception as e:
                    logging.error(f"检查事件时出错: {e}")
                    import traceback
                    logging.error(f"详细错误: {traceback.format_exc()}")
                    time.sleep(5)
        except KeyboardInterrupt:
            print("监控服务已停止")
        sys.exit(0)
    
    # 使用监控逻辑
    logging.info("启动RDP监控服务")
    print("启动RDP监控服务")
    monitor_login_events()

def is_admin():
    """检查当前程序是否以管理员权限运行"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def update_rdp_port(port: int) -> bool:
    """更新RDP端口配置"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config_dir = os.path.join(current_dir, 'config')
    config_file = os.path.join(config_dir, "config.json")
    
    # 读取现有配置
    config = load_config()
    
    # 更新端口配置
    config["rdp_port"] = port
    
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logging.info(f"RDP端口已更新为: {port}")
        return True
    except Exception as e:
        logging.error(f"更新RDP端口失败: {e}")
        return False

def monitor_login_events():
    """主监控循环，使用改进后的登录事件处理和断开逻辑"""
    logging.info("启动RDP登录监控...")
    
    # 加载配置
    config = load_config()
    
    # 加载已处理事件
    processed_events = load_processed_events()
    
    # 创建数据目录
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    
    # 创建RDPMonitor实例用于PIN验证
    pin_code = config.get("pin_code", "")
    sckey = config.get("sckey", "")
    notification_url = config.get("notification_url", "")
    rdp_monitor = RDPMonitor(notification_url, sckey, pin_code)
    
    logging.info(f"RDP设置: PIN码验证={'已启用' if pin_code else '未启用'}, 通知URL={notification_url}")
    logging.info(f"使用配置对象: {rdp_monitor}")
    
    try:
        # 记录启动信息
        logging.info(f"RDP监控服务已启动，主机: {socket.gethostname()}")
        logging.info(f"使用配置: {config}")
        
        # 主循环
        while True:
            try:
                # 检查安全日志中的新事件，使用RDPMonitor实例进行验证和通知
                new_processed_events = check_windows_security_log(config, processed_events, rdp_monitor)
                
                # 更新已处理事件
                if new_processed_events != processed_events:
                    processed_events = new_processed_events
                    save_processed_events(processed_events)
                    logging.debug(f"已处理事件数量: {len(processed_events)}")
                
                # 睡眠指定的检查间隔时间
                time.sleep(config.get("check_interval", 5))
                
            except Exception as e:
                logging.error(f"监控循环中出错: {e}")
                import traceback
                logging.error(f"详细错误: {traceback.format_exc()}")
                # 短暂休眠后继续
                time.sleep(5)
    
    except KeyboardInterrupt:
        logging.info("监控服务已手动停止")
    except Exception as e:
        logging.error(f"监控服务异常退出: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
    finally:
        logging.info("监控服务已停止")

def is_ip_in_blacklist(ip, config):
    """检查IP是否在黑名单中
    
    Args:
        ip: 要检查的IP地址
        config: 配置对象
        
    Returns:
        bool: 如果IP在黑名单中返回True，否则返回False
    """
    if not ip:
        return False

    # 首先检查IP是否在白名单中，如果在白名单中则不判定为黑名单
    if is_ip_in_whitelist(ip, config):
        logging.info(f"IP {ip} 在白名单中，白名单优先于黑名单")
        return False
        
    # 读取黑名单
    blacklist = load_ip_blacklist()
    
    # 精确匹配
    if ip in blacklist:
        logging.info(f"IP {ip} 在黑名单中")
        return True
    
    # CIDR匹配
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        for item in blacklist:
            if '/' in item:  # CIDR格式
                try:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        logging.info(f"IP {ip} 匹配黑名单CIDR规则: {item}")
                        return True
                except Exception as e:
                    logging.error(f"检查CIDR黑名单规则 {item} 时出错: {e}")
    except Exception as e:
        logging.error(f"检查IP {ip} 是否在黑名单中时发生错误: {e}")
    
    return False

def load_ip_blacklist():
    """加载IP黑名单列表
    
    Returns:
        list: 包含所有黑名单IP/CIDR的列表
    """
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 从配置文件获取黑名单文件路径
    config = load_config()
    blacklist_path = config.get("ip_blacklistfile", "data/ip_blacklist.txt")
    
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(blacklist_path):
        blacklist_path = os.path.join(current_dir, blacklist_path)
    
    # 确保目录存在
    blacklist_dir = os.path.dirname(blacklist_path)
    if not os.path.exists(blacklist_dir):
        os.makedirs(blacklist_dir)
        logging.info(f"已创建黑名单目录: {blacklist_dir}")
    
    blacklist = []
    
    # 如果黑名单文件存在，读取内容
    if os.path.exists(blacklist_path):
        try:
            with open(blacklist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blacklist.append(line)
            logging.debug(f"已加载黑名单文件 {blacklist_path}，包含 {len(blacklist)} 个条目")
        except Exception as e:
            logging.error(f"读取黑名单文件失败: {e}")
    else:
        # 创建空黑名单文件
        try:
            with open(blacklist_path, 'w', encoding='utf-8') as f:
                f.write("# IP黑名单文件，每行一个IP地址或CIDR网段\n")
                f.write("# 示例:\n")
                f.write("# 192.168.1.100\n")
                f.write("# 10.0.0.0/8\n")
            logging.info(f"已创建默认黑名单文件: {blacklist_path}")
        except Exception as e:
            logging.error(f"创建默认黑名单文件失败: {e}")
    
    return blacklist

def load_ip_whitelist():
    """加载IP白名单列表
    
    Returns:
        list: 包含所有白名单IP/CIDR的列表
    """
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 从配置文件获取白名单文件路径
    config = load_config()
    whitelist_path = config.get("ip_whitelistfile", "data/ip_whitelist.txt")
    
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(whitelist_path):
        whitelist_path = os.path.join(current_dir, whitelist_path)
    
    # 确保目录存在
    whitelist_dir = os.path.dirname(whitelist_path)
    if not os.path.exists(whitelist_dir):
        os.makedirs(whitelist_dir)
        logging.info(f"已创建白名单目录: {whitelist_dir}")
    
    whitelist = []
    
    # 如果白名单文件存在，读取内容
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        whitelist.append(line)
            logging.debug(f"已加载白名单文件 {whitelist_path}，包含 {len(whitelist)} 个条目")
        except Exception as e:
            logging.error(f"读取白名单文件失败: {e}")
    else:
        # 创建空白名单文件
        try:
            with open(whitelist_path, 'w', encoding='utf-8') as f:
                f.write("# IP白名单文件，每行一个IP地址或CIDR网段\n")
                f.write("# 示例:\n")
                f.write("# 192.168.1.100\n")
                f.write("# 10.0.0.0/8\n")
            logging.info(f"已创建默认白名单文件: {whitelist_path}")
        except Exception as e:
            logging.error(f"创建默认白名单文件失败: {e}")
    
    return whitelist

def add_ip_to_blacklist(ip):
    """将IP添加到黑名单
    
    Args:
        ip: 要添加的IP地址
        
    Returns:
        bool: 添加成功返回True，否则返回False
    """
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(current_dir, 'logs')
    
    # 如果IP为空或为"unknown"，尝试获取有效IP
    if not ip or ip == "unknown":
        # 尝试从日志文件中获取IP
        trigger_log = os.path.join(logs_dir, 'rdp_trigger.log')
        if os.path.exists(trigger_log):
            try:
                with open(trigger_log, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                    # 搜索最近的IP记录
                    ip_match = re.search(r'检测到RDP连接: IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_content)
                    if ip_match:
                        ip = ip_match.group(1)
                        logging.info(f"从rdp_trigger.log获取到黑名单IP: {ip}")
            except Exception as e:
                logging.error(f"从rdp_trigger.log读取IP失败: {e}")
        
        # 如果仍然没有有效IP，尝试从message.log获取
        if not ip or ip == "unknown":
            message_file = os.path.join(logs_dir, 'message.log')
            if os.path.exists(message_file):
                try:
                    with open(message_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 使用正则表达式查找IP地址
                    # 从配置文件获取RDP端口
                    config = load_config()
                    rdp_port = config.get("rdp_port", 3389)
                    
                    ip_patterns = [
                        fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):{rdp_port}',  # IP:port
                        fr'TCP\\s+\\S+:{rdp_port}\\s+(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}):\\d+',  # TCP *:port IP:port
                        fr'TCP\\s+(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}):\\d+\\s+\\S+:{rdp_port}'   # TCP IP:port *:port
                    ]
                    
                    for pattern in ip_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            if isinstance(matches[0], tuple):
                                ip = matches[0][0]  # 获取正则表达式的第一个捕获组
                            else:
                                ip = matches[0]
                            logging.info(f"从message.log获取到黑名单IP: {ip}")
                            break
                except Exception as e:
                    logging.error(f"从message.log读取IP失败: {e}")
    
    # 如果仍然没有有效IP，无法添加到黑名单
    if not ip or ip == "unknown":
        logging.error("无法获取有效的IP地址，无法添加到黑名单")
        return False
    
    # 从配置文件获取黑名单文件路径
    config = load_config()
    blacklist_path = config.get("ip_blacklistfile", "data/ip_blacklist.txt")
    
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(blacklist_path):
        blacklist_path = os.path.join(current_dir, blacklist_path)
    
    # 加载现有黑名单
    blacklist = load_ip_blacklist()
    
    # 检查IP是否已在黑名单中
    if ip in blacklist:
        logging.info(f"IP {ip} 已在黑名单中")
        return True
    
    # 添加IP到黑名单
    try:
        with open(blacklist_path, 'a', encoding='utf-8') as f:
            f.write(f"{ip}\n")
        logging.info(f"IP {ip} 已添加到黑名单")
        return True
    except Exception as e:
        logging.error(f"添加IP到黑名单失败: {e}")
        return False

def add_ip_to_whitelist(ip):
    """将IP添加到白名单
    
    Args:
        ip: 要添加的IP地址
        
    Returns:
        bool: 添加成功返回True，否则返回False
    """
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(current_dir, 'logs')
    
    # 如果IP为空或为"unknown"，尝试获取有效IP
    if not ip or ip == "unknown":
        # 尝试从日志文件中获取IP
        trigger_log = os.path.join(logs_dir, 'rdp_trigger.log')
        if os.path.exists(trigger_log):
            try:
                with open(trigger_log, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                    # 搜索最近的IP记录
                    ip_match = re.search(r'检测到RDP连接: IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_content)
                    if ip_match:
                        ip = ip_match.group(1)
                        logging.info(f"从rdp_trigger.log获取到白名单IP: {ip}")
            except Exception as e:
                logging.error(f"从rdp_trigger.log读取IP失败: {e}")
        
        # 如果仍然没有有效IP，尝试从message.log获取
        if not ip or ip == "unknown":
            message_file = os.path.join(logs_dir, 'message.log')
            if os.path.exists(message_file):
                try:
                    with open(message_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # 使用正则表达式查找IP地址
                    # 从配置文件获取RDP端口
                    config = load_config()
                    rdp_port = config.get("rdp_port", 3389)
                    
                    ip_patterns = [
                        fr'(\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}\.\d{{1,3}}):{rdp_port}',  # IP:port
                        fr'TCP\\s+\\S+:{rdp_port}\\s+(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}):\\d+',  # TCP *:port IP:port
                        fr'TCP\\s+(\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}):\\d+\\s+\\S+:{rdp_port}'   # TCP IP:port *:port
                    ]
                    
                    for pattern in ip_patterns:
                        matches = re.findall(pattern, content)
                        if matches:
                            if isinstance(matches[0], tuple):
                                ip = matches[0][0]  # 获取正则表达式的第一个捕获组
                            else:
                                ip = matches[0]
                            logging.info(f"从message.log获取到白名单IP: {ip}")
                            break
                except Exception as e:
                    logging.error(f"从message.log读取IP失败: {e}")
    
    # 如果仍然没有有效IP，无法添加到白名单
    if not ip or ip == "unknown":
        logging.error("无法获取有效的IP地址，无法添加到白名单")
        return False
    
    # 从配置文件获取白名单文件路径
    config = load_config()
    whitelist_path = config.get("ip_whitelistfile", "data/ip_whitelist.txt")
    
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(whitelist_path):
        whitelist_path = os.path.join(current_dir, whitelist_path)
    
    # 加载现有白名单
    whitelist = load_ip_whitelist()
    
    # 检查IP是否已在白名单中
    if ip in whitelist:
        logging.info(f"IP {ip} 已在白名单中")
        return True
    
    # 添加IP到白名单
    try:
        with open(whitelist_path, 'a', encoding='utf-8') as f:
            f.write(f"{ip}\n")
        logging.info(f"IP {ip} 已添加到白名单")
        return True
    except Exception as e:
        logging.error(f"添加IP到白名单失败: {e}")
        return False

def clear_rdp_events_file():
    """清空RDP事件记录文件，确保不会保留旧的验证状态"""
    try:
        # 使用绝对路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(current_dir, 'data')
        events_file = os.path.join(data_dir, "rdp_events.json")
        
        if os.path.exists(events_file):
            # 保留一个空的事件数组
            with open(events_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
            logging.info("已清空RDP事件记录文件，确保下次连接重新验证")
            return True
    except Exception as e:
        logging.error(f"清空RDP事件记录文件失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return False
    return True

if __name__ == "__main__":
    main() 