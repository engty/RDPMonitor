#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
RDP登录触发器
当远程桌面连接时，由任务计划程序触发执行
用于配合rdp_monitor.py进行登录检测和通知
"""

import os
import sys
import json
import socket
import logging
import requests
from datetime import datetime
import re
import subprocess
import time

# 设置脚本工作目录为脚本所在目录
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

# 确保必要的目录存在
data_dir = os.path.join(script_dir, 'data')
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

log_dir = os.path.join(script_dir, 'logs')
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# 配置日志
log_file = os.path.join(log_dir, 'rdp_trigger.log')
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

def load_config():
    """加载配置文件"""
    config_dir = os.path.join(script_dir, 'config')
    config_file = os.path.join(config_dir, 'config.json')
    
    default_config = {
        "notification_url": "",
        "sckey": "",
        "pin_code": "123456"
    }
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"读取配置文件失败: {e}")
            return default_config
    else:
        logging.warning(f"配置文件不存在，使用默认配置")
        return default_config

def get_local_ip():
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

def get_connection_info():
    """获取RDP连接信息"""
    connection_info = {}
    connection_info["hostname"] = socket.gethostname()
    connection_info["local_ip"] = get_local_ip()
    connection_info["event_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 读取message.log文件获取连接信息
    message_file = os.path.join(log_dir, 'message.log')
    logging.info(f"尝试从 {message_file} 读取连接信息")
    
    if os.path.exists(message_file):
        try:
            # 尝试以不同编码读取文件
            encodings = ['utf-8', 'gbk', 'gb2312', 'ansi']
            content = None
            
            for encoding in encodings:
                try:
                    with open(message_file, 'r', encoding=encoding) as f:
                        content = f.read()
                        logging.info(f"成功使用 {encoding} 编码读取文件")
                        break
                except UnicodeDecodeError:
                    continue
            
            if content is None:
                # 如果所有编码都失败，尝试二进制读取
                with open(message_file, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    logging.info("使用二进制模式读取并强制解码")
            
            # 记录原始内容用于调试
            logging.info(f"文件内容预览: {content[:200]}...")
                
            # 提取用户名
            username_match = re.search(r'whoami\s+(.+?)$', content, re.MULTILINE)
            if username_match:
                connection_info["username"] = username_match.group(1).strip()
                logging.info(f"找到用户名: {connection_info['username']}")
            else:
                # 尝试不同方式匹配用户名
                # 1. 尝试匹配格式: 计算机名\用户名 (作为独立一行)
                username_match = re.search(r'([^\\]+?)\\([^\\]+?)\r?\n', content, re.MULTILINE)
                if username_match:
                    connection_info["username"] = username_match.group(2).strip()
                    logging.info(f"找到用户名(计算机名\\用户名格式): {connection_info['username']}")
                else:
                    # 2. 尝试读取第5行 (基于日志观察)
                    lines = content.split('\n')
                    if len(lines) >= 5:
                        fifth_line = lines[4].strip()
                        if '\\' in fifth_line:
                            computer_name, username = fifth_line.split('\\', 1)
                            connection_info["username"] = username.strip()
                            logging.info(f"从第5行提取用户名: {connection_info['username']}")
                        else:
                            connection_info["username"] = "unknown"
                            logging.warning("第5行不包含用户名格式")
                    else:
                        connection_info["username"] = "unknown"
                        logging.warning("未找到用户名信息")
            
            # 使用多种模式提取IP地址
            # 1. 标准netstat输出模式 (IP:3389)
            ip_patterns = [
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):3389',  # IP:3389
                r'TCP\s+\S+:3389\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', # TCP *:3389 IP:port
                r'TCP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+\s+\S+:3389', # TCP IP:port *:3389
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.*3389', # 任何包含IP和3389的行
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # 最后尝试匹配任何IP
            ]
            
            all_ips = []
            for pattern in ip_patterns:
                matches = re.findall(pattern, content)
                logging.info(f"使用模式 '{pattern}' 找到IP: {matches}")
                all_ips.extend(matches)
            
            # 去重
            all_ips = list(dict.fromkeys(all_ips))
            
            # 过滤本地IP和内网IP
            filtered_ips = []
            for ip in all_ips:
                if ip and not (ip.startswith('127.') or ip.startswith('0.') or 
                        ip == connection_info["local_ip"] or ip == "0.0.0.0" or 
                        ip == "255.255.255.255"):
                    filtered_ips.append(ip)
            
            logging.info(f"所有找到的IP: {all_ips}")
            logging.info(f"过滤后的IP: {filtered_ips}")
            
            if filtered_ips:
                # 优先使用外网IP
                external_ips = [ip for ip in filtered_ips if not is_private_ip(ip)]
                if external_ips:
                    connection_info["client_ip"] = external_ips[0]
                    logging.info(f"使用外网IP: {connection_info['client_ip']}")
                else:
                    connection_info["client_ip"] = filtered_ips[0]
                    logging.info(f"使用内网IP: {connection_info['client_ip']}")
                
                # 修改为始终使用过滤后列表的第一个IP（即netstat中的连接IP）
                connection_info["client_ip"] = filtered_ips[0]
                logging.info(f"检测到RDP连接: IP={filtered_ips[0]}")
            else:
                # 如果没找到任何有效IP
                if all_ips:
                    connection_info["client_ip"] = all_ips[0]
                    logging.warning(f"未找到理想IP，使用: {connection_info['client_ip']}")
                else:
                    connection_info["client_ip"] = "unknown"
                    logging.error("未找到任何IP地址")
            
            # 尝试使用备用方法获取IP
            if connection_info["client_ip"] == "unknown":
                logging.info("尝试使用备用方法获取连接IP...")
                # 使用ipconfig/all和netstat -n命令组合获取
                try:
                    netstat_output = subprocess.check_output("netstat -n | findstr :3389", shell=True).decode('utf-8', errors='ignore')
                    logging.info(f"netstat输出: {netstat_output[:200]}...")
                    
                    # 从netstat输出提取IP
                    ip_matches = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+', netstat_output)
                    filtered_netstat_ips = [ip for ip in ip_matches if not (ip.startswith('127.') or ip.startswith('0.') or ip == connection_info["local_ip"])]
                    
                    if filtered_netstat_ips:
                        connection_info["client_ip"] = filtered_netstat_ips[0]
                        logging.info(f"通过netstat备用方法找到IP: {connection_info['client_ip']}")
                except Exception as e:
                    logging.error(f"备用方法获取IP失败: {e}")
                
        except Exception as e:
            logging.error(f"读取连接信息失败: {e}")
            import traceback
            logging.error(f"错误详情: {traceback.format_exc()}")
    else:
        logging.error(f"消息文件不存在: {message_file}")
    
    return connection_info

def is_private_ip(ip):
    """判断是否是内网IP"""
    if ip == "unknown":
        return True
        
    try:
        # 检查常见的内网IP范围
        if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
            return True
            
        # 172.16.0.0/12 网段
        if ip.startswith('172.'):
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return True
                
        # 169.254.0.0/16 自动私有IP
        if ip.startswith('169.254.'):
            return True
            
        return False
    except Exception as e:
        logging.error(f"IP地址格式无效: {e}")
        return True

def is_ip_in_blacklist(ip, config):
    """检查IP是否在黑名单中"""
    if not ip:
        return False
    
    # 首先检查IP是否在白名单中，如果在白名单中则不判定为黑名单
    if is_ip_in_whitelist(ip, config):
        logging.info(f"IP {ip} 在白名单中，白名单优先于黑名单")
        return False
    
    # 读取黑名单文件
    blacklist_path = config.get("ip_blacklistfile", "data/ip_blacklist.txt")
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(blacklist_path):
        blacklist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), blacklist_path)
    
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

def show_pin_dialog():
    """显示PIN码验证对话框并等待验证结果"""
    try:
        config = load_config()
        pin_code = config.get("pin_code", "123456")
        
        if not pin_code:
            logging.info("未配置PIN码，跳过验证")
            return None
        
        # 从日志文件获取连接信息
        connection_info = get_connection_info()
        client_ip = connection_info.get("client_ip", "unknown")
        
        # 首先检查IP是否在白名单中，如果在白名单中则跳过验证
        if is_ip_in_whitelist(client_ip, config):
            logging.info(f"IP {client_ip} 在白名单中，跳过PIN验证")
            return "白名单免验证"
        
        # 然后检查IP是否在黑名单中，如果在黑名单中则拒绝连接
        if is_ip_in_blacklist(client_ip, config):
            logging.warning(f"IP {client_ip} 在黑名单中，拒绝连接")
            
            # 断开连接
            try:
                disconnect_cmd = f'"{script_dir}\\force_disconnect.bat"'
                subprocess.Popen(disconnect_cmd, shell=True)
                logging.info(f"已执行断开连接命令：{disconnect_cmd}")
            except Exception as e:
                logging.error(f"断开连接失败: {e}")
            
            return "黑名单拒绝"
        
        # 保存验证结果到文件
        pin_result_file = os.path.join(log_dir, 'pin_verification_result.txt')
        
        # 移除对旧验证结果的复用，确保每次都重新验证
        if os.path.exists(pin_result_file):
            try:
                # 删除旧的验证结果文件，确保获取最新结果
                os.remove(pin_result_file)
                logging.info("删除旧的验证结果文件，将进行新的验证")
            except Exception as e:
                logging.error(f"删除旧验证结果文件失败: {e}")
                # 继续进行验证
        
        # 关键修复：确保验证历史记录文件为空，强制每次都进行新的验证
        try:
            verification_history_file = os.path.join(script_dir, "data", "verification_history.json")
            if os.path.exists(verification_history_file):
                with open(verification_history_file, 'w', encoding='utf-8') as f:
                    json.dump({}, f)
                logging.info("已清空验证历史记录，确保进行新的验证")
        except Exception as e:
            logging.error(f"清空验证历史记录失败: {e}")
        
        # 同样清空RDP事件记录文件
        clear_rdp_events_file()
        
        # 使用Python脚本显示PIN码验证对话框并等待结果
        # 修改为使用rdp_monitor.py的验证功能
        cmd = f'python "{script_dir}\\rdp_monitor.py" --verify-pin-only'
        
        logging.info(f"启动PIN验证进程: {cmd}")
        process = subprocess.Popen(cmd, shell=True)
        
        # 等待最多30秒检查验证结果
        max_wait_time = 30
        wait_interval = 1
        total_waited = 0
        
        while total_waited < max_wait_time:
            if os.path.exists(pin_result_file):
                # 读取验证结果
                try:
                    with open(pin_result_file, 'r') as f:
                        result = f.read().strip()
                    logging.info(f"PIN验证结果: {result}")
                    
                    # 确保在读取结果后，进程有足够时间退出
                    if result in ["失败", "断开"]:
                        logging.info(f"检测到验证失败或断开，等待1秒确保处理完成")
                        time.sleep(1)
                    
                    return result
                except Exception as e:
                    logging.error(f"读取PIN验证结果失败: {e}")
                    break
            
            time.sleep(wait_interval)
            total_waited += wait_interval
            
            # 检查进程是否仍在运行
            if process.poll() is not None:
                logging.info(f"PIN验证进程已退出，返回值: {process.returncode}")
                # 如果进程已退出但没有结果文件，再等待一秒
                if not os.path.exists(pin_result_file):
                    logging.warning("进程已退出但未找到结果文件，等待1秒")
                    time.sleep(1)
                    if os.path.exists(pin_result_file):
                        with open(pin_result_file, 'r') as f:
                            result = f.read().strip()
                        logging.info(f"延迟读取到PIN验证结果: {result}")
                        return result
        
        logging.warning(f"等待PIN验证结果超时")
        return "超时"
    except Exception as e:
        logging.error(f"显示PIN码对话框失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return "错误"

def main():
    """主函数"""
    try:
        logging.info("RDP登录触发器启动")
        
        # 处理命令行参数
        verify_pin_only = False
        for arg in sys.argv:
            if arg == "--verify-pin":
                verify_pin_only = True
                logging.info("检测到--verify-pin参数，将只进行PIN验证")
        
        # 记录触发时间和基本信息
        connection_info = get_connection_info()
        logging.info(f"检测到RDP连接: IP={connection_info.get('client_ip', 'unknown')}, 用户={connection_info.get('username', 'unknown')}")
        
        # 延迟一秒，确保信息记录完成
        time.sleep(1)
        
        # 显示PIN码验证对话框并获取验证结果
        verification_result = show_pin_dialog()
        logging.info(f"PIN验证结果: {verification_result}")
        
        # 在连接信息中添加验证结果
        if verification_result:
            connection_info["verification_result"] = verification_result
        else:
            # 如果没有PIN验证逻辑或验证被跳过
            connection_info["verification_result"] = "外部脚本触发"
        
        # 关键修复：确保对任何验证结果都发送通知，包括失败和断开
        # 发送通知
        send_notification_with_verification(connection_info)
        
        logging.info("RDP登录触发器执行完成")
        
    except Exception as e:
        logging.error(f"触发器执行失败: {e}")
        import traceback
        logging.error(traceback.format_exc())

def is_ip_in_whitelist(ip, config):
    """检查IP是否在白名单中"""
    if ip == "unknown":
        return False
    
    # 首先读取白名单文件
    whitelist_path = config.get("ip_whitelistfile", "data/ip_whitelist.txt")
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(whitelist_path):
        whitelist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), whitelist_path)
    
    whitelist_from_file = []
    # 如果白名单文件存在，读取内容
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        whitelist_from_file.append(line)
            logging.debug(f"已加载白名单文件 {whitelist_path}，包含 {len(whitelist_from_file)} 个条目")
        except Exception as e:
            logging.error(f"读取白名单文件失败: {e}")
    
    # 精确匹配白名单文件
    if ip in whitelist_from_file:
        logging.info(f"IP {ip} 在白名单文件中")
        return True
    
    # CIDR匹配白名单文件
    try:
        import ipaddress
        ip_obj = ipaddress.ip_address(ip)
        
        for item in whitelist_from_file:
            if '/' in item:  # CIDR格式
                try:
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        logging.info(f"IP {ip} 匹配白名单文件CIDR规则: {item}")
                        return True
                except Exception as e:
                    logging.error(f"检查白名单文件CIDR规则 {item} 时出错: {e}")
    except Exception as e:
        logging.error(f"检查IP {ip} 是否在白名单文件中时发生错误: {e}")
    
    # 从配置中获取白名单列表
    whitelist_str = config.get("ip_whitelist", "")
    
    # 如果是字符串格式，转换为列表
    if isinstance(whitelist_str, str):
        whitelist = [x.strip() for x in whitelist_str.split(",") if x.strip()]
    else:
        # 兼容旧格式的数组
        whitelist = whitelist_str if isinstance(whitelist_str, list) else []
    
    # 检查IP是否在白名单中
    for whitelist_item in whitelist:
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

def get_ip_location(ip):
    """查询IP地址的地理位置信息(中文)"""
    if is_private_ip(ip):
        logging.info(f"IP {ip} 是内网IP，跳过地理位置查询")
        return None
        
    try:
        # 记录开始查询
        logging.info(f"开始查询IP {ip} 的地理位置信息")
        
        # 使用ipinfo.io API (无需API密钥的基础查询)
        url = f"https://ipinfo.io/{ip}/json"
        logging.info(f"尝试使用ipinfo.io API: {url}")
        
        # 设置超时时间，避免长时间等待导致阻塞
        response = requests.get(url, timeout=5)
        
        # 检查请求是否成功
        if response.status_code == 200:
            data = response.json()
            logging.info(f"ipinfo.io API响应数据: {data}")
            
            # 从结果中提取城市和国家信息
            city = data.get("city", "")
            country_code = data.get("country", "")
            region = data.get("region", "")
            
            # 国家代码转中文名称的映射
            country_map = {
                "CN": "中国", "US": "美国", "JP": "日本", "KR": "韩国", "DE": "德国",
                "FR": "法国", "GB": "英国", "RU": "俄罗斯", "CA": "加拿大", "AU": "澳大利亚",
                "IN": "印度", "BR": "巴西", "SG": "新加坡", "MY": "马来西亚", "TH": "泰国",
                "VN": "越南", "ID": "印度尼西亚", "PH": "菲律宾", "NZ": "新西兰", "HK": "香港",
                "TW": "台湾", "MO": "澳门"
            }
            
            # 转换国家代码为中文名称
            country = country_map.get(country_code, country_code)
            
            # 组合位置信息
            location_parts = []
            if country:
                location_parts.append(country)
            if region:
                location_parts.append(region)
            if city:
                location_parts.append(city)
                
            if location_parts:
                location = " ".join(location_parts)
                logging.info(f"成功获取到IP地理位置: {location}")
                return location
            else:
                logging.warning("ipinfo.io API响应中未找到地理位置信息")
        else:
            logging.warning(f"ipinfo.io API请求失败: HTTP {response.status_code}")
        
        # 备用方案：使用ip-api.com的接口
        try:
            backup_url = f"http://ip-api.com/json/{ip}?lang=zh-CN"
            logging.info(f"尝试使用备用API: {backup_url}")
            response = requests.get(backup_url, timeout=3)
            
            if response.status_code == 200:
                data = response.json()
                logging.info(f"备用API响应数据: {data}")
                
                if data.get("status") == "success":
                    location_parts = []
                    country = data.get("country", "")
                    regionName = data.get("regionName", "")
                    city = data.get("city", "")
                    
                    if country:
                        location_parts.append(country)
                    if regionName:
                        location_parts.append(regionName)
                    if city:
                        location_parts.append(city)
                        
                    if location_parts:
                        location = " ".join(location_parts)
                        logging.info(f"备用API成功获取IP地理位置: {location}")
                        return location
        except Exception as e:
            logging.error(f"备用API请求失败: {e}")
        
        logging.warning(f"所有API尝试均失败，无法获取IP {ip} 的地理位置")
        return None
    except Exception as e:
        logging.error(f"获取IP地理位置失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return None

def send_notification_with_verification(connection_info):
    """发送包含验证结果的RDP登录通知"""
    try:
        # 加载配置
        config = load_config()
        sckey = config.get("sckey", "")
        
        # 如果sckey为空，不发送通知
        if not sckey:
            logging.info("SCKEY为空，跳过发送通知")
            return False
        
        notification_url = config.get("notification_url", "")
        
        client_ip = connection_info.get("client_ip", "unknown")
        verification_result = connection_info.get("verification_result", "外部脚本触发")
        username = connection_info.get('username', 'unknown')
        event_time = connection_info.get('event_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        hostname = connection_info.get('hostname', socket.gethostname())
        
        # 确定IP类型
        ip_type = "外网IP"
        try:
            if is_private_ip(client_ip):
                ip_type = "内网IP"
                logging.info(f"IP {client_ip} 被识别为内网IP")
            else:
                logging.info(f"IP {client_ip} 被识别为外网IP")
        except Exception as e:
            logging.error(f"判断IP类型时出错: {e}")
            pass
            
        # 获取IP地理位置信息
        ip_location = None
        source_info = ""
        
        if ip_type == "外网IP":
            # 查询IP地理位置信息
            logging.info(f"开始查询外网IP {client_ip} 的地理位置")
            ip_location = get_ip_location(client_ip)
            
            if ip_location:
                logging.info(f"成功获取到IP {client_ip} 的地理位置: {ip_location}")
                source_info = f"{client_ip} ({ip_location})"
            else:
                logging.warning(f"未能获取到IP {client_ip} 的地理位置，使用默认标记")
                source_info = f"{client_ip} ({ip_type})"
        else:
            logging.info(f"内网IP {client_ip} 不查询地理位置")
            source_info = f"{client_ip} (内网)"
        
        logging.info(f"最终标记的来源信息: {source_info}")
            
        # 检查是否为白名单免验证情况
        is_whitelist_bypass = "白名单免验证" in verification_result or verification_result == "白名单免验证"
        force_notification = connection_info.get("force_notification", False)
        
        # 白名单IP且是免验证情况下不发送通知，除非强制通知
        if is_ip_in_whitelist(client_ip, config) and is_whitelist_bypass and not force_notification:
            logging.info(f"IP {client_ip} 白名单通过不发送通知")
            return False
        
        # 检查IP是否在白名单中，只有不在白名单中的IP才发送通知
        # 或者其他非"白名单免验证"状态（如验证成功/失败等）需要发送通知
        if not is_ip_in_whitelist(client_ip, config) or (not is_whitelist_bypass) or force_notification:
            # 美化验证结果
            if verification_result == "成功":
                result_text = "✓ 验证通过"
                status_message = "验证已通过，允许连接"
            elif verification_result == "失败":
                result_text = "✗ 验证失败"
                status_message = "验证失败，已强制断开连接"
            elif verification_result == "断开":
                result_text = "用户断开"
                status_message = "用户主动断开连接"
            elif verification_result == "超时":
                result_text = "验证超时"
                status_message = "验证超时，已强制断开连接"
            else:
                result_text = verification_result
                status_message = "请检查连接状态"
                
            # 获取验证时间（如果有）
            verification_time = connection_info.get("verification_time", "未知")
            if verification_time != "未知":
                verification_time = f"{verification_time}秒"

            # 构建简化的Markdown格式消息内容，每个主要项目之间添加空行
            formatted_message = f"""
## RDP验证结果

**时间**：{event_time}

**用户**：**{username}**

**来源**：{source_info}

**主机**：{hostname}

**验证详情**：
- 验证状态：**{result_text}**
- 验证时间：{verification_time}

> {status_message}
"""
            
            # 构建标题，加入验证结果
            title = 'Windows远程登录'
            if verification_result == "成功":
                title += " (验证通过)"
            elif verification_result == "失败":
                title += " (验证失败)"
            elif verification_result == "断开":
                title += " (用户断开)"
            elif verification_result == "超时":
                title += " (验证超时)"
            elif verification_result == "错误":
                title += " (验证错误)"
            else:
                title += f" ({verification_result})"
            
            # 构建推送参数
            params = {
                'title': title,
                'desp': formatted_message
            }
            
            # 检查notification_url中是否包含{sckey}占位符，并替换
            if notification_url and "{sckey}" in notification_url:
                notification_url = notification_url.replace("{sckey}", sckey)
                logging.info(f"替换notification_url中的{sckey}占位符")
            else:
                # 如果没有notification_url或没有占位符，使用默认URL
                push_url = f'https://sctapi.ftqq.com/{sckey}.send'
                if not notification_url:
                    notification_url = push_url
                    logging.info(f"使用默认推送URL: {push_url}")
            
            # 使用POST请求发送推送
            logging.info(f"发送通知到: {notification_url}")
            response = requests.post(notification_url, data=params, timeout=10)
            
            # 记录推送结果
            if response.status_code == 200:
                logging.info(f"推送成功: {response.text[:100]}")
                # 检查是否存在标志文件(防止重复通知)
                flag_file = os.path.join(log_dir, 'notification_sent.flag')
                with open(flag_file, 'w') as f:
                    f.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                return True
            else:
                logging.error(f"推送失败: {response.status_code}, {response.text[:100]}")
                return False
        else:
            logging.info(f"IP {client_ip} 在白名单中且状态为免验证，跳过通知")
            return False
    except Exception as e:
        logging.error(f"发送通知失败: {e}")
        import traceback
        logging.error(f"详细错误: {traceback.format_exc()}")
        return False

# 新增清理rdp_events.json的函数
def clear_rdp_events_file():
    """清空RDP事件记录文件，确保不会保留旧的验证状态"""
    try:
        # 使用绝对路径
        data_dir = os.path.join(script_dir, 'data')
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