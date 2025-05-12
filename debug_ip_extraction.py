#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RDP监控系统IP提取和白名单黑名单功能调试脚本
"""

import os
import sys
import json
import logging
import subprocess
import re
import socket
from datetime import datetime, timedelta

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

def load_config():
    """加载配置文件"""
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'config.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"加载配置文件失败: {e}")
            return {}
    else:
        logging.error(f"配置文件不存在: {config_path}")
        return {}

def load_ip_whitelist():
    """加载IP白名单列表"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 从配置文件获取白名单文件路径
    config = load_config()
    whitelist_path = config.get("ip_whitelistfile", "data/ip_whitelist.txt")
    
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(whitelist_path):
        whitelist_path = os.path.join(current_dir, whitelist_path)
    
    whitelist = []
    
    # 如果白名单文件存在，读取内容
    if os.path.exists(whitelist_path):
        try:
            with open(whitelist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        whitelist.append(line)
            logging.info(f"已加载白名单文件 {whitelist_path}，包含 {len(whitelist)} 个条目")
        except Exception as e:
            logging.error(f"读取白名单文件失败: {e}")
    else:
        logging.error(f"白名单文件不存在: {whitelist_path}")
    
    return whitelist

def load_ip_blacklist():
    """加载IP黑名单列表"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 从配置文件获取黑名单文件路径
    config = load_config()
    blacklist_path = config.get("ip_blacklistfile", "data/ip_blacklist.txt")
    
    # 如果路径是相对路径，转换为绝对路径
    if not os.path.isabs(blacklist_path):
        blacklist_path = os.path.join(current_dir, blacklist_path)
    
    blacklist = []
    
    # 如果黑名单文件存在，读取内容
    if os.path.exists(blacklist_path):
        try:
            with open(blacklist_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        blacklist.append(line)
            logging.info(f"已加载黑名单文件 {blacklist_path}，包含 {len(blacklist)} 个条目")
        except Exception as e:
            logging.error(f"读取黑名单文件失败: {e}")
    else:
        logging.error(f"黑名单文件不存在: {blacklist_path}")
    
    return blacklist

def is_ip_in_whitelist(ip, config):
    """检查IP是否在白名单中"""
    if ip == "unknown":
        logging.info("IP为unknown，不在白名单中")
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
    
    logging.info(f"IP {ip} 不在任何白名单中")
    return False

def is_ip_in_blacklist(ip, config):
    """检查IP是否在黑名单中"""
    if not ip:
        logging.info("IP为空，不在黑名单中")
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
    
    logging.info(f"IP {ip} 不在黑名单中")
    return False

def extract_client_ip():
    """提取当前RDP连接的客户端IP"""
    config = load_config()
    rdp_port = config.get("rdp_port", 3389)
    client_ip = None
    
    # 方法1: 使用netstat命令获取当前RDP连接
    try:
        # 执行netstat命令
        result = subprocess.run(['netstat', '-n'], capture_output=True, text=True)
        
        # 检查命令是否成功执行
        if result.returncode == 0:
            # 查找ESTABLISHED状态的RDP连接
            for line in result.stdout.splitlines():
                # 检查是否包含RDP端口且状态为ESTABLISHED
                if f':{rdp_port}' in line and 'ESTABLISHED' in line:
                    logging.info(f"发现RDP连接: {line}")
                    
                    # 提取远程IP地址
                    pattern = r'TCP\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+'
                    match = re.search(pattern, line)
                    
                    if match:
                        # 提取匹配的IP地址
                        ip = match.group(1)
                        if not ip.startswith('127.') and not ip.startswith('0.'):
                            logging.info(f"从netstat找到客户端IP: {ip}")
                            client_ip = ip
                            break
    except Exception as e:
        logging.error(f"使用netstat获取RDP连接失败: {e}")
    
    # 方法2: 从message.log文件中提取IP
    if not client_ip:
        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        message_file = os.path.join(logs_dir, 'message.log')
        if os.path.exists(message_file):
            try:
                with open(message_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # 使用正则表达式查找IP地址
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
                
                logging.info(f"找到的所有IP: {all_ips}")
                logging.info(f"过滤后的IP: {filtered_ips}")
                
                # 如果找到了有效IP，使用第一个
                if filtered_ips:
                    client_ip = filtered_ips[0]
                    logging.info(f"从message.log找到客户端IP: {client_ip}")
            except Exception as e:
                logging.error(f"从message.log读取IP失败: {e}")
    
    # 方法3: 从rdp_trigger.log中获取IP
    if not client_ip:
        logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
        trigger_log = os.path.join(logs_dir, 'rdp_trigger.log')
        if os.path.exists(trigger_log):
            try:
                with open(trigger_log, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()
                    # 查找"检测到RDP连接: IP="后面的IP地址
                    ip_match = re.search(r'检测到RDP连接: IP=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', log_content)
                    if ip_match:
                        client_ip = ip_match.group(1)
                        logging.info(f"从rdp_trigger.log找到客户端IP: {client_ip}")
            except Exception as e:
                logging.error(f"读取rdp_trigger.log失败: {e}")
    
    return client_ip

def load_failed_attempts():
    """加载失败尝试记录"""
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    attempts_file = os.path.join(data_dir, "failed_attempts.json")
    
    if os.path.exists(attempts_file):
        try:
            with open(attempts_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    logging.warning(f"失败尝试记录文件为空: {attempts_file}")
                    return {}
                else:
                    return json.loads(content)
        except Exception as e:
            logging.error(f"读取失败尝试记录文件失败: {e}")
            return {}
    else:
        logging.warning(f"失败尝试记录文件不存在: {attempts_file}")
        return {}

def main():
    """主函数"""
    logging.info("开始测试IP提取和白名单黑名单功能")
    
    # 测试1: 提取当前RDP连接的客户端IP
    client_ip = extract_client_ip()
    logging.info(f"测试1 - 提取的客户端IP: {client_ip if client_ip else '未找到IP'}")
    
    # 加载配置
    config = load_config()
    logging.info(f"加载的配置: {config}")
    
    # 测试2: 检查IP白名单和黑名单
    if client_ip:
        # 先检查白名单
        is_white = is_ip_in_whitelist(client_ip, config)
        logging.info(f"测试2 - IP {client_ip} 是否在白名单中: {is_white}")
        
        # 再检查黑名单
        is_black = is_ip_in_blacklist(client_ip, config)
        logging.info(f"测试2 - IP {client_ip} 是否在黑名单中: {is_black}")
        
        # 加载失败尝试记录
        failed_attempts = load_failed_attempts()
        logging.info(f"失败尝试记录: {failed_attempts}")
        
        # 检查客户端IP是否在失败尝试记录中
        if client_ip in failed_attempts:
            attempt_info = failed_attempts[client_ip]
            logging.info(f"IP {client_ip} 在失败尝试记录中，次数: {attempt_info.get('count', 0)}，过期时间: {attempt_info.get('expiry', 'N/A')}")
        else:
            logging.info(f"IP {client_ip} 不在失败尝试记录中")
    else:
        logging.warning("未能提取到客户端IP，跳过白名单黑名单检查")
    
    # 测试3: 检查指定IP是否在白名单和黑名单中
    test_ips = ["14.19.152.205", "192.168.1.9"]
    for test_ip in test_ips:
        is_white = is_ip_in_whitelist(test_ip, config)
        logging.info(f"测试3 - IP {test_ip} 是否在白名单中: {is_white}")
        
        is_black = is_ip_in_blacklist(test_ip, config)
        logging.info(f"测试3 - IP {test_ip} 是否在黑名单中: {is_black}")
        
        # 检查测试IP是否在失败尝试记录中
        if test_ip in failed_attempts:
            attempt_info = failed_attempts[test_ip]
            logging.info(f"IP {test_ip} 在失败尝试记录中，次数: {attempt_info.get('count', 0)}，过期时间: {attempt_info.get('expiry', 'N/A')}")
        else:
            logging.info(f"IP {test_ip} 不在失败尝试记录中")
    
    logging.info("IP提取和白名单黑名单功能测试完成")

if __name__ == "__main__":
    main() 