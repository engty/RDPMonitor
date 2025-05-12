#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import json
import logging
import requests
from datetime import datetime
import socket

# 设置日志
def setup_logging():
    # 确保日志目录存在
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    # 创建日志文件
    log_file = os.path.join(log_dir, 'notification_debug.log')
    
    # 配置日志记录器
    logger = logging.getLogger('notification_debug')
    logger.setLevel(logging.DEBUG)
    
    # 清除已有处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # 创建文件处理器
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

def load_config():
    """加载配置"""
    # 使用绝对路径
    current_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 确保config目录存在
    config_dir = os.path.join(current_dir, 'config')
    if not os.path.exists(config_dir):
        os.makedirs(config_dir)
    
    config_file = os.path.join(config_dir, "config.json")
    default_config = {
        "notification_url": "",
        "sckey": "SCT193132TFWL7mLnu8pqgKDBERSDN2RSp",  # 默认SCKEY
        "pin_code": "1187",  # 默认PIN码
        "rdp_port": 3389     # 默认RDP端口
    }
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载配置文件失败: {e}")
    
    return default_config

def send_test_notification(logger, verification_result=None):
    config = load_config()
    sckey = config.get("sckey", "SCT193132TFWL7mLnu8pqgKDBERSDN2RSp")
    
    # 测试消息
    push_data = {
        "event": "rdp_login",
        "status": "success", 
        "time": datetime.now().isoformat(),
        "username": "test_user",
        "ip": "8.8.8.8",
        "system": socket.gethostname(),
        "message": "RDP监控调试推送",
        "verification_result": verification_result
    }
    
    # 构建推送消息
    event_time = push_data.get("time", "")
    verification_result = push_data.get("verification_result", "无需验证")
    
    # 按照用户指定的格式构建简单的推送内容
    simple_message = f"调试通知 - 模拟外网登录\n"
    simple_message += f"主机：{socket.gethostname()}\n"
    simple_message += f"登陆者IP: {push_data.get('ip', '')}\n"
    simple_message += f"用户: {push_data.get('username', '未知')}\n"
    simple_message += f"时间：{event_time}\n"
    simple_message += f"验证状态: {verification_result if verification_result else '无需验证'}"
    
    # 构建参数，避免URL长度问题
    title = f"Windows远程登录 - {push_data.get('event_type', '调试测试')}"
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
    push_url = f'https://sctapi.ftqq.com/{sckey}.send'
    
    try:
        # 使用POST请求
        logger.info(f"发送通知到: {push_url}")
        logger.info(f"通知内容: 标题={title}, 验证状态={verification_result}")
        logger.info(f"完整通知内容: {simple_message}")
        
        response = requests.post(
            push_url,
            data=params,
            timeout=10
        )
        
        logger.info(f"通知已发送，状态码: {response.status_code}")
        if response.status_code == 200:
            logger.info(f"推送成功！响应: {response.text}")
            return True
        else:
            logger.error(f"推送失败，状态码: {response.status_code}, 响应: {response.text}")
            return False
    except Exception as e:
        logger.error(f"发送通知失败: {e}")
        import traceback
        logger.error(f"详细错误: {traceback.format_exc()}")
        return False

if __name__ == "__main__":
    logger = setup_logging()
    logger.info("======= 开始调试通知发送 =======")
    
    # 测试不同验证状态的通知
    status_options = ["成功", "失败", "无需验证", None]
    
    for status in status_options:
        logger.info(f"测试发送验证状态: {status}")
        success = send_test_notification(logger, status)
        logger.info(f"发送结果: {'成功' if success else '失败'}")
        
    logger.info("======= 调试通知发送完成 =======") 