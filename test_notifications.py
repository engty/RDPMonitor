#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
RDP通知测试脚本
用于测试各种类型的通知推送功能
"""

import sys
import logging
import socket
import os
from datetime import datetime, timedelta
from rdp_monitor import RDPMonitor, setup_logging

def setup_test_environment():
    """设置测试环境"""
    # 配置日志
    setup_logging(debug_mode=True)
    logging.info("开始通知测试...")
    
    # 创建必要的目录
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, 'data')
    
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
        logging.info(f"创建数据目录: {data_dir}")
    
    return base_dir

def test_regular_notification(rdp_monitor):
    """测试普通RDP登录通知"""
    logging.info("测试普通RDP登录通知...")
    
    event_data = {
        "event_id": 4624,
        "event_type": "登录成功",
        "username": "test_user",
        "client_ip": "8.8.8.8",  # 外网IP
        "hostname": socket.gethostname(),
        "event_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "raw_data": "登录类型: 3\n安全ID: S-1-5-21...",
        "force_notification": True  # 强制发送通知
    }
    
    success = rdp_monitor.send_notification(event_data)
    logging.info(f"普通登录通知发送{'成功' if success else '失败'}")
    return success

def test_verification_notification(rdp_monitor):
    """测试验证结果通知"""
    logging.info("测试验证成功通知...")
    
    event_data = {
        "event_id": 4624,
        "event_type": "登录验证成功",
        "username": "test_user",
        "client_ip": "8.8.8.8",  # 外网IP
        "hostname": socket.gethostname(),
        "event_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "raw_data": "登录类型: 3\n安全ID: S-1-5-21...",
        "verification_result": "成功",
        "force_notification": True  # 强制发送通知
    }
    
    success = rdp_monitor.send_notification(event_data)
    logging.info(f"验证成功通知发送{'成功' if success else '失败'}")
    
    logging.info("测试验证失败通知...")
    event_data["verification_result"] = "失败"
    event_data["event_type"] = "登录验证失败"
    
    success = rdp_monitor.send_notification(event_data)
    logging.info(f"验证失败通知发送{'成功' if success else '失败'}")
    return success

def test_blacklist_notification(rdp_monitor):
    """测试黑名单IP尝试登录通知"""
    logging.info("测试黑名单IP尝试登录通知...")
    
    # 测试IP地址
    ip_address = "192.168.1.100"
    
    # 创建尝试详情
    attempt_details = {
        "first_attempt": (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S'),
        "last_attempt": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "count": 5
    }
    
    success = rdp_monitor.send_blacklist_notification(ip_address, attempt_details)
    logging.info(f"黑名单IP尝试登录通知发送{'成功' if success else '失败'}")
    return success

def test_failed_attempts_notification(rdp_monitor):
    """测试登录失败尝试通知"""
    logging.info("测试登录失败尝试通知...")
    
    # 测试IP地址
    ip_address = "192.168.1.101"
    
    # 失败尝试次数和最大允许次数
    failed_attempts = 2
    max_attempts = 3
    
    # 尝试时间
    first_attempt_time = (datetime.now() - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
    last_attempt_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    success = rdp_monitor.send_failed_attempts_notification(
        ip_address, 
        failed_attempts, 
        max_attempts,
        first_attempt_time,
        last_attempt_time
    )
    logging.info(f"登录失败尝试通知发送{'成功' if success else '失败'}")
    return success

def main():
    """主函数"""
    # 设置测试环境
    base_dir = setup_test_environment()
    
    # 创建RDPMonitor实例
    # 注意：需要有有效的SCKEY，否则通知会失败
    rdp_monitor = RDPMonitor()
    
    # 记录测试结果
    results = {}
    
    # 测试普通登录通知
    results["普通登录通知"] = test_regular_notification(rdp_monitor)
    
    # 测试验证结果通知
    results["验证结果通知"] = test_verification_notification(rdp_monitor)
    
    # 测试黑名单IP尝试登录通知
    results["黑名单IP通知"] = test_blacklist_notification(rdp_monitor)
    
    # 测试登录失败尝试通知
    results["登录失败通知"] = test_failed_attempts_notification(rdp_monitor)
    
    # 打印测试结果摘要
    logging.info("==== 通知测试结果摘要 ====")
    for name, success in results.items():
        status = "✅ 成功" if success else "❌ 失败"
        logging.info(f"{name}: {status}")
    
    success_count = sum(1 for status in results.values() if status)
    logging.info(f"总计: {success_count}/{len(results)} 成功")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 