#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
RDP通知测试工具
简单的命令行工具，用于测试各种类型的通知
"""

import sys
import argparse
import socket
import os
from datetime import datetime, timedelta
from rdp_monitor import RDPMonitor, setup_logging

def test_regular_notification(rdp_monitor):
    """测试普通RDP登录通知"""
    print("发送普通RDP登录通知...")
    
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
    return success

def test_verification_success(rdp_monitor):
    """测试验证成功通知"""
    print("发送验证成功通知...")
    
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
    return success

def test_verification_failed(rdp_monitor):
    """测试验证失败通知"""
    print("发送验证失败通知...")
    
    event_data = {
        "event_id": 4624,
        "event_type": "登录验证失败",
        "username": "test_user",
        "client_ip": "8.8.8.8",  # 外网IP
        "hostname": socket.gethostname(),
        "event_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "raw_data": "登录类型: 3\n安全ID: S-1-5-21...",
        "verification_result": "失败",
        "force_notification": True  # 强制发送通知
    }
    
    success = rdp_monitor.send_notification(event_data)
    return success

def test_blacklist_notification(rdp_monitor):
    """测试黑名单IP尝试登录通知"""
    print("发送黑名单IP尝试登录通知...")
    
    # 测试IP地址
    ip_address = "192.168.1.100"
    
    # 创建尝试详情
    attempt_details = {
        "first_attempt": (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S'),
        "last_attempt": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "count": 5
    }
    
    success = rdp_monitor.send_blacklist_notification(ip_address, attempt_details)
    return success

def test_failed_attempts_notification(rdp_monitor):
    """测试登录失败尝试通知"""
    print("发送登录失败尝试通知...")
    
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
    return success

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='测试RDP通知推送功能')
    parser.add_argument('-a', '--all', action='store_true', help='测试所有类型的通知')
    parser.add_argument('-r', '--regular', action='store_true', help='测试普通登录通知')
    parser.add_argument('-s', '--success', action='store_true', help='测试验证成功通知')
    parser.add_argument('-f', '--failed', action='store_true', help='测试验证失败通知')
    parser.add_argument('-b', '--blacklist', action='store_true', help='测试黑名单IP通知')
    parser.add_argument('-m', '--multiple', action='store_true', help='测试多次失败尝试通知')
    parser.add_argument('-d', '--debug', action='store_true', help='启用调试模式')
    
    args = parser.parse_args()
    
    # 如果没有参数，显示帮助
    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    # 设置日志
    setup_logging(debug_mode=args.debug)
    
    # 创建RDPMonitor实例
    rdp_monitor = RDPMonitor()
    
    # 存储测试结果
    results = {}
    
    # 根据参数执行测试
    if args.all or args.regular:
        results["普通登录通知"] = test_regular_notification(rdp_monitor)
    
    if args.all or args.success:
        results["验证成功通知"] = test_verification_success(rdp_monitor)
    
    if args.all or args.failed:
        results["验证失败通知"] = test_verification_failed(rdp_monitor)
    
    if args.all or args.blacklist:
        results["黑名单IP通知"] = test_blacklist_notification(rdp_monitor)
    
    if args.all or args.multiple:
        results["多次失败尝试通知"] = test_failed_attempts_notification(rdp_monitor)
    
    # 打印测试结果摘要
    print("\n==== 通知测试结果摘要 ====")
    for name, success in results.items():
        status = "✅ 成功" if success else "❌ 失败"
        print(f"{name}: {status}")
    
    success_count = sum(1 for status in results.values() if status)
    print(f"总计: {success_count}/{len(results)} 成功")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 