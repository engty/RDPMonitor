import os
import sys
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import logging
import time
from pathlib import Path
from logging.handlers import TimedRotatingFileHandler

# 添加当前目录到系统路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 导入RDP监控模块
import rdp_monitor

# 查找日志配置相关代码
def configure_logging() -> logging.Logger:
    """配置服务日志
    
    Returns:
        logging.Logger: 配置好的日志记录器
    """
    # 确保日志目录存在
    base_dir = os.path.dirname(os.path.abspath(__file__))
    log_dir = os.path.join(base_dir, 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
        
    # 使用统一的日志命名格式，与rdp_monitor.py保持一致
    log_file = os.path.join(log_dir, 'rdp_monitor_service.log')
    
    # 创建按天滚动的日志处理器
    handler = TimedRotatingFileHandler(
        log_file,
        when='midnight',
        interval=1,
        backupCount=90,  # 保留90天
        encoding='utf-8'
    )
    
    # 统一的日志格式
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # 清除现有处理器
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        
    logger.addHandler(handler)
    
    # 删除超过90天的老日志文件
    try:
        rdp_monitor.clean_old_logs(log_dir, 90)
    except Exception as e:
        logger.error(f"清理旧日志文件失败: {e}")
    
    return logger

class RDPMonitorService(win32serviceutil.ServiceFramework):
    """Windows服务：RDP登录监控"""
    
    _svc_name_ = "RDPMonitor"
    _svc_display_name_ = "RDP登录监控服务"
    _svc_description_ = "监控远程桌面登录事件并发送通知"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.is_running = False
        
        # 设置日志文件路径为程序所在目录
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 配置日志
        self.logger = configure_logging()

    def SvcStop(self):
        """停止服务"""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.is_running = False
        self.logger.info('服务停止')

    def SvcDoRun(self):
        """运行服务"""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.is_running = True
        self.main()

    def main(self):
        """主要服务逻辑"""
        self.logger.info('服务启动')
        
        # 切换到服务所在目录
        os.chdir(self.base_dir)
        
        try:
            # 加载配置
            config = rdp_monitor.load_config()
            notification_url = config.get("notification_url", "")
            sckey = config.get("sckey", "")
            pin_code = config.get("pin_code", "")
            
            # 创建监控实例，传递所有必要参数
            monitor = rdp_monitor.RDPMonitor(notification_url, sckey, pin_code)
            
            # 在单独的线程中启动监控，以便可以正常响应停止请求
            import threading
            monitor_thread = threading.Thread(target=monitor.monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            # 保持服务运行，直到收到停止请求
            while self.is_running:
                # 检查是否有停止请求
                rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
                
                time.sleep(1)
                
        except Exception as e:
            self.logger.error(f"服务运行中发生错误: {e}")
            import traceback
            self.logger.error(f"详细错误: {traceback.format_exc()}")
            servicemanager.LogErrorMsg(f"服务错误: {str(e)}")

def install_service() -> bool:
    """安装Windows服务
    
    Returns:
        bool: 安装成功返回True，失败返回False
    """
    try:
        # 获取当前脚本的完整路径
        script_path = os.path.abspath(__file__)
        
        # 如果服务已经存在，先移除
        try:
            win32serviceutil.RemoveService(RDPMonitorService._svc_name_)
            print(f"已移除现有服务: {RDPMonitorService._svc_name_}")
        except:
            pass
        
        # 安装新服务
        win32serviceutil.InstallService(
            pythonClassString=f"{os.path.basename(__file__).split('.')[0]}.RDPMonitorService",
            serviceName=RDPMonitorService._svc_name_,
            displayName=RDPMonitorService._svc_display_name_,
            description=RDPMonitorService._svc_description_,
            startType=win32service.SERVICE_AUTO_START
        )
        print(f"服务安装成功: {RDPMonitorService._svc_display_name_}")
        print("您可以在Windows服务管理器中启动该服务")
        return True
    except Exception as e:
        print(f"服务安装失败: {e}")
        return False

def uninstall_service() -> bool:
    """卸载Windows服务
    
    Returns:
        bool: 卸载成功返回True，失败返回False
    """
    try:
        win32serviceutil.RemoveService(RDPMonitorService._svc_name_)
        print(f"服务卸载成功: {RDPMonitorService._svc_name_}")
        return True
    except Exception as e:
        print(f"服务卸载失败: {e}")
        return False

def update_notification_url() -> bool:
    """更新通知URL
    
    Returns:
        bool: 更新成功返回True，失败返回False
    """
    url = input("请输入通知URL: ")
    if rdp_monitor.update_notification_url(url):
        print(f"通知URL已更新为: {url}")
        return True
    else:
        print("通知URL更新失败")
        return False

def update_sckey() -> bool:
    """更新Server酱SCKEY
    
    Returns:
        bool: 更新成功返回True，失败返回False
    """
    sckey = input("请输入Server酱SCKEY: ")
    if rdp_monitor.update_sckey(sckey):
        print(f"SCKEY已更新")
        return True
    else:
        print("SCKEY更新失败")
        return False
        
def update_pin_code() -> bool:
    """更新PIN码
    
    Returns:
        bool: 更新成功返回True，失败返回False
    """
    pin = input("请输入登录验证PIN码: ")
    if rdp_monitor.update_pin_code(pin):
        print(f"PIN码已更新")
        return True
    else:
        print("PIN码更新失败")
        return False
        
def update_rdp_port() -> bool:
    """更新RDP端口
    
    Returns:
        bool: 更新成功返回True，失败返回False
    """
    try:
        port = int(input("请输入RDP端口 (默认3389): "))
        if port <= 0 or port > 65535:
            print("端口号必须在1-65535之间")
            return False
            
        if rdp_monitor.update_rdp_port(port):
            print(f"RDP端口已更新为: {port}")
            return True
        else:
            print("RDP端口更新失败")
            return False
    except ValueError:
        print("请输入有效的端口号")
        return False

def show_menu() -> str:
    """显示菜单
    
    Returns:
        str: 用户选择的选项
    """
    print("\n==== RDP监控服务管理工具 ====")
    print("1. 安装服务")
    print("2. 卸载服务")
    print("3. 更新通知URL")
    print("4. 更新SCKEY")
    print("5. 更新PIN码")
    print("6. 更新RDP端口")
    print("0. 退出")
    
    choice = input("请选择操作: ")
    return choice

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # 如果有命令行参数，按照win32serviceutil的方式处理服务
        win32serviceutil.HandleCommandLine(RDPMonitorService)
    else:
        # 否则显示交互式菜单
        while True:
            choice = show_menu()
            
            if choice == "1":
                install_service()
            elif choice == "2":
                uninstall_service()
            elif choice == "3":
                update_notification_url()
            elif choice == "4":
                update_sckey()
            elif choice == "5":
                update_pin_code()
            elif choice == "6":
                update_rdp_port()
            elif choice == "0":
                break
            else:
                print("无效选择，请重试")
            
            input("\n按回车键继续...") 