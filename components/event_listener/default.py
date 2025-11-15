# SNMP Trap 监听器 - 只使用LangBot官方SDK
from __future__ import annotations

import socket
import threading
import asyncio
import os
from datetime import datetime
from typing import Any

from langbot_plugin.api.definition.components.common.event_listener import EventListener
import logging

from ..utils.message_helper import MessageHelper

# 创建logger实例
logger = logging.getLogger(__name__)


class DefaultEventListener(EventListener):

    def __init__(self):
        super().__init__()  # Critical fix for self.plugin initialization
        self.trap_count = 0
        self.default_group_id = "1056816501"
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None
        self.udp_socket = None
        self.host = "0.0.0.0"  # 监听所有网络接口
        self.port = 1162  # 使用非特权端口

    async def initialize(self) -> None:
        """初始化SNMP监听器"""
        try:
            print("[DEBUG] self.plugin type:", type(self.plugin))
            print("[DEBUG] self.plugin is None:", self.plugin is None)

            # 读取环境变量中的群组ID
            env_group_id = os.getenv('SNMP_DEFAULT_GROUP_ID')
            if env_group_id and env_group_id.strip():
                self.default_group_id = env_group_id.strip()

            print("[INIT] Starting SNMP Trap listener initialization")
            print(f"[INIT] Read group ID from environment variable: {self.default_group_id}")

            if self.plugin is None:
                print("[ERROR] self.plugin is None - MessageHelper will not work")
                return

            print("[DEBUG] plugin available, starting SNMP Trap listener initialization")
            print("[INIT] Starting UDP listener...")
            print(f"[UDP] UDP listener started on {self.host}:{self.port}")
            print("[UDP] UDP receive loop started")
            print(f"[SUCCESS] SNMP listener started, listening on port: {self.host}:{self.port}")
            print(f"[SUCCESS] Target QQ group: {self.default_group_id}")
            print("[SUCCESS] Import status: Normal")

            # 启动UDP监听器线程
            self.running = True
            self.thread = threading.Thread(target=self._udp_listener_thread, daemon=True)
            self.thread.start()

        except Exception as e:
            print(f"[ERROR] Failed to initialize SNMP listener: {e}")
            logger.error(f"Failed to initialize SNMP listener: {e}")
            raise

    def _udp_listener_thread(self):
        """UDP监听器线程"""
        try:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.bind((self.host, self.port))
            self.udp_socket.settimeout(1.0)  # Set timeout to allow checking stop_event

            print(f"[UDP] Successfully bound to {self.host}:{self.port}")

            while self.running and not self.stop_event.is_set():
                try:
                    # 等待数据，但定期检查stop_event
                    try:
                        data, addr = self.udp_socket.recvfrom(4096)
                        if data:
                            self.trap_count += 1
                            print(f"[UDP] Received packet: from {addr[0]}:{addr[1]}, length {len(data)} bytes")
                            self._process_trap_data(data, addr)
                    except socket.timeout:
                        # 超时是正常的，继续循环检查stop_event
                        continue

                except Exception as e:
                    print(f"[ERROR] UDP receive error: {e}")

        except Exception as e:
            print(f"[ERROR] UDP listener thread error: {e}")
        finally:
            if self.udp_socket:
                self.udp_socket.close()

    def _process_trap_data(self, data: bytes, addr):
        """处理接收到的Trap数据"""
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            self.trap_count += 1
            print(f"[TRAP] === Received SNMP Trap #{self.trap_count} ===")
            print(f"[TRAP] Source: {addr[0]}:{addr[1]}")
            print(f"[TRAP] Time: {timestamp}")
            print(f"[TRAP] Length: {len(data)} bytes")
            print(f"[TRAP] Target group: {self.default_group_id}")

            # 显示十六进制数据用于调试
            hex_data = data.hex()
            print(f"[DEBUG] Hex data: {hex_data}")

            # 检查是否是IP包（以太网帧+IP头+UDP头+SNMP数据）
            # 以太网头14字节，IP头以0x45开头，SNMP数据以0x30开头
            if len(data) >= 28 and data[14] == 0x45 and data[28:30] == b'\x30\x82':
                # 这是一个以太网帧+IP包+UDP头+SNMP trap
                print(f"[DEBUG] Detected Ethernet+IP+UDP+SNMP packet")
                # 跳过以太网头(14) + IP头 + UDP头(8)
                # IP头长度 = (IHL字段 * 4)，IHL是data[14]的低4位
                ip_header_length = (data[14] & 0x0f) * 4
                total_headers = 14 + ip_header_length + 8  # 以太网 + IP + UDP
                if len(data) > total_headers:
                    snmp_data = data[total_headers:]
                    print(f"[DEBUG] Extracted SNMP data, headers: {total_headers} bytes, SNMP: {len(snmp_data)} bytes")
                    print(f"[DEBUG] SNMP hex data: {snmp_data.hex()}")
                else:
                    snmp_data = data
            elif len(data) >= 20 and data[0:2] == b'\x30\x82':
                # 纯SNMP数据包
                print(f"[DEBUG] Detected pure SNMP packet")
                snmp_data = data
            else:
                # 其他情况，尝试查找SNMP起始位置
                print(f"[DEBUG] Unknown packet format, searching for SNMP data...")
                snmp_data = data
                # 查找SNMP SEQUENCE标记
                for i in range(len(data) - 2):
                    if data[i:i+2] == b'\x30\x82':
                        snmp_data = data[i:]
                        print(f"[DEBUG] Found SNMP data at offset {i}")
                        break

            # 尝试解析为ASCII用于显示
            try:
                text_data = data.decode('utf-8', errors='ignore')
                print(f"[DEBUG] ASCII representation: {text_data}")
            except:
                text_data = ""
                print(f"[DEBUG] Could not decode as ASCII")

            # 检查是否包含网络设备相关的关键词
            trap_content_lower = text_data.lower()
            network_keywords = [
                "router", "switch", "firewall", "network", "interface", "port", "link", "down", "up",
                "cpu", "memory", "disk", "usage", "threshold", "exceeded", "critical", "major",
                "minor", "warning", "alert", "trap", "snmp", "oid", "device", "host", "server",
                "网卡", "端口", "链路", "路由器", "交换机", "防火墙", "网络", "接口", "设备"
            ]

            is_network_alert = any(keyword in trap_content_lower for keyword in network_keywords)

            if is_network_alert:
                print(f"[ALERT] This is a network device alert, will be sent to group")
            else:
                print(f"[INFO] Regular SNMP Trap, will be sent to group")

            # 使用MessageHelper直接解析和格式化SNMP Trap
            def format_message_async():
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(
                        MessageHelper.format_snmp_alert(
                            hostname="Unknown",  # 由MessageHelper内部解析
                            message="Unknown",   # 由MessageHelper内部解析
                            severity="Unknown",  # 由MessageHelper内部解析
                            source=addr[0],     # 传入源IP作为默认值
                            trap_count=self.trap_count,
                            raw_data=snmp_data.hex(),  # 传递十六进制数据给解析器
                            group_id=self.default_group_id
                        )
                    )
                finally:
                    loop.close()

            formatted_message = format_message_async()

            print(f"[TRAP] Formatted message length: {len(formatted_message)} characters")

            # 直接使用formatted_message（已经包含标题）
            # 发送群消息，添加间隔避免频率限制
            success = self._send_group_message(formatted_message)
            if success:
                # 发送成功后等待2秒，避免频率限制
                import time
                time.sleep(2)

        except Exception as e:
            print(f"[ERROR] Error processing Trap data: {e}")
            import traceback
            print(f"[ERROR] Traceback: {traceback.format_exc()}")

    def _send_group_message(self, message: str) -> bool:
        """发送消息到QQ群，只使用SDK"""
        try:
            print(f"[SEND] Sending message to QQ group {self.default_group_id}")

            # 使用MessageHelper发送消息
            from ..utils.message_helper import MessageHelper

            # 在新的事件循环中运行异步方法
            def run_async():
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(
                        MessageHelper.send_message_via_sdk(self.plugin, self.default_group_id, message)
                    )
                finally:
                    loop.close()

            success = run_async()

            if success:
                print(f"[SUCCESS] Message sent to QQ group {self.default_group_id}")
                return True
            else:
                print(f"[ERROR] Message sending failed")
                return False

        except Exception as e:
            print(f"[ERROR] Message sending failed: {e}")
            return False

    # 个人消息发送功能已移除，只支持群消息

    async def on_event(self, event: Any) -> None:
        """处理事件"""
        pass

    async def cleanup(self) -> None:
        """清理资源"""
        try:
            print("[CLEANUP] Cleaning up SNMP listener resources")
            self.running = False
            self.stop_event.set()

            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=5)

            if self.udp_socket:
                self.udp_socket.close()

            print("[CLEANUP] SNMP listener cleanup completed")

        except Exception as e:
            print(f"[ERROR] Cleanup error: {e}")
            logger.error(f"Cleanup error: {e}")