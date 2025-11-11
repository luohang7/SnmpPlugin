# 工作版本的SNMP Trap监听器
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Dict, Any
from datetime import datetime

from langbot_plugin.api.definition.components.common.event_listener import EventListener

# 导入消息辅助工具
from ..utils.message_helper import MessageHelper

logger = logging.getLogger(__name__)


class WorkingEventListener(EventListener):
    """能正常工作的SNMP Trap监听器"""

    def __init__(self):
        super().__init__()
        self.default_group_id = None
        self.trap_count = 0
        self.running = False
        self.socket = None
        self.receive_thread = None

    async def initialize(self):
        await super().initialize()

        # 获取群组ID
        self.default_group_id = await MessageHelper.get_group_id(self.plugin)

        # 启动UDP监听器
        self._start_udp_listener()

        print(f"SNMP监听器已初始化")
        print(f"默认群组ID: {self.default_group_id}")

    def _start_udp_listener(self):
        """启动UDP监听器"""
        try:
            # 创建socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind(('127.0.0.1', 1162))

            self.running = True
            print("UDP监听器已启动在127.0.0.1:1162")

            # 启动监听线程
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()

        except Exception as e:
            print(f"启动UDP监听器失败: {e}")
            logger.error(f"启动UDP监听器失败: {e}")

    def _receive_loop(self):
        """UDP接收循环"""
        print("UDP接收循环已启动")
        while self.running:
            try:
                self.socket.settimeout(1.0)
                try:
                    data, addr = self.socket.recvfrom(4096)
                    print(f"收到UDP数据包: 来自 {addr[0]}:{addr[1]}, 长度 {len(data)} 字节")

                    # 处理Trap数据
                    self._process_trap_data(data, addr)

                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"接收数据时出错: {e}")

            except Exception as e:
                print(f"监听循环出错: {e}")

    def _process_trap_data(self, data: bytes, addr: tuple):
        """处理Trap数据"""
        try:
            self.trap_count += 1

            # 解析数据
            text_data = data.decode('utf-8', errors='ignore')
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

            trap_info = {
                'raw_data': text_data,
                'source_ip': addr[0],
                'source_port': addr[1],
                'timestamp': timestamp,
                'trap_count': self.trap_count,
                'message_type': 'snmp_trap'
            }

            print(f"处理SNMP Trap #{self.trap_count}")
            print(f"来源: {addr[0]}:{addr[1]}")
            print(f"内容: {text_data[:100]}...")

            # 格式化消息
            alert_message = MessageHelper.format_trap_message(trap_info, "SNMP Trap告警")

            # 同步方式发送消息
            try:
                # 在新线程中异步发送消息
                import asyncio
                import threading

                def async_send():
                    try:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)

                        print(f"开始发送消息到群 {self.default_group_id}")
                        result = loop.run_until_complete(
                            MessageHelper.send_to_qq_group(
                                self.plugin,
                                alert_message,
                                self.default_group_id,
                                "SNMP Trap告警"
                            )
                        )
                        print(f"消息发送结果: {result}")

                    except Exception as inner_e:
                        print(f"异步发送消息内部错误: {inner_e}")
                    finally:
                        loop.close()

                send_thread = threading.Thread(target=async_send, daemon=True)
                send_thread.start()

            except Exception as e:
                print(f"发送消息失败: {e}")
                import traceback
                traceback.print_exc()

        except Exception as e:
            print(f"处理Trap数据时出错: {e}")

    def __del__(self):
        """清理资源"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("SNMP监听器已清理")