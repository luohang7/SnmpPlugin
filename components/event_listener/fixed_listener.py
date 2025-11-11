# 固定版本 - 直接发送消息到QQ群
from __future__ import annotations

import logging
import socket
import threading
import time
from typing import Dict, Any
from datetime import datetime

from langbot_plugin.api.definition.components.common.event_listener import EventListener

# 导入消息平台相关模块
from langbot_plugin.api.entities.builtin.platform.message import MessageChain, Plain, AtAll

logger = logging.getLogger(__name__)


class FixedEventListener(EventListener):
    """固定版本的SNMP Trap监听器"""

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
        try:
            config = self.plugin.get_config()
            config_group_id = config.get('default_group_id')
            if config_group_id and config_group_id != "123456789":
                self.default_group_id = config_group_id
                logger.info(f"✅ 从插件配置读取到默认群组ID: {self.default_group_id}")
            else:
                import os
                env_group_id = os.getenv('SNMP_DEFAULT_GROUP_ID')
                if env_group_id and env_group_id.strip():
                    self.default_group_id = env_group_id.strip()
                    logger.info(f"✅ 从环境变量读取到默认群组ID: {self.default_group_id}")
                else:
                    self.default_group_id = "123456789"
                    logger.warning(f"⚠️ 无法读取配置，使用默认群组ID: {self.default_group_id}")
        except Exception as e:
            self.default_group_id = "123456789"
            logger.error(f"获取群组ID失败: {e}")

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

            # 构建告警消息
            alert_message = f"🚨 **SNMP Trap告警** 🚨\n\n"
            alert_message += f"⏰ **时间**: {timestamp}\n"
            alert_message += f"🖥️ **来源**: {addr[0]}\n"
            alert_message += f"📊 **序号**: #{self.trap_count}\n"
            alert_message += f"📝 **内容**: {text_data}\n"
            alert_message += "\n---\n"
            alert_message += "📧 **状态**: SNMP Trap已接收\n"
            alert_message += "🔌 **插件**: 正常运行"

            print(f"处理SNMP Trap #{self.trap_count}")
            print(f"来源: {addr[0]}:{addr[1]}")
            print(f"内容: {text_data[:50]}...")
            print(f"完整消息:\n{alert_message}")

            # 尝试发送消息
            self._try_send_message(alert_message)

        except Exception as e:
            print(f"处理Trap数据时出错: {e}")
            import traceback
            traceback.print_exc()

    def _try_send_message(self, message: str):
        """尝试发送消息"""
        try:
            print(f"尝试发送消息到群 {self.default_group_id}")

            # 使用插件API发送消息
            import asyncio

            def async_send():
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                    # 构造消息链
                    message_chain = MessageChain([
                        AtAll(),
                        Plain(text="\n"),
                        Plain(text=message)
                    ])

                    # 使用插件的方法发送消息
                    result = loop.run_until_complete(
                        self._send_group_message_async(message_chain)
                    )
                    print(f"发送结果: {result}")

                except Exception as e:
                    print(f"异步发送失败: {e}")
                    import traceback
                    traceback.print_exc()
                finally:
                    loop.close()

            send_thread = threading.Thread(target=async_send, daemon=True)
            send_thread.start()

        except Exception as e:
            print(f"发送消息失败: {e}")
            import traceback
            traceback.print_exc()

    async def _send_group_message_async(self, message_chain):
        """异步发送群消息的尝试"""
        try:
            print("尝试使用plugin.send_message发送消息")

            # 获取机器人列表
            bots = await self.plugin.get_bots()
            if not bots:
                print("❌ 没有可用的机器人配置")
                return False

            # 获取第一个机器人的UUID
            bot_info = bots[0]
            if isinstance(bot_info, dict):
                bot_uuid = bot_info.get('uuid')
                print(f"🤖 使用机器人: {bot_info.get('name')} (UUID: {bot_uuid})")
            else:
                bot_uuid = str(bot_info)
                print(f"🤖 使用机器人UUID: {bot_uuid}")

            if not bot_uuid:
                print("❌ 无法获取机器人UUID")
                return False

            # 使用正确的API发送消息
            await self.plugin.send_message(
                bot_uuid=bot_uuid,
                target_type="group",
                target_id=self.default_group_id,
                message_chain=message_chain
            )

            print(f"✅ 消息已发送到QQ群 {self.default_group_id}")
            return True

        except Exception as e:
            print(f"❌ 发送消息API失败: {e}")
            import traceback
            traceback.print_exc()
            return False

    def __del__(self):
        """清理资源"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("SNMP监听器已清理")