#!/usr/bin/env python3
"""
简单的SNMP Trap接收器 - 使用同步方式
"""

import socket
import threading
import time
import logging
from typing import Dict, Any, Callable, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class SimpleTrapReceiver:
    """简单的SNMP Trap接收器"""

    def __init__(self, port: int = 1162, host: str = '0.0.0.0'):
        self.port = port
        self.host = host
        self.running = False
        self.socket = None
        self.thread = None
        self.message_callback: Optional[Callable] = None
        self.received_traps = 0

    def set_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """设置接收到trap时的回调函数"""
        self.message_callback = callback

    def start(self):
        """启动SNMP Trap监听服务（同步）"""
        if self.running:
            logger.warning("SNMP Trap服务已在运行中")
            return

        try:
            # 创建UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))

            self.running = True
            print(f"🔌 SNMP Trap监听服务已启动")
            print(f"🌐 监听地址: {self.host}:{self.port}")
            print(f"📡 等待接收SNMP Trap消息...")

            # 在独立线程中运行监听
            self.thread = threading.Thread(target=self._receive_traps)
            self.thread.daemon = True
            self.thread.start()

        except Exception as e:
            print(f"❌ 启动SNMP Trap服务失败: {e}")
            logger.error(f"启动SNMP Trap服务失败: {e}")
            self.running = False
            if self.socket:
                self.socket.close()
                self.socket = None
            raise

    def stop(self):
        """停止SNMP Trap监听服务"""
        if not self.running:
            return

        self.running = False
        print("🛑 正在停止SNMP Trap监听服务...")

        if self.socket:
            self.socket.close()
            self.socket = None

        if self.thread:
            self.thread.join(timeout=2)

        print(f"✅ SNMP Trap监听服务已停止，共接收 {self.received_traps} 条Trap")

    def _receive_traps(self):
        """接收SNMP Trap消息的主循环（同步）"""
        print("📡 SNMP Trap接收循环已启动")

        while self.running:
            try:
                # 设置socket超时
                self.socket.settimeout(1.0)

                try:
                    # 接收数据
                    data, addr = self.socket.recvfrom(4096)
                    print(f"📨 接收到来自 {addr[0]}:{addr[1]} 的数据包，长度: {len(data)} 字节")

                    # 解析SNMP Trap
                    trap_info = self._parse_snmp_trap(data, addr)
                    if trap_info:
                        self.received_traps += 1
                        print(f"🚨 SNMP Trap #{self.received_traps} 已解析")

                        # 调用回调函数处理trap
                        if self.message_callback:
                            # 这里需要用异步方式调用
                            import asyncio
                            try:
                                loop = asyncio.get_event_loop()
                                if loop.is_running():
                                    asyncio.create_task(self._safe_callback(trap_info))
                                else:
                                    # 如果没有运行的事件循环，直接调用
                                    self.message_callback(trap_info)
                            except RuntimeError:
                                # 如果没有事件循环，创建一个
                                asyncio.run(self._safe_callback(trap_info))

                except socket.timeout:
                    # 超时是正常的，继续循环
                    continue
                except Exception as e:
                    print(f"❌ 接收数据包时出错: {e}")
                    continue

            except Exception as e:
                if self.running:  # 只有在服务还在运行时才记录错误
                    print(f"❌ SNMP Trap监听循环出错: {e}")
                time.sleep(0.1)  # 短暂休眠后继续

    async def _safe_callback(self, trap_info: Dict[str, Any]):
        """安全地调用回调函数"""
        try:
            if asyncio.iscoroutinefunction(self.message_callback):
                await self.message_callback(trap_info)
            else:
                self.message_callback(trap_info)
        except Exception as e:
            print(f"❌ 执行SNMP Trap回调函数时出错: {e}")

    def _parse_snmp_trap(self, data: bytes, addr: tuple) -> Optional[Dict[str, Any]]:
        """解析SNMP Trap数据（简化版本）"""
        try:
            # 基本的解析逻辑
            trap_info = {
                'raw_data': data.hex()[:100] + '...' if len(data) > 50 else data.hex(),
                'source_ip': addr[0],
                'source_port': addr[1],
                'data_length': len(data),
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'trap_count': self.received_traps + 1,
                'message_type': 'snmp_trap',
                'parsed': False
            }

            # 简单的SNMP版本检测
            if len(data) > 0:
                version = data[0] if data[0] < 3 else 'unknown'
                trap_info['snmp_version'] = version

            # 尝试提取可读信息
            readable_text = self._extract_readable_text(data)
            if readable_text:
                trap_info['readable_content'] = readable_text
                trap_info['parsed'] = True

            print(f"🔍 SNMP Trap解析结果: {trap_info}")
            return trap_info

        except Exception as e:
            print(f"❌ 解析SNMP Trap时出错: {e}")
            return None

    def _extract_readable_text(self, data: bytes) -> Optional[str]:
        """从SNMP数据中提取可读文本"""
        try:
            # 尝试解码为ASCII字符串
            readable_parts = []

            # 查找可能的字符串片段
            i = 0
            while i < len(data):
                # 如果是可打印ASCII字符
                if 32 <= data[i] <= 126:
                    start = i
                    while i < len(data) and 32 <= data[i] <= 126:
                        i += 1
                    readable_parts.append(data[start:i].decode('ascii', errors='ignore'))
                else:
                    i += 1

            # 过滤掉太短的片段
            readable_texts = [part for part in readable_parts if len(part) >= 3]

            if readable_texts:
                return ' '.join(readable_texts[:5])  # 最多返回5个片段

        except Exception as e:
            print(f"提取可读文本时出错: {e}")

        return None

    def get_status(self) -> Dict[str, Any]:
        """获取SNMP Trap接收器状态"""
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            'received_traps': self.received_traps,
            'has_callback': self.message_callback is not None
        }