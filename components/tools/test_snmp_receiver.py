# 测试SNMP Trap接收器的工具
from __future__ import annotations

from typing import Any
import logging
from datetime import datetime
import subprocess
import sys

from langbot_plugin.api.definition.components.tool.tool import Tool

logger = logging.getLogger(__name__)


class TestSnmpReceiver(Tool):

    async def call(self, params: dict[str, Any]) -> dict[str, Any]:
        """测试SNMP Trap接收器功能并发送测试Trap"""
        try:
            print("🧪 开始测试SNMP Trap接收器...")

            # 获取群组ID
            from ..utils.message_helper import MessageHelper
            group_id = await MessageHelper.get_group_id(self.plugin)

            test_result = {
                "status": "success",
                "message": "SNMP Trap接收器测试功能已准备就绪",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "group_id": group_id,
                "instructions": [
                    "1. 确保SNMP Trap接收器已启动（检查插件启动日志）",
                    "2. 配置你的网络设备发送SNMP Trap到本机的1162端口",
                    "3. 或者点击下方按钮发送测试Trap",
                    "4. 查看插件控制台日志是否显示接收到Trap"
                ],
                "port": 1162,
                "protocol": "UDP"
            }

            # 检查是否可以发送测试Trap
            try:
                # 尝试发送一个简单的UDP测试包到1162端口
                import socket
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_data = f"Test SNMP Trap at {datetime.now()}".encode('utf-8')
                test_socket.sendto(test_data, ('localhost', 1162))
                test_socket.close()

                test_result["test_sent"] = True
                test_result["test_message"] = "已发送测试UDP数据包到localhost:1162"

            except Exception as test_e:
                test_result["test_sent"] = False
                test_result["test_message"] = f"无法发送测试数据包: {test_e}"

            print("✅ SNMP Trap接收器测试准备完成")
            print("📋 测试说明:")
            for instruction in test_result["instructions"]:
                print(f"   {instruction}")
            print(f"📊 测试结果: {test_result['test_message']}")

            return test_result

        except Exception as e:
            logger.error(f"测试SNMP Trap接收器失败: {e}")
            print(f"❌ 测试SNMP Trap接收器失败: {e}")

            return {
                "status": "error",
                "message": f"测试SNMP Trap接收器失败: {str(e)}",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }