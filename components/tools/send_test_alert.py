# 发送测试 SNMP Trap 告警工具
from __future__ import annotations

from typing import Any
import logging
from datetime import datetime

from langbot_plugin.api.definition.components.tool.tool import Tool

# 导入消息辅助工具
from ..utils.message_helper import MessageHelper

logger = logging.getLogger(__name__)


class SendTestAlert(Tool):

    async def call(self, params: dict[str, Any]) -> dict[str, Any]:
        """发送测试 SNMP Trap 告警到 QQ 群"""
        try:
            print("🚀 开始发送测试 SNMP Trap 告警...")

            # 构建测试告警数据
            test_trap_data = {
                'raw_message': '这是一条测试 SNMP Trap 告警消息',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'trap_count': 999,
                'message_type': 'test_alert',
                'severity': 'Warning',
                'hostname': 'test-device.example.com'
            }

            # 格式化告警消息
            alert_message = MessageHelper.format_trap_message(test_trap_data, "测试网络告警")

            # 添加测试标识
            alert_message += "\n🧪 **注意**: 这是一条测试消息"

            # 获取群组ID
            group_id = await MessageHelper.get_group_id(self.plugin)

            # 使用消息辅助工具发送到QQ群
            success = await MessageHelper.send_to_qq_group(
                self.plugin,
                alert_message,
                group_id,
                "测试 SNMP Trap 告警"
            )

            print("✅ 测试告警发送完成")

            return {
                "status": "success" if success else "error",
                "message": "测试 SNMP Trap 告警已发送" if success else "发送失败",
                "timestamp": test_trap_data['timestamp'],
                "group_id": group_id
            }

        except Exception as e:
            logger.error(f"发送测试告警失败: {e}")
            print(f"❌ 发送测试告警失败: {e}")

            return {
                "status": "error",
                "message": f"发送测试告警失败: {str(e)}",
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }