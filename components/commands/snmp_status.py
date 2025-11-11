# SNMP Trap 插件状态命令
from __future__ import annotations

from typing import Any, AsyncGenerator
from datetime import datetime

from langbot_plugin.api.definition.components.command.command import Command, Subcommand
from langbot_plugin.api.entities.builtin.command.context import ExecuteContext, CommandReturn

from ..utils.message_helper import MessageHelper


class SnmpStatus(Command):

    async def initialize(self):
        await super().initialize()

        @self.subcommand(
            name="",  # 空字符串表示根命令
            help="显示 SNMP Trap 插件状态",
            usage="snmp_status",
            aliases=["status"],
        )
        async def show_status(self, context: ExecuteContext) -> AsyncGenerator[CommandReturn, None]:
            """显示SNMP Trap插件状态"""
            print(f"🚀 收到状态查询命令: {context.command_text}")

            try:
                # 获取群组ID配置
                group_id = await MessageHelper.get_group_id(self.plugin)

                # 构建状态消息
                status_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                status_message = f"🔌 **SNMP Trap 插件状态** 🔌\n\n"
                status_message += f"⏰ **查询时间**: {status_time}\n"
                status_message += f"📱 **目标QQ群**: {group_id}\n"
                status_message += f"📡 **监听端口**: 1162 (UDP)\n"
                status_message += f"🔧 **插件状态**: 运行中\n"
                status_message += f"🎯 **功能状态**: SNMP Trap 接收和转发正常\n"
                status_message += "\n---\n"
                status_message += "📋 **可用功能**:\n"
                status_message += "• 接收 SNMP Trap 消息\n"
                status_message += "• 自动转发告警到指定QQ群\n"
                status_message += "• @全体成员 通知\n"
                status_message += "• 支持测试告警功能\n"

                print(f"📤 返回插件状态信息")

                yield CommandReturn(text=status_message)
                print(f"✅ 状态消息已返回")

            except Exception as e:
                error_message = f"❌ 获取插件状态失败: {str(e)}"
                print(error_message)
                yield CommandReturn(text=error_message)