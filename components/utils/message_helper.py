# 消息发送辅助工具
from __future__ import annotations

import logging
import os
from typing import Any, Dict
from datetime import datetime

from langbot_plugin.api.entities.builtin.platform.message import MessageChain, Plain, AtAll

logger = logging.getLogger(__name__)


class MessageHelper:
    """消息发送辅助类，统一处理消息发送和配置读取逻辑"""

    @staticmethod
    async def get_group_id(plugin) -> str:
        """获取群组ID，优先级：插件配置 > 环境变量 > 默认值"""
        try:
            config = await plugin.get_config()
            config_group_id = config.get('default_group_id')
            if config_group_id and config_group_id != "123456789":
                logger.info(f"✅ 从插件配置读取到默认群组ID: {config_group_id}")
                return config_group_id
        except Exception as e:
            logger.debug(f"插件配置读取失败: {e}")

        # 尝试从环境变量读取
        env_group_id = os.getenv('SNMP_DEFAULT_GROUP_ID')
        if env_group_id and env_group_id.strip():
            logger.info(f"✅ 从环境变量读取到默认群组ID: {env_group_id}")
            return env_group_id.strip()

        # 返回默认值
        default_id = "123456789"
        logger.warning(f"⚠️ 无法读取配置，使用默认群组ID: {default_id}")
        logger.info("💡 请在.env文件中设置 SNMP_DEFAULT_GROUP_ID=你的实际QQ群号")
        return default_id

    @staticmethod
    async def send_to_qq_group(plugin, message: str, group_id: str, message_type: str = "告警"):
        """发送消息到QQ群并艾特所有人"""
        try:
            print(f"📤 准备发送{message_type}到QQ群 {group_id}")

            # 获取可用的机器人列表
            bots = await plugin.get_bots()
            if not bots:
                print("❌ 没有可用的机器人配置")
                logger.error("没有可用的机器人配置")
                return False

            # 获取平台适配器
            adapters = plugin.get_platform_adapters()
            if not adapters:
                print("❌ 没有可用的平台适配器")
                logger.error("没有可用的平台适配器")
                return False

            # 使用第一个可用的机器人
            bot_info = bots[0]
            adapter = adapters[0]
            print(f"🤖 使用机器人: {bot_info}")
            print(f"🔧 使用适配器: {adapter}")

            # 构造消息链，包含@所有人
            message_chain = MessageChain([
                AtAll(),
                Plain(text="\n"),
                Plain(text=message)
            ])

            # 使用host.send_active_message发送消息
            await plugin.host.send_active_message(
                adapter=adapter,
                target_type="group",
                target_id=group_id,
                message=message_chain
            )

            print(f"✅ {message_type}已发送到QQ群 {group_id}")
            logger.info(f"{message_type}已成功发送，群组 {group_id}，机器人 {bot_info}")
            return True

        except Exception as e:
            logger.error(f"发送{message_type}到QQ群失败: {e}")
            print(f"❌ 发送{message_type}失败: {e}")
            print(f"💾 备份消息 - QQ群 {group_id}: {message}")
            import traceback
            traceback.print_exc()
            return False

    @staticmethod
    def format_trap_message(trap_data: Dict[str, Any], title: str = "网络告警") -> str:
        """格式化Trap告警消息"""
        message = f"🚨 **{title}通知** 🚨\n\n"
        message += f"⏰ **时间**: {trap_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"

        if trap_data.get('severity'):
            message += f"🎯 **告警级别**: {trap_data.get('severity')}\n"

        if trap_data.get('hostname') or trap_data.get('source_ip'):
            hostname = trap_data.get('hostname') or trap_data.get('source_ip', 'Unknown')
            message += f"🖥️ **主机**: {hostname}\n"

        if trap_data.get('trap_count'):
            message += f"📊 **告警序号**: #{trap_data.get('trap_count')}\n"

        if trap_data.get('message_type'):
            message += f"💬 **消息类型**: {trap_data.get('message_type')}\n"

        if trap_data.get('raw_message'):
            message += f"📝 **原始消息**: {trap_data.get('raw_message')}\n"

        if trap_data.get('readable_content'):
            message += f"📝 **可读内容**: {trap_data.get('readable_content')}\n"

        if trap_data.get('raw_data'):
            message += f"🔍 **原始数据**: {trap_data.get('raw_data')}\n"

        if trap_data.get('snmp_version'):
            message += f"🔧 **SNMP版本**: {trap_data.get('snmp_version')}\n"

        message += "\n---\n"
        message += "📧 **处理状态**: SNMP Trap Webhook Plugin 已处理\n"
        message += "🔌 **插件状态**: 正常运行中\n"

        return message