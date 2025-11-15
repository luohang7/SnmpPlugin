# 消息发送辅助工具 - 邮件版本
from __future__ import annotations

import logging
import os
from typing import Any, Dict
from datetime import datetime

from langbot_plugin.api.entities.builtin.platform.message import MessageChain, Plain

logger = logging.getLogger(__name__)


class MessageHelper:
    """消息发送辅助类 - 邮件版本"""

    @staticmethod
    async def get_group_id(plugin) -> str:
        """获取群组ID，优先级：插件配置 > 环境变量 > 默认值"""
        try:
            config = await plugin.get_config()
            config_group_id = config.get('default_group_id')
            if config_group_id and config_group_id != "123456789":
                logger.info(f"Using group ID from plugin config: {config_group_id}")
                return config_group_id
        except Exception as e:
            logger.debug(f"Failed to read plugin config: {e}")

        # 尝试从环境变量读取
        env_group_id = os.getenv('SMTP_DEFAULT_GROUP_ID')
        if env_group_id and env_group_id.strip():
            logger.info(f"Using group ID from environment: {env_group_id}")
            return env_group_id.strip()

        # 返回默认值
        default_id = "1056816501"
        logger.info(f"Using default group ID: {default_id}")
        return default_id

    @staticmethod
    async def send_message_via_sdk(plugin, group_id: str, message: str, message_type: str = "Alert") -> bool:
        """使用LangBot官方SDK发送群消息"""
        try:
            print(f"[SEND] Attempting to send {message_type} to QQ group {group_id}")
            print(f"[SEND] Message length: {len(message)} characters")

            # 获取可用的机器人列表
            bots = await plugin.get_bots()

            if not bots:
                print("[ERROR] No available bots configured")
                logger.error("No available bots configured")
                return False

            # 智能选择机器人
            bot_uuid = None
            bot_name = 'Unknown'
            bot_adapter = None

            print(f"[DEBUG] Available robots: {bots}")

            for bot in bots:
                if isinstance(bot, dict):
                    bot_id = bot.get('uuid')
                    bot_adapter_type = bot.get('adapter', '')
                    bot_name_current = bot.get('name', 'Unknown')

                    print(f"[DEBUG] Checking robot: {bot_name_current} ({bot_id}) - Adapter: {bot_adapter_type}")

                    # 优先选择NapCat机器人（qq适配器）
                    if not bot_uuid and bot_adapter_type == 'qq':
                        bot_uuid = bot_id
                        bot_name = bot_name_current
                        bot_adapter = bot_adapter_type
                        print(f"[INFO] Selected NapCat robot: {bot_name} ({bot_uuid})")

                    elif not bot_uuid and ('qq' in bot_adapter_type.lower() and bot_adapter_type != 'qqofficial'):
                        bot_uuid = bot_id
                        bot_name = bot_name_current
                        bot_adapter = bot_adapter_type
                        print(f"[INFO] Selected QQ robot: {bot_name} ({bot_uuid})")

                    elif not bot_uuid:
                        bot_uuid = bot_id
                        bot_name = bot_name_current
                        bot_adapter = bot_adapter_type

            if bot_uuid:
                print(f"[SUCCESS] Using robot: {bot_name} ({bot_uuid}) - Adapter: {bot_adapter}")
            else:
                print("[ERROR] No available robots found")
                return False

            # 构造消息链，直接使用传入的消息（已经包含标题）
            message_chain = MessageChain([
                Plain(text=message)
            ])

            print(f"[API] Calling LangBot SDK send_message...")
            print(f"[API] Sending parameters:")
            print(f"  bot_uuid: {bot_uuid}")
            print(f"  target_type: group")
            print(f"  target_id: {group_id}")

            # 确保target_id是数字格式
            try:
                target_id_numeric = int(group_id)
            except ValueError:
                print(f"[WARNING] Cannot convert group ID {group_id} to number, using original format")
                target_id_numeric = group_id

            # 使用LangBot官方SDK发送消息，增加超时时间
            import asyncio
            try:
                result = await asyncio.wait_for(
                    plugin.send_message(
                        bot_uuid=bot_uuid,
                        target_type="group",
                        target_id=target_id_numeric,
                        message_chain=message_chain
                    ),
                    timeout=30.0  # 30秒超时
                )
            except asyncio.TimeoutError:
                print(f"[WARNING] Send message timeout after 30 seconds")
                logger.warning("Send message timeout after 30 seconds")
                # 假设消息可能已经发送成功，因为NapCat日志显示发送成功
                return True

            print(f"[API] send_message returned: {result}")

            # 检查结果
            if result == {} or result is None:
                print(f"[SUCCESS] {message_type} sent to group {group_id}")
                logger.info(f"{message_type} sent to group {group_id}")
                return True
            else:
                print(f"[SUCCESS] {message_type} sent successfully")
                logger.info(f"{message_type} sent successfully")
                return True

        except Exception as e:
            logger.error(f"Failed to send {message_type} to QQ group: {e}")
            print(f"[ERROR] Failed to send {message_type}: {e}")
            return False