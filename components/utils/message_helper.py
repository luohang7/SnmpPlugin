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

    # 缓存机器人信息，避免重复获取
    _cached_bots = None
    _cache_time = None
    _cache_ttl = 300  # 缓存5分钟

    # 预选的机器人信息
    _selected_bot_uuid = None
    _selected_bot_name = None

    @staticmethod
    def select_best_bot(bots):
        """智能选择最佳机器人"""
        if not bots:
            return None, None

        bot_uuid = None
        bot_name = 'Unknown'

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
                    print(f"[INFO] Selected NapCat robot: {bot_name} ({bot_uuid})")

                elif not bot_uuid and ('qq' in bot_adapter_type.lower() and bot_adapter_type != 'qqofficial'):
                    bot_uuid = bot_id
                    bot_name = bot_name_current
                    print(f"[INFO] Selected QQ robot: {bot_name} ({bot_uuid})")

                elif not bot_uuid:
                    bot_uuid = bot_id
                    bot_name = bot_name_current

        return bot_uuid, bot_name

    @staticmethod
    def get_group_id(plugin) -> str:
        """获取群组ID，优先级：插件配置 > 环境变量 > 默认值"""
        try:
            # 强制获取最新配置，不使用缓存（同步调用）
            config = plugin.get_config()
            config_group_id = config.get('default_group_id')
            if config_group_id and config_group_id != "123456789":
                logger.info(f"[CONFIG] Using group ID from plugin config: {config_group_id}")
                print(f"[CONFIG] Plugin config returned: {config_group_id}")
                return config_group_id
            else:
                logger.info(f"[CONFIG] Plugin config returned default/empty value: {config_group_id}")
                print(f"[CONFIG] Plugin config returned default/empty value: {config_group_id}")
        except Exception as e:
            logger.warning(f"[CONFIG] Failed to read plugin config: {e}")
            print(f"[CONFIG] Failed to read plugin config: {e}")

        # 尝试从环境变量读取
        env_group_id = os.getenv('SMTP_DEFAULT_GROUP_ID')
        if env_group_id and env_group_id.strip():
            logger.info(f"[CONFIG] Using group ID from environment: {env_group_id}")
            print(f"[CONFIG] Using group ID from environment: {env_group_id}")
            return env_group_id.strip()

        # 返回默认值
        default_id = "1056816501"
        logger.info(f"[CONFIG] Using default group ID: {default_id}")
        print(f"[CONFIG] Using default group ID: {default_id}")
        return default_id

    @staticmethod
    async def send_message_via_sdk(plugin, group_id: str, message: str, message_type: str = "Alert") -> bool:
        """使用LangBot官方SDK发送群消息"""
        try:
            print(f"[SEND] Attempting to send {message_type} to QQ group {group_id}")
            print(f"[SEND] Message length: {len(message)} characters")

            # 获取可用的机器人列表（使用缓存）
            import time
            current_time = time.time()

            # 检查缓存是否有效
            if (MessageHelper._cached_bots is None or
                MessageHelper._cache_time is None or
                current_time - MessageHelper._cache_time > MessageHelper._cache_ttl):

                print(f"[DEBUG] Getting fresh bots list (cache expired or empty)")
                max_bot_retries = 2
                bot_retry_delay = 1.0

                for bot_attempt in range(max_bot_retries):
                    try:
                        import asyncio
                        print(f"[API] Getting bots - Attempt {bot_attempt + 1}/{max_bot_retries}")
                        MessageHelper._cached_bots = await asyncio.wait_for(plugin.get_bots(), timeout=15.0)
                        MessageHelper._cache_time = current_time

                        # 预选最佳机器人
                        MessageHelper._selected_bot_uuid, MessageHelper._selected_bot_name = MessageHelper.select_best_bot(MessageHelper._cached_bots)

                        print(f"[DEBUG] Bot list cached successfully on attempt {bot_attempt + 1}")
                        break  # 成功获取，跳出重试循环

                    except asyncio.TimeoutError:
                        print(f"[WARNING] get_bots() timeout on attempt {bot_attempt + 1}/{max_bot_retries}")
                        if bot_attempt < max_bot_retries - 1:
                            print(f"[RETRY] Waiting {bot_retry_delay} seconds before retry...")
                            await asyncio.sleep(bot_retry_delay)
                        else:
                            print(f"[WARNING] get_bots() timeout after all retries, using cached data if available")
                            if MessageHelper._cached_bots is None:
                                print(f"[ERROR] No cached bot data available")
                                return False

                    except Exception as e:
                        print(f"[WARNING] get_bots() failed on attempt {bot_attempt + 1}: {e}")
                        if bot_attempt < max_bot_retries - 1:
                            print(f"[RETRY] Waiting {bot_retry_delay} seconds before retry...")
                            await asyncio.sleep(bot_retry_delay)
                        else:
                            print(f"[WARNING] get_bots() failed after all retries: {e}, using cached data if available")
                            if MessageHelper._cached_bots is None:
                                print(f"[ERROR] No cached bot data available")
                                return False
            else:
                print(f"[DEBUG] Using cached bots list (cache age: {current_time - MessageHelper._cache_time:.1f}s)")

            bots = MessageHelper._cached_bots

            if not bots:
                print("[ERROR] No available bots configured")
                logger.error("No available bots configured")
                return False

            # 使用预选的机器人，如果没有则重新选择
            bot_uuid = MessageHelper._selected_bot_uuid
            bot_name = MessageHelper._selected_bot_name

            if not bot_uuid:
                print("[DEBUG] No pre-selected bot, selecting now...")
                bot_uuid, bot_name = MessageHelper.select_best_bot(bots)
                MessageHelper._selected_bot_uuid = bot_uuid
                MessageHelper._selected_bot_name = bot_name

            if bot_uuid:
                print(f"[SUCCESS] Using pre-selected robot: {bot_name} ({bot_uuid})")
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

            # 使用LangBot官方SDK发送消息，增加重试机制
            import asyncio
            max_retries = 3
            retry_delay = 2.0  # 重试间隔2秒

            for attempt in range(max_retries):
                try:
                    print(f"[API] Attempt {attempt + 1}/{max_retries} - Sending message...")
                    result = await asyncio.wait_for(
                        plugin.send_message(
                            bot_uuid=bot_uuid,
                            target_type="group",
                            target_id=target_id_numeric,
                            message_chain=message_chain
                        ),
                        timeout=30.0  # 30秒超时
                    )

                    print(f"[API] send_message returned: {result}")

                    # 检查结果
                    if result == {} or result is None:
                        print(f"[SUCCESS] {message_type} sent to group {group_id} on attempt {attempt + 1}")
                        logger.info(f"{message_type} sent to group {group_id} on attempt {attempt + 1}")
                        return True
                    else:
                        print(f"[WARNING] Unexpected result: {result}, retrying...")

                except asyncio.TimeoutError:
                    print(f"[WARNING] Send message timeout after 30 seconds (attempt {attempt + 1}/{max_retries})")
                    logger.warning(f"Send message timeout on attempt {attempt + 1}/{max_retries}")

                    if attempt < max_retries - 1:
                        print(f"[RETRY] Waiting {retry_delay} seconds before retry...")
                        await asyncio.sleep(retry_delay)
                    else:
                        print(f"[ERROR] All {max_retries} attempts timed out, assuming message may have been sent")
                        logger.warning("All retry attempts timed out, but message may have been sent")
                        return True  # 假设消息可能已经发送成功

                except Exception as e:
                    print(f"[ERROR] Send message failed on attempt {attempt + 1}: {e}")
                    logger.error(f"Send message failed on attempt {attempt + 1}: {e}")

                    if attempt < max_retries - 1:
                        print(f"[RETRY] Waiting {retry_delay} seconds before retry...")
                        await asyncio.sleep(retry_delay)
                    else:
                        print(f"[ERROR] All {max_retries} attempts failed")
                        return False

            return False

        except Exception as e:
            logger.error(f"Failed to send {message_type} to QQ group: {e}")
            print(f"[ERROR] Failed to send {message_type}: {e}")
            return False