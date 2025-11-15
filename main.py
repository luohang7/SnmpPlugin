# 邮件告警监听插件
from __future__ import annotations

import logging
from langbot_plugin.api.definition.plugin import BasePlugin

logger = logging.getLogger(__name__)

class EmailAlarmListenerPlugin(BasePlugin):

    async def initialize(self) -> None:
        """插件初始化"""
        logger.info("Email Alarm Listener Plugin starting...")

        # 预先获取并缓存机器人列表
        try:
            import sys
            import os
            import asyncio

            # 添加插件路径到sys.path以支持绝对导入
            plugin_dir = os.path.dirname(os.path.abspath(__file__))
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)

            from components.utils.message_helper import MessageHelper

            logger.info("Pre-caching bot list to avoid timeout issues...")

            # 添加重试机制获取机器人列表
            max_init_retries = 3
            init_retry_delay = 2.0

            for init_attempt in range(max_init_retries):
                try:
                    logger.info(f"Getting bots list - Attempt {init_attempt + 1}/{max_init_retries}")
                    MessageHelper._cached_bots = await asyncio.wait_for(self.get_bots(), timeout=15.0)
                    MessageHelper._cache_time = __import__('time').time()

                    # 预选最佳机器人
                    MessageHelper._selected_bot_uuid, MessageHelper._selected_bot_name = MessageHelper.select_best_bot(MessageHelper._cached_bots)

                    logger.info(f"Bot list cached successfully on attempt {init_attempt + 1}: {len(MessageHelper._cached_bots)} bots available")
                    logger.info(f"Pre-selected robot: {MessageHelper._selected_bot_name} ({MessageHelper._selected_bot_uuid})")
                    break  # 成功获取，跳出重试循环

                except asyncio.TimeoutError:
                    logger.warning(f"get_bots() timeout on attempt {init_attempt + 1}/{max_init_retries}")
                    if init_attempt < max_init_retries - 1:
                        logger.info(f"Waiting {init_retry_delay} seconds before retry...")
                        await asyncio.sleep(init_retry_delay)
                    else:
                        logger.error("Failed to cache bot list after all retries during initialization")
                        raise

                except Exception as e:
                    logger.warning(f"get_bots() failed on attempt {init_attempt + 1}: {e}")
                    if init_attempt < max_init_retries - 1:
                        logger.info(f"Waiting {init_retry_delay} seconds before retry...")
                        await asyncio.sleep(init_retry_delay)
                    else:
                        logger.error(f"Failed to cache bot list after all retries during initialization: {e}")
                        raise
        except Exception as e:
            logger.warning(f"Failed to pre-cache bot list: {e}. Will fetch on-demand.")

        # 插件启动完成
        logger.info("Email Alarm Listener Plugin started")
        logger.info("Starting to listen for SMTP email messages on port 1162...")
        logger.info("Use plugin config or SMTP_DEFAULT_GROUP_ID environment variable to set target QQ group")

    def __del__(self) -> None:
        """插件清理"""
        logger.info("Email Alarm Listener Plugin shutting down...")