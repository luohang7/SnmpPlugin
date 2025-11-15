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
            from .components.utils.message_helper import MessageHelper
            import asyncio

            logger.info("Pre-caching bot list to avoid timeout issues...")
            MessageHelper._cached_bots = await asyncio.wait_for(self.get_bots(), timeout=15.0)
            MessageHelper._cache_time = __import__('time').time()
            logger.info(f"Bot list cached successfully: {len(MessageHelper._cached_bots)} bots available")
        except Exception as e:
            logger.warning(f"Failed to pre-cache bot list: {e}. Will fetch on-demand.")

        # 插件启动完成
        logger.info("Email Alarm Listener Plugin started")
        logger.info("Starting to listen for SMTP email messages on port 1162...")
        logger.info("Use plugin config or SMTP_DEFAULT_GROUP_ID environment variable to set target QQ group")

    def __del__(self) -> None:
        """插件清理"""
        logger.info("Email Alarm Listener Plugin shutting down...")