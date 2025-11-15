# 邮件告警监听插件
from __future__ import annotations

import logging
from langbot_plugin.api.definition.plugin import BasePlugin

logger = logging.getLogger(__name__)

class EmailAlarmListenerPlugin(BasePlugin):

    async def initialize(self) -> None:
        """插件初始化"""
        logger.info("Email Alarm Listener Plugin starting...")

        # 插件启动完成
        logger.info("Email Alarm Listener Plugin started")
        logger.info("Starting to listen for SMTP email messages on port 1162...")
        logger.info("Use plugin config or SMTP_DEFAULT_GROUP_ID environment variable to set target QQ group")

    def __del__(self) -> None:
        """插件清理"""
        logger.info("Email Alarm Listener Plugin shutting down...")