# SNMP Trap 监听插件
from __future__ import annotations

import logging
from langbot_plugin.api.definition.plugin import BasePlugin

logger = logging.getLogger(__name__)

class SnmpPlugin(BasePlugin):

    async def initialize(self) -> None:
        """插件初始化"""
        logger.info("SNMP Trap Plugin starting...")

        # 插件启动完成
        logger.info("SNMP Trap Plugin started")
        logger.info("Starting to listen for SNMP Trap messages...")
        logger.info("Use plugin config or SNMP_DEFAULT_GROUP_ID environment variable to set target QQ group")

    def __del__(self) -> None:
        """插件清理"""
        logger.info("SNMP Trap Plugin shutting down...")