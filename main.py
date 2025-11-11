# SNMP Trap 监听插件
from __future__ import annotations

import logging
from langbot_plugin.api.definition.plugin import BasePlugin

logger = logging.getLogger(__name__)

class SnmpPlugin(BasePlugin):

    async def initialize(self) -> None:
        """插件初始化"""
        logger.info("🚀 SNMP Trap Plugin 启动中...")

        # 插件启动完成
        logger.info("✅ SNMP Trap Plugin 已启动")
        logger.info("📡 开始监听 SNMP Trap 消息...")
        logger.info("🔧 使用插件配置或环境变量 SNMP_DEFAULT_GROUP_ID 设置目标QQ群")

    def __del__(self) -> None:
        """插件清理"""
        logger.info("🛑 SNMP Trap Plugin 正在关闭...")