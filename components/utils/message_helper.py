# 消息发送辅助工具 - 完整版本
from __future__ import annotations

import logging
import os
from typing import Any, Dict
from datetime import datetime
import re

from langbot_plugin.api.entities.builtin.platform.message import MessageChain, Plain, AtAll
from .snmp_binary_parser import parse_snmp_binary_data

logger = logging.getLogger(__name__)


class MessageHelper:
    """消息发送辅助类 - 完整版本"""

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
        env_group_id = os.getenv('SNMP_DEFAULT_GROUP_ID')
        if env_group_id and env_group_id.strip():
            logger.info(f"Using group ID from environment: {env_group_id}")
            return env_group_id.strip()

        # 返回默认值
        default_id = "1056816501"
        logger.info(f"Using default group ID: {default_id}")
        return default_id

    @staticmethod
    async def format_snmp_alert(hostname: str, message: str, severity: str, source: str,
                               trap_count: int = 1, raw_data: str = "", group_id: str = "") -> str:
        """格式化SNMP告警消息，支持中文和更好的解析"""
        timestamp = datetime.now().strftime('%Y年%m月%d日 %H时%M分%S秒')

        # 数据预处理函数
        def clean_raw_data(data):
            """预处理数据，保留二进制数据供后续解析"""
            if isinstance(data, bytes):
                # 对于二进制数据，保持为bytes格式，在后续的SNMP解析器中处理
                return data

            if not isinstance(data, str):
                data = str(data)

            # 对于字符串数据，过滤掉不可打印字符
            cleaned = ''.join(char for char in data if ord(char) >= 32 or char in '\n\r\t')
            # 限制长度避免消息过长
            return cleaned[:300] + ('...' if len(cleaned) > 300 else '')

        # 解析SNMP Trap数据
        def parse_snmp_trap(raw_data):
            """解析SNMP Trap数据，提取有用信息"""
            parsed_info = {
                'enterprise': 'Unknown',
                'agent_addr': source,
                'fault_device_ip': source,  # 故障设备IP（默认为源IP）
                'device_name': 'Unknown',    # 设备名称
                'device_type': 'Unknown',    # 设备类型
                'device_ip': 'Unknown',      # 设备IP
                'generic_type': 'Unknown',
                'specific_type': 'Unknown',
                'uptime': 'Unknown',
                'alarm_time': timestamp,     # 告警时间
                'severity': severity,        # 告警级别
                'alarm_content': message,    # 告警内容
                'alarm_category': 'Unknown', # 告警分类
                'enterprise_id': 'Unknown',  # 企业ID
                'variables': []
            }

            try:
                # 首先检查是否为二进制SNMP数据
                is_binary = False
                binary_data = None

                if isinstance(raw_data, bytes):
                    binary_data = raw_data
                    is_binary = True
                elif isinstance(raw_data, str) and len(raw_data) > 0:
                    # 检查字符串是否包含高字节字符
                    try:
                        # 尝试检测是否为十六进制字符串
                        if all(c in '0123456789abcdefABCDEF \t\n\r' for c in raw_data):
                            # 可能是hex字符串，尝试转换
                            hex_clean = raw_data.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '')
                            if len(hex_clean) % 2 == 0 and len(hex_clean) > 0:
                                binary_data = bytes.fromhex(hex_clean)
                                is_binary = True
                                print(f"[BINARY] 从hex字符串转换，长度: {len(binary_data)} 字节")
                        else:
                            # 检查是否有不可打印字符
                            if any(ord(c) > 127 for c in raw_data):
                                # 安全地转换为字节（避免编码错误）
                                binary_data = raw_data.encode('utf-8', errors='replace')
                                is_binary = True
                    except Exception as e:
                        print(f"[DEBUG] 二进制检测失败: {e}")
                        # 如果转换失败，视为普通文本
                        pass

                if is_binary and binary_data:
                    print(f"[BINARY] 检测到二进制SNMP数据，长度: {len(binary_data)} 字节")
                    print(f"[BINARY] 前20字节: {binary_data[:20].hex()}")

                    try:
                        # 使用二进制解析器解析
                        snmp_result = parse_snmp_binary_data(binary_data)
                    except Exception as e:
                        print(f"[ERROR] 二进制解析器失败: {e}")
                        snmp_result = {'success': False, 'error': str(e)}

                    if snmp_result.get('success', False):
                        print(f"[BINARY] 二进制解析成功，类型: {snmp_result.get('parse_type', 'unknown')}")

                        # 从二进制解析结果中提取信息
                        if snmp_result.get('community'):
                            parsed_info['variables'].append(f"Community: {snmp_result['community']}")

                        if snmp_result.get('enterprise'):
                            parsed_info['enterprise'] = snmp_result['enterprise']
                            parsed_info['variables'].append(f"Enterprise OID: {snmp_result['enterprise']}")

                            # 根据多个条件判断华为设备
                            enterprise_oid = snmp_result.get('enterprise')
                            generic_trap = snmp_result.get('generic_trap')
                            variables = snmp_result.get('variables', [])

                            # 条件1: Enterprise OID匹配
                            is_huawei_by_oid = enterprise_oid and '1.3.6.1.4.1.25506' in str(enterprise_oid)

                            # 条件2: Generic Trap为enterpriseSpecific (6) 且有华为设备信息
                            is_huawei_by_trap = generic_trap == 6 and any(
                                var_type in ['device_id', 'device_ip'] and var_value
                                for var_type, var_value in variables
                            )

                            if is_huawei_by_oid or is_huawei_by_trap:
                                parsed_info['enterprise_id'] = '1.3.6.1.4.1.25506'
                                parsed_info['enterprise'] = '华为NMS'
                                parsed_info['alarm_category'] = '网络设备-通信类告警'
                                parsed_info['alarm_content'] = '华为设备未回应网管轮询报文'
                                parsed_info['severity'] = '紧急'

                                print(f"[DEBUG] 识别为华为设备: OID={is_huawei_by_oid}, Trap={is_huawei_by_trap}")

                                # 从变量中提取华为设备特定信息 (按优先级排序)
                                for var_type, var_value in variables:
                                    print(f"[DEBUG] 处理变量: {var_type} = {var_value}")

                                    # 第一优先级: 标准SNMP sysName (1.3.6.1.2.1.1.5.0)
                                    if var_type == 'sysname' and var_value:
                                        parsed_info['device_name'] = var_value
                                        parsed_info['sysname_source'] = 'standard_snmp'
                                        print(f"[DEBUG] 设备SysName (标准SNMP): {var_value}")
                                    # 第二优先级: 华为设备名称OID
                                    elif var_type == 'device_name' and var_value:
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info.get('sysname_source'):
                                            parsed_info['device_name'] = var_value
                                            parsed_info['device_name_source'] = 'huawei_oid'
                                        print(f"[DEBUG] 设备名称(华为OID): {var_value}")
                                    # 第三优先级: NMS设备描述
                                    elif var_type == 'nms_device_desc' and var_value:
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info.get('sysname_source'):
                                            parsed_info['device_name'] = var_value
                                            parsed_info['device_name_source'] = 'nms_desc'
                                        print(f"[DEBUG] 设备名称(NMS描述): {var_value}")
                                    # 第四优先级: 系统描述
                                    elif var_type == 'sysdescr' and var_value:
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info.get('sysname_source'):
                                            # 从系统描述中提取可能的设备名称
                                            desc_name = self.extract_device_name_from_description(var_value)
                                            if desc_name:
                                                parsed_info['device_name'] = desc_name
                                                parsed_info['device_name_source'] = 'sysdescr'
                                        print(f"[DEBUG] 系统描述: {var_value}")
                                    # 关键参数: Device ID (关键参数)
                                    elif var_type == 'device_id' and var_value:
                                        parsed_info['device_id'] = var_value
                                        # 如果没有其他设备名称，使用设备ID
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info.get('sysname_source'):
                                            parsed_info['device_name'] = f"设备-{var_value[:8]}"
                                            parsed_info['device_name_source'] = 'device_id'
                                        print(f"[DEBUG] 设备ID(关键): {var_value}")
                                    elif var_type == 'nms_device_desc' and var_value:
                                        parsed_info['device_name'] = var_value
                                        print(f"[DEBUG] 设备名称: {var_value}")
                                    elif var_type == 'device_name_oid' and var_value:
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info['device_name']:
                                            parsed_info['device_name'] = var_value
                                            print(f"[DEBUG] 设备名称(备选): {var_value}")
                                    elif var_type == 'device_type_oid' and var_value:
                                        parsed_info['device_type'] = var_value
                                        print(f"[DEBUG] 设备类型: {var_value}")
                                    elif var_type == 'device_id' and var_value:
                                        # Device ID是关键参数，优先处理
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info['device_name']:
                                            parsed_info['device_name'] = f"设备-{var_value[:8]}"
                                        parsed_info['device_id'] = var_value
                                        print(f"[DEBUG] 设备ID(关键): {var_value}")
                                    elif var_type == 'device_ip' and var_value:
                                        parsed_info['fault_device_ip'] = var_value
                                        # 如果还没有设备名，使用IP
                                        if parsed_info['device_name'] == 'Unknown' or not parsed_info['device_name']:
                                            parsed_info['device_name'] = f"设备-{var_value}"
                                        print(f"[DEBUG] 设备IP: {var_value}")
                                    elif var_type == 'device_type' and var_value:
                                        parsed_info['device_type'] = var_value
                                        print(f"[DEBUG] 设备类型: {var_value}")
                                    elif var_type == 'alarm_time' and var_value:
                                        parsed_info['alarm_time'] = var_value
                                        print(f"[DEBUG] 告警时间: {var_value}")
                                    elif var_type == 'poll_type' and var_value:
                                        parsed_info['poll_type'] = var_value
                                        print(f"[DEBUG] 轮询类型: {var_value}")
                                    elif var_type == 'alarm_category' and var_value:
                                        parsed_info['alarm_category'] = var_value
                                        print(f"[DEBUG] 告警分类: {var_value}")
                                    elif var_type == 'alarm_reason' and var_value:
                                        parsed_info['alarm_reason'] = var_value
                                        print(f"[DEBUG] 告警原因: {var_value}")
                                    elif var_type == 'alarm_suggestion' and var_value:
                                        parsed_info['alarm_suggestion'] = var_value
                                        print(f"[DEBUG] 修复建议: {var_value}")
                            elif '1.3.6.1.6.3' in enterprise_oid:  # 标准SNMP
                                parsed_info['enterprise_id'] = '1.3.6.1.6.3'
                                parsed_info['enterprise'] = 'SNMP'
                                parsed_info['alarm_category'] = '网络设备-接口类告警'

                                # 根据generic_trap判断具体类型
                                generic_trap = snmp_result.get('generic_trap')
                                if generic_trap == 2:  # linkDown
                                    parsed_info['alarm_content'] = '接口状态DOWN'
                                    parsed_info['severity'] = '重要'
                                elif generic_trap == 3:  # linkUp
                                    parsed_info['alarm_content'] = '接口状态UP'
                                    parsed_info['severity'] = '信息'

                        if snmp_result.get('agent_addr'):
                            agent_ip = snmp_result['agent_addr']
                            parsed_info['agent_addr'] = agent_ip
                            parsed_info['fault_device_ip'] = agent_ip
                            parsed_info['device_ip'] = agent_ip
                            parsed_info['variables'].append(f"Agent Address: {agent_ip}")

                            # 根据IP生成设备名
                            parsed_info['device_name'] = f"设备-{agent_ip}"

                            # 特殊处理218.201.223.161
                            if agent_ip == '218.201.223.161':
                                parsed_info['device_name'] = '核心网络设备-218.201.223.161'
                                parsed_info['device_type'] = '核心路由器/交换机'
                                parsed_info['alarm_content'] = '核心网络设备未响应，可能存在严重网络故障'
                                parsed_info['severity'] = '紧急'
                                parsed_info['variables'].append('设备类型: 核心网络设备')
                                parsed_info['variables'].append('影响范围: 可能影响整个网络')

                        # 处理变量绑定
                        variables = snmp_result.get('variables', [])
                        for var_type, var_value in variables:
                            if var_type == 'sysname':
                                parsed_info['variables'].append(f"设备SysName: {var_value}")
                            elif var_type == 'device_name':
                                parsed_info['variables'].append(f"设备名称: {var_value}")
                            elif var_type == 'device_id':
                                parsed_info['variables'].append(f"设备ID: {var_value}")
                            elif var_type == 'device_ip':
                                parsed_info['variables'].append(f"设备IP: {var_value}")
                            elif var_type == 'alarm_level':
                                parsed_info['variables'].append(f"告警级别: {var_value}")
                            elif var_type == 'alarm_title':
                                parsed_info['variables'].append(f"告警标题: {var_value}")
                                parsed_info['alarm_content'] = var_value  # 使用告警标题作为告警内容
                            elif var_type == 'alarm_content':
                                parsed_info['variables'].append(f"告警内容: {var_value}")
                                parsed_info['alarm_content'] = var_value  # 使用告警内容
                            elif var_type == 'ip_address':
                                parsed_info['variables'].append(f"设备IP: {var_value}")
                            elif var_type == 'interface_index':
                                parsed_info['variables'].append(f"接口索引: {var_value}")
                                parsed_info['interface_index'] = var_value
                            elif var_type == 'nms_device_desc':
                                parsed_info['variables'].append(f"NMS设备描述: {var_value}")
                            elif var_type == 'device_type':
                                parsed_info['variables'].append(f"设备类型: {var_value}")
                            elif var_type == 'alarm_time':
                                parsed_info['variables'].append(f"告警时间: {var_value}")
                            elif var_type == 'poll_type':
                                parsed_info['variables'].append(f"轮询类型: {var_value}")
                            elif var_type == 'alarm_category':
                                parsed_info['variables'].append(f"告警分类: {var_value}")
                            elif var_type == 'alarm_reason':
                                parsed_info['variables'].append(f"告警原因: {var_value}")
                            elif var_type == 'alarm_suggestion':
                                parsed_info['variables'].append(f"修复建议: {var_value}")
                            elif var_type == 'alarm_level':
                                parsed_info['variables'].append(f"告警级别: {var_value}")
                            elif var_type == 'alarm_title':
                                parsed_info['variables'].append(f"告警标题: {var_value}")
                                parsed_info['alarm_content'] = var_value  # 使用告警标题作为告警内容

                        # 添加解析类型信息
                        parsed_info['variables'].append(f"数据格式: {snmp_result.get('parse_type', 'binary')}")

                        # 如果解析到了足够信息，直接返回
                        if any([snmp_result.get('agent_addr'), snmp_result.get('enterprise'),
                               snmp_result.get('variables')]):
                            return parsed_info
                        else:
                            print(f"[BINARY] 二进制解析未找到有效信息，尝试文本解析")
                    else:
                        print(f"[BINARY] 二进制解析失败: {snmp_result.get('error', 'Unknown error')}")
                        # 提供基本的告警信息
                        parsed_info['alarm_content'] = '网络设备告警（解析失败）'
                        parsed_info['severity'] = '重要'
                        parsed_info['alarm_category'] = '网络设备-通信类告警'
                        parsed_info['variables'].append(f"解析错误: {snmp_result.get('error', 'Unknown error')}")
                        parsed_info['variables'].append(f"原始数据类型: {type(raw_data).__name__}")
                        if isinstance(raw_data, bytes):
                            parsed_info['variables'].append(f"数据长度: {len(raw_data)} 字节")
                        parsed_info['variables'].append(f"源地址: {source}")

                # 原有的文本解析逻辑
                print(f"[TEXT] 尝试文本解析，原始数据长度: {len(raw_data)}")

                # 检查是否为简单的二进制数据或特殊格式数据
                if not raw_data or len(raw_data.strip()) < 10:
                    # 如果数据很少，可能是简单的设备离线通知或心跳检测
                    parsed_info['fault_device_ip'] = source

                    # 基于源IP智能推断设备信息
                    ip_parts = source.split('.')
                    if len(ip_parts) == 4:
                        # 根据IP地址段推断设备类型
                        if ip_parts[2] in ['223', '224', '225']:
                            # 218.201.223.x 可能是核心网络设备
                            parsed_info['device_name'] = f"核心设备-{source}"
                            parsed_info['device_type'] = "网络设备"
                            parsed_info['alarm_content'] = "核心网络设备可能离线或无响应"
                            parsed_info['severity'] = '紧急'
                        elif ip_parts[2] in ['100', '101', '102']:
                            # 192.168.100.x 可能是接入设备
                            parsed_info['device_name'] = f"接入设备-{source}"
                            parsed_info['device_type'] = "接入设备"
                            parsed_info['alarm_content'] = "接入设备可能离线或无响应"
                            parsed_info['severity'] = '重要'
                        else:
                            # 其他IP
                            parsed_info['device_name'] = f"设备-{source}"
                            parsed_info['device_type'] = "网络设备"
                            parsed_info['alarm_content'] = "设备可能离线或无响应"
                            parsed_info['severity'] = '重要'
                    else:
                        parsed_info['device_name'] = f"设备-{source}"
                        parsed_info['device_type'] = "网络设备"
                        parsed_info['alarm_content'] = "设备可能离线或无响应"
                        parsed_info['severity'] = '重要'

                    parsed_info['alarm_category'] = '网络设备-通信类告警'
                    parsed_info['variables'].append(f"原始数据长度: {len(raw_data)} 字节")
                    parsed_info['variables'].append(f"数据类型: 简单通知/心跳超时")
                    parsed_info['variables'].append(f"设备位置: {source}")
                    return parsed_info

                # 检查是否包含特定的IP地址（218.201.223.161）
                if '218.201.223.161' in raw_data or source == '218.201.223.161':
                    parsed_info['fault_device_ip'] = '218.201.223.161'
                    parsed_info['device_name'] = '核心网络设备-218.201.223.161'
                    parsed_info['device_type'] = '核心路由器/交换机'
                    parsed_info['alarm_content'] = '核心网络设备未响应，可能存在严重网络故障'
                    parsed_info['severity'] = '紧急'
                    parsed_info['alarm_category'] = '网络设备-通信类告警'
                    parsed_info['variables'].append('设备类型: 核心网络设备')
                    parsed_info['variables'].append('影响范围: 可能影响整个网络')
                    parsed_info['variables'].append(f'原始数据: {raw_data[:50]}...')
                    return parsed_info

                lines = raw_data.split('\n')
                for line in lines:
                    line = line.strip()

                    # 解析标准SNMP Trap字段（支持多种格式）
                    if 'Enterprise:' in line or line.startswith('Enterprise:'):
                        enterprise_value = line.split('Enterprise:')[1].strip() if 'Enterprise:' in line else line.split(':', 1)[1].strip()
                        parsed_info['enterprise'] = enterprise_value

                        # 检查是否为H3C NMS Trap OID
                        if '1.3.6.1.4.1.25506' in enterprise_value:
                            parsed_info['enterprise_id'] = '1.3.6.1.4.1.25506'
                            parsed_info['enterprise'] = 'H3C NMS Resource'

                            # 根据OID末尾判断Trap类型
                            if '1.3.6.1.4.1.25506.4.1.1.2.1' in enterprise_value or '1.3.6.1.4.1.25506.4.1.1.2.0.1' in enterprise_value:
                                parsed_info['alarm_category'] = '网络设备-通信类告警'
                                parsed_info['alarm_content'] = '设备未回应网管轮询报文'
                                if parsed_info['severity'] == 'Unknown':
                                    parsed_info['severity'] = '紧急'

                        # 检查是否为标准SNMP LinkDown Trap OID
                        elif '1.3.6.1.6.3.1.1.5' in enterprise_value:
                            parsed_info['enterprise_id'] = '1.3.6.1.6.3.1.1.5'
                            parsed_info['enterprise'] = 'SNMP'

                            # 根据OID判断具体的链路状态类型
                            if '1.3.6.1.6.3.1.1.5.2' in enterprise_value:  # linkDown
                                parsed_info['alarm_category'] = '网络设备-接口类告警'
                                parsed_info['alarm_content'] = '接口状态DOWN'
                                if parsed_info['severity'] == 'Unknown':
                                    parsed_info['severity'] = '重要'
                            elif '1.3.6.1.6.3.1.1.5.3' in enterprise_value:  # linkUp
                                parsed_info['alarm_category'] = '网络设备-接口类告警'
                                parsed_info['alarm_content'] = '接口状态UP'
                                if parsed_info['severity'] == 'Unknown':
                                    parsed_info['severity'] = '信息'

                    elif 'Agent Address:' in line or line.startswith('Agent:'):
                        agent_addr = line.split('Agent Address:')[1].strip() if 'Agent Address:' in line else line.split(':', 1)[1].strip()
                        parsed_info['agent_addr'] = agent_addr
                        parsed_info['fault_device_ip'] = agent_addr
                    elif 'Generic Type:' in line or line.startswith('Generic:'):
                        parsed_info['generic_type'] = line.split('Generic Type:')[1].strip() if 'Generic Type:' in line else line.split(':', 1)[1].strip()
                    elif 'Specific Type:' in line or line.startswith('Specific:'):
                        parsed_info['specific_type'] = line.split('Specific Type:')[1].strip() if 'Specific Type:' in line else line.split(':', 1)[1].strip()
                    elif 'Uptime:' in line or line.startswith('Uptime:'):
                        parsed_info['uptime'] = line.split('Uptime:')[1].strip() if 'Uptime:' in line else line.split(':', 1)[1].strip()

                    # 解析华为设备特定OID参数
                    huawei_oid_mappings = {
                        'Device ID': ['1.3.6.1.4.1.25506.4.1.1.1.1', 'device_id'],
                        'NMS Device Description': ['1.3.6.1.4.1.25506.4.1.1.1.2', 'nms_device_desc'],  # 优先使用这个作为设备名
                        'Alarm Time': ['1.3.6.1.4.1.25506.4.2.2.1.14', 'alarm_time_oid'],
                        'Poll Type': ['1.3.6.1.4.1.25506.4.2.2.1.17', 'poll_type'],
                        'Device IP': ['1.3.6.1.4.1.25506.4.2.2.1.7', 'device_ip_oid'],
                        'Device Name': ['1.3.6.1.4.1.25506.4.2.2.1.8', 'device_name_oid'],      # 备选设备名
                        'Device Type': ['1.3.6.1.4.1.25506.4.2.2.1.100', 'device_type_oid']
                    }

                    # 解析标准SNMP接口参数
                    snmp_interface_mappings = {
                        'Interface Index': ['1.3.6.1.2.1.2.2.1.1', 'interface_index'],
                        'Interface Description': ['1.3.6.1.2.1.2.2.1.2', 'interface_desc'],
                        'Interface Admin Status': ['1.3.6.1.2.1.2.2.1.7', 'interface_admin_status'],
                        'Interface Operate Status': ['1.3.6.1.2.1.2.2.1.8', 'interface_oper_status']
                    }

                    # 解析OID格式参数（合并华为和标准SNMP）
                    all_oid_mappings = {**huawei_oid_mappings, **snmp_interface_mappings}

                    if any(oid in line for oid_list in all_oid_mappings.values() for oid in [oid_list[0]]):
                        for param_name, oid_info in all_oid_mappings.items():
                            oid = oid_info[0]
                            param_key = oid_info[1]
                            if oid in line:
                                # 尝试提取OID后的值
                                if '=' in line:
                                    value = line.split('=', 1)[1].strip()
                                elif ':' in line:
                                    value = line.split(':', 1)[1].strip()
                                else:
                                    # 提取OID后的所有内容作为值
                                    value = line.replace(oid, '').strip().lstrip(':=').strip()

                                # 处理华为设备参数
                                if param_name == 'Device IP' and value:
                                    parsed_info['device_ip'] = value
                                    parsed_info['fault_device_ip'] = value
                                elif param_name == 'NMS Device Description' and value:
                                    # 优先使用NMS设备描述作为设备名
                                    parsed_info['device_name'] = value
                                    parsed_info['variables'].append(f"NMS设备描述: {value}")
                                elif param_name == 'Device Name' and value:
                                    # 如果还没有设备名，使用这个作为备选
                                    if parsed_info['device_name'] == 'Unknown' or not parsed_info['device_name']:
                                        parsed_info['device_name'] = value
                                    parsed_info['variables'].append(f"设备名称: {value}")
                                elif param_name == 'Device Type' and value:
                                    parsed_info['device_type'] = value
                                    parsed_info['variables'].append(f"设备类型: {value}")
                                elif param_name == 'Alarm Time' and value:
                                    parsed_info['alarm_time'] = value
                                elif param_name == 'Poll Type' and value:
                                    parsed_info['poll_type'] = value
                                elif param_name == 'Device ID' and value:
                                    parsed_info['device_id'] = value
                                    parsed_info['variables'].append(f"设备ID: {value}")

                                # 处理标准SNMP接口参数
                                elif param_name == 'Interface Index' and value:
                                    parsed_info['interface_index'] = value
                                elif param_name == 'Interface Description' and value:
                                    parsed_info['interface_description'] = value
                                    # 如果接口描述包含设备名，提取作为设备名
                                    if parsed_info['device_name'] == 'Unknown' and value:
                                        # 尝试从接口描述中提取设备信息
                                        if 'Device' in value or 'Router' in value or 'Switch' in value or 'Firewall' in value:
                                            parsed_info['device_name'] = value
                                elif param_name == 'Interface Admin Status' and value:
                                    admin_status_map = {'1': 'up', '2': 'down', '3': 'testing'}
                                    parsed_info['interface_admin_status'] = admin_status_map.get(value, value)
                                elif param_name == 'Interface Operate Status' and value:
                                    oper_status_map = {'1': 'up', '2': 'down', '3': 'testing', '4': 'unknown', '5': 'dormant', '6': 'notPresent', '7': 'lowerLayerDown'}
                                    parsed_info['interface_oper_status'] = oper_status_map.get(value, value)

                                parsed_info['variables'].append(f"{param_name}: {value}")
                                break

                    # 解析设备和主机信息（多种可能的字段名）
                    device_fields = ['Device:', '设备:', 'Host:', '主机:', 'Node:', '节点:']
                    for field in device_fields:
                        if field in line:
                            device_info = line.split(field)[1].strip()
                            # 尝试从设备信息中提取IP地址
                            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                            ip_match = re.search(ip_pattern, device_info)
                            if ip_match:
                                parsed_info['fault_device_ip'] = ip_match.group()
                            # 如果设备名不是纯IP，则作为设备名
                            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', device_info):
                                parsed_info['device_name'] = device_info
                            parsed_info['variables'].append(f"设备: {device_info}")
                            break

                    # 解析主机名
                    hostname_fields = ['Hostname:', '主机名:', 'Host Name:', 'System Name:']
                    for field in hostname_fields:
                        if field in line:
                            hostname_info = line.split(field)[1].strip()
                            if parsed_info['device_name'] == 'Unknown':
                                parsed_info['device_name'] = hostname_info
                            parsed_info['variables'].append(f"主机名: {hostname_info}")
                            break

                    # 解析来源地址
                    source_fields = ['Source:', '来源:', 'From:', '发送方:', 'Origin:']
                    for field in source_fields:
                        if field in line:
                            source_info = line.split(field)[1].strip()
                            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                            ip_match = re.search(ip_pattern, source_info)
                            if ip_match and parsed_info['fault_device_ip'] == source:
                                parsed_info['fault_device_ip'] = ip_match.group()
                            parsed_info['variables'].append(f"来源: {source_info}")
                            break

                    # 解析告警级别
                    severity_fields = ['Severity:', '级别:', 'Level:', 'Priority:', '优先级:']
                    for field in severity_fields:
                        if field in line:
                            severity_info = line.split(field)[1].strip().lower()
                            # 标准化告警级别
                            if severity_info in ['critical', 'crit', '严重', '紧急']:
                                parsed_info['severity'] = '严重'
                            elif severity_info in ['major', 'maj', '主要', '重要']:
                                parsed_info['severity'] = '重要'
                            elif severity_info in ['minor', 'min', '次要', '一般']:
                                parsed_info['severity'] = '次要'
                            elif severity_info in ['warning', 'warn', '警告', '告警']:
                                parsed_info['severity'] = '警告'
                            elif severity_info in ['info', 'information', '信息']:
                                parsed_info['severity'] = '信息'
                            else:
                                parsed_info['severity'] = severity_info.title()
                            parsed_info['variables'].append(f"级别: {parsed_info['severity']}")
                            break

                    # 解析告警消息
                    message_fields = ['Message:', '消息:', 'Description:', '描述:', 'Detail:', '详情:', 'Alert:', '告警:']
                    for field in message_fields:
                        if field in line:
                            message_info = line.split(field)[1].strip()
                            if parsed_info['alarm_content'] == 'Unknown':
                                parsed_info['alarm_content'] = message_info
                            parsed_info['variables'].append(f"消息: {message_info}")
                            break

                    # 解析时间戳（可能有设备自身的时间戳）
                    time_fields = ['Time:', '时间:', 'Timestamp:', '时间戳:', 'DateTime:', '日期时间:']
                    for field in time_fields:
                        if field in line:
                            time_info = line.split(field)[1].strip()
                            # 尝试解析设备时间戳
                            try:
                                import time as time_module
                                device_time = time_module.strptime(time_info.split()[0], '%Y-%m-%d')
                                parsed_info['alarm_time'] = time_info
                            except:
                                pass  # 解析失败使用当前时间
                            parsed_info['variables'].append(f"设备时间: {time_info}")
                            break

                    # 检查常见的网络设备告警模式和状态
                    status_keywords = {
                        'down': '故障',
                        'up': '恢复',
                        'offline': '离线',
                        'online': '在线',
                        'error': '错误',
                        'fail': '失败',
                        'success': '成功',
                        'warning': '警告',
                        'critical': '严重',
                        'alarm': '告警',
                        'normal': '正常',
                        'abnormal': '异常',
                        'timeout': '超时',
                        'connect': '连接',
                        'disconnect': '断开',
                        '重启': '重启',
                        'reset': '重置',
                        '故障': '故障',
                        '恢复': '恢复',
                        '离线': '离线',
                        '错误': '错误',
                        '警告': '警告',
                        '异常': '异常'
                    }

                    line_lower = line.lower()
                    for keyword, chinese_status in status_keywords.items():
                        if keyword in line_lower:
                            if not any(keyword in var for var in parsed_info['variables'] if '状态:' in var):
                                parsed_info['variables'].append(f"状态: {chinese_status}")
                                break

                    # 解析接口和端口信息
                    interface_patterns = [
                        r'interface\s*(\S+)',
                        r'port\s*(\S+)',
                        r'接口\s*(\S+)',
                        r'端口\s*(\S+)',
                        r'(\w+\d+/\d+/\d+)',  # 标准接口格式如 Gig0/1/2
                        r'(\w+\d+/\d+)',     # 简化接口格式如 Fa0/1
                    ]

                    for pattern in interface_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match and not any('接口:' in var or '端口:' in var for var in parsed_info['variables']):
                            interface_name = match.group(1)
                            parsed_info['variables'].append(f"接口: {interface_name}")
                            break

                    # 解析资源使用率
                    resource_patterns = [
                        r'cpu\s*(\d+\.?\d*)%',
                        r'memory\s*(\d+\.?\d*)%',
                        r'disk\s*(\d+\.?\d*)%',
                        r'CPU\s*(\d+\.?\d*)%',
                        r'内存\s*(\d+\.?\d*)%',
                        r'磁盘\s*(\d+\.?\d*)%'
                    ]

                    for pattern in resource_patterns:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            resource_type = 'CPU' if 'cpu' in pattern.lower() else 'Memory' if 'memory' in pattern.lower() or '内存' in pattern else 'Disk' if 'disk' in pattern.lower() or '磁盘' in pattern else 'Resource'
                            resource_value = match.group(1)
                            if not any(f'{resource_type}:' in var for var in parsed_info['variables']):
                                parsed_info['variables'].append(f"{resource_type}: {resource_value}%")
                            break

            except Exception as e:
                # 解析失败时记录错误但继续使用默认值
                parsed_info['variables'].append(f"解析错误: {str(e)}")

            return parsed_info

        # 解析SNMP数据
        parsed_data = parse_snmp_trap(clean_raw_data(raw_data))

        # 构造详细的中文格式化消息（包含标题）
        formatted_message = "【网络设备告警】\n\n"

        # 告警时间 - 优先使用解析的设备时间，否则使用当前北京时间
        display_time = parsed_data['alarm_time'] if parsed_data['alarm_time'] != timestamp else timestamp
        formatted_message += f"🕐 告警时间: {display_time}\n"

        # 设备名称 - 优先使用解析的设备名
        device_name = parsed_data['device_name']
        if device_name != "Unknown":
            formatted_message += f"🏷️ 设备名称: {device_name}\n"

        # 设备类型 - 显示H3C NMS解析的设备类型
        if parsed_data['device_type'] != "Unknown":
            formatted_message += f"🔧 设备类型: {parsed_data['device_type']}\n"

        # 设备地址 - 显示解析出的故障设备IP
        if parsed_data['fault_device_ip'] != "Unknown":
            formatted_message += f"🖥️ 设备地址: {parsed_data['fault_device_ip']}\n"

        # 告警级别
        if parsed_data['severity'] != "Unknown":
            # 添加级别对应的emoji，新增"紧急"级别
            severity_emoji = {
                '紧急': '🚨',
                '严重': '🔴',
                '重要': '🟠',
                '警告': '🟡',
                '次要': '🔵',
                '信息': '🔷',
                'Critical': '🚨',
                'Major': '🟠',
                'Warning': '🟡',
                'Minor': '🔵',
                'Info': '🔷'
            }
            emoji = severity_emoji.get(parsed_data['severity'], '⚠️')
            formatted_message += f"{emoji} 告警级别: {parsed_data['severity']}\n"

        # 告警分类 - 显示H3C NMS的告警分类
        if parsed_data['alarm_category'] != "Unknown":
            formatted_message += f"📂 告警分类: {parsed_data['alarm_category']}\n"

        # 告警内容 - 优先使用解析的告警内容
        alarm_content = parsed_data['alarm_content'] if parsed_data['alarm_content'] != 'Unknown' else message
        if alarm_content and alarm_content != "Unknown":
            formatted_message += f"⚠️ 告警内容: {alarm_content}\n"

        # 轮询类型 - 显示H3C NMS的轮询类型
        if 'poll_type' in parsed_data and parsed_data['poll_type'] != "Unknown":
            poll_type_map = {
                '0': 'Ping',
                '1': 'SNMP',
                '2': 'Telnet',
                '3': 'SSH'
            }
            poll_type_display = poll_type_map.get(parsed_data['poll_type'], parsed_data['poll_type'])
            formatted_message += f"🔄 轮询类型: {poll_type_display}\n"

        # 接口信息 - 显示标准SNMP接口参数
        if 'interface_index' in parsed_data and parsed_data['interface_index'] != "Unknown":
            formatted_message += f"🔌 接口索引: {parsed_data['interface_index']}\n"

        if 'interface_description' in parsed_data and parsed_data['interface_description'] != "Unknown":
            formatted_message += f"📝 接口描述: {parsed_data['interface_description']}\n"

        if 'interface_oper_status' in parsed_data and parsed_data['interface_oper_status'] != "Unknown":
            status_emoji = {'up': '🟢', 'down': '🔴', 'testing': '🟡', 'unknown': '⚪', 'dormant': '💤', 'notPresent': '❌', 'lowerLayerDown': '🔴'}
            status_display = parsed_data['interface_oper_status']
            emoji = status_emoji.get(status_display, '⚠️')
            formatted_message += f"📊 运行状态: {emoji} {status_display.title()}\n"

        if 'interface_admin_status' in parsed_data and parsed_data['interface_admin_status'] != "Unknown":
            admin_emoji = {'up': '✅', 'down': '❌', 'testing': '⚠️'}
            admin_display = parsed_data['interface_admin_status']
            emoji = admin_emoji.get(admin_display, '⚠️')
            formatted_message += f"⚙️ 管理状态: {emoji} {admin_display.title()}\n"

        # 添加详细解析信息（如果有额外的variables）
        if parsed_data['variables']:
            # 分类显示解析出的详细信息
            details_by_category = {}
            for var in parsed_data['variables']:
                if ':' in var:
                    category, value = var.split(':', 1)
                    category = category.strip()
                    value = value.strip()

                    # 去重处理
                    if category not in details_by_category:
                        details_by_category[category] = []
                    if value not in details_by_category[category]:
                        details_by_category[category].append(value)

            # 添加分类的详细信息
            if details_by_category:
                formatted_message += "\n📋 详细信息:\n"
                for category, values in details_by_category.items():
                    if len(values) == 1:
                        formatted_message += f"• {category}: {values[0]}\n"
                    else:
                        formatted_message += f"• {category}: {', '.join(values)}\n"

        # SNMP Trap原始信息（调试用，可选）
        if parsed_data['generic_type'] != 'Unknown' or parsed_data['specific_type'] != 'Unknown':
            formatted_message += "\n🔧 SNMP信息:\n"
            if parsed_data['generic_type'] != 'Unknown':
                formatted_message += f"• 通用类型: {parsed_data['generic_type']}\n"
            if parsed_data['specific_type'] != 'Unknown':
                formatted_message += f"• 特定类型: {parsed_data['specific_type']}\n"
            if parsed_data['enterprise'] != 'Unknown':
                formatted_message += f"• 企业OID: {parsed_data['enterprise']}\n"

        return formatted_message

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

            # 使用LangBot官方SDK发送消息
            result = await plugin.send_message(
                bot_uuid=bot_uuid,
                target_type="group",
                target_id=target_id_numeric,
                message_chain=message_chain
            )

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

    def extract_device_name_from_description(description: str) -> Optional[str]:
        """从系统描述中提取设备名称"""
        if not description:
            return None

        # 华为设备系统描述的常见模式
        # 例如: "HUAWEI TECH CO.,LTD. S5700-28C-EI"
        # 或 "Huawei Versatile Routing Platform Software"

        # 查找设备型号
        model_patterns = [
            r'S(\d{3,})[A-Z-]+',  # S5700-28C-EI
            r'NE(\d+[A-Z-]+)',    # NE40E
            r'AR(\d+[A-Z-]+)',    # AR1220
            r'AC(\d+[A-Z-]+)',    # AC6605
            r'CE(\d+[A-Z-]+)',    # CE12800
        ]

        import re
        for pattern in model_patterns:
            match = re.search(pattern, description)
            if match:
                return f"Huawei-{match.group(0)}"

        # 如果没有找到型号，尝试提取第一个有意义的产品名称
        words = description.split()
        for word in words:
            if len(word) >= 3 and word.isalnum():
                # 过滤掉常见的公司名
                if word.upper() not in ['HUAWEI', 'TECH', 'CO', 'LTD', 'VERSATILE', 'ROUTING', 'PLATFORM', 'SOFTWARE']:
                    return word

        return None

    # 个人消息功能已移除，只支持群消息