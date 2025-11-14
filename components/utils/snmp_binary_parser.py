#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNMP二进制包解析器
解析真实SNMP trap二进制数据
"""

import struct
import re
from typing import Dict, Any, Optional


class SNMPBinaryParser:
    """SNMP二进制包解析器"""

    def __init__(self):
        """初始化解析器"""
        self.version_map = {
            0: 'SNMPv1',
            1: 'SNMPv2c',
            2: 'SNMPv3'
        }

        self.generic_trap_map = {
            0: 'coldStart',
            1: 'warmStart',
            2: 'linkDown',
            3: 'linkUp',
            4: 'authenticationFailure',
            5: 'egpNeighborLoss',
            6: 'enterpriseSpecific'
        }

    def parse_snmp_trap(self, data: bytes) -> Dict[str, Any]:
        """
        解析SNMP trap二进制数据

        Args:
            data: SNMP trap二进制数据

        Returns:
            解析后的字典信息
        """
        try:
            # 首先尝试作为ASCII文本解析
            ascii_result = self.parse_as_ascii(data)
            if ascii_result['success']:
                return ascii_result

            # 然后尝试作为二进制SNMP解析
            binary_result = self.parse_as_binary(data)
            if binary_result['success']:
                return binary_result

            # 最后尝试提取可读的字符串
            return self.extract_readable_strings(data)

        except Exception as e:
            return {
                'success': False,
                'error': f"解析失败: {str(e)}",
                'raw_data': data.hex() if isinstance(data, bytes) else str(data)
            }

    def parse_as_ascii(self, data: bytes) -> Dict[str, Any]:
        """将数据作为ASCII文本解析"""
        try:
            # 尝试解码为ASCII
            text = data.decode('ascii', errors='ignore')

            # 使用正则表达式提取SNMP字段
            result = {
                'success': True,
                'parse_type': 'ascii',
                'community': self.extract_community(text),
                'enterprise': self.extract_enterprise(text),
                'agent_addr': self.extract_agent_address(text),
                'generic_trap': self.extract_generic_trap(text),
                'specific_trap': self.extract_specific_trap(text),
                'time_stamp': self.extract_timestamp(text),
                'variables': self.extract_variables(text)
            }

            # 如果提取到了有用信息，返回结果
            if any([result['community'], result['agent_addr'],
                   result['enterprise'], result['variables']]):
                return result

            return {'success': False, 'error': 'ASCII解析未找到有效SNMP字段'}

        except Exception:
            return {'success': False, 'error': 'ASCII解析失败'}

    def parse_as_binary(self, data: bytes) -> Dict[str, Any]:
        """将数据作为二进制SNMP包解析"""
        try:
            if len(data) < 10:
                return {'success': False, 'error': '数据太短，不是有效的SNMP包'}

            # 查找SNMP版本
            version = self.extract_version_from_binary(data)

            # 查找community字符串
            community = self.extract_community_from_binary(data)

            # 查找agent address
            agent_addr = self.extract_ip_from_binary(data)

            # 查找enterprise OID
            enterprise = self.extract_enterprise_from_binary(data)

            # 查找变量绑定
            variables = self.extract_variables_from_binary(data)

            result = {
                'success': True,
                'parse_type': 'binary',
                'version': version,
                'community': community,
                'enterprise': enterprise,
                'agent_addr': agent_addr,
                'variables': variables
            }

            # 如果提取到了有用信息，返回结果
            if any([community, agent_addr, enterprise, variables]):
                return result

            return {'success': False, 'error': '二进制解析未找到有效SNMP字段'}

        except Exception as e:
            return {'success': False, 'error': f'二进制解析失败: {str(e)}'}

    def extract_community(self, text: str) -> Optional[str]:
        """从文本中提取community字符串"""
        # 查找常见的community字符串
        communities = ['public', 'private', 'cisco', 'huawei', 'h3c']
        for comm in communities:
            if comm in text.lower():
                return comm
        return None

    def extract_enterprise(self, text: str) -> Optional[str]:
        """从文本中提取enterprise OID"""
        # 查找OID模式
        oid_pattern = r'(\d+(?:\.\d+)+)'
        matches = re.findall(oid_pattern, text)

        for match in matches:
            # 寻找可能的企业OID
            if len(match) > 6 and match.count('.') >= 3:
                return match
        return None

    def extract_agent_address(self, text: str) -> Optional[str]:
        """从文本中提取agent IP地址"""
        # 查找IP地址模式
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = re.findall(ip_pattern, text)

        for ip in matches:
            # 过滤掉明显不是IP的数字
            if not (ip.startswith('0.') or ip.startswith('255.')):
                return ip
        return None

    def extract_generic_trap(self, text: str) -> Optional[int]:
        """从文本中提取generic trap类型"""
        # 查找数字0-6作为trap类型
        trap_pattern = r'\b([0-6])\b'
        match = re.search(trap_pattern, text)
        if match:
            return int(match.group(1))
        return None

    def extract_specific_trap(self, text: str) -> Optional[int]:
        """从文本中提取specific trap类型"""
        # 查找特定trap数字
        trap_pattern = r'\b(\d{1,3})\b'
        matches = re.findall(trap_pattern, text)
        for match in matches:
            num = int(match)
            if num > 6 and num < 1000:  # 通常specific trap在6-1000之间
                return num
        return None

    def extract_timestamp(self, text: str) -> Optional[str]:
        """从文本中提取时间戳"""
        # 查找看起来像时间戳的数字
        timestamp_pattern = r'\b(\d{10,13})\b'
        match = re.search(timestamp_pattern, text)
        if match:
            return match.group(1)
        return None

    def extract_variables(self, text: str) -> list:
        """从文本中提取变量绑定"""
        variables = []

        # 提取所有IP地址
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_matches = re.findall(ip_pattern, text)
        for ip in ip_matches:
            if not (ip.startswith('0.') or ip.startswith('255.')):
                variables.append(('ip_address', ip))

        # 提取看起来像接口索引的数字
        interface_pattern = r'\b(\d{1,4})\b'
        matches = re.findall(interface_pattern, text)
        for match in matches:
            num = int(match)
            if 1 <= num <= 9999:  # 合理的接口索引范围
                variables.append(('interface_index', str(num)))

        return variables

    def extract_version_from_binary(self, data: bytes) -> Optional[str]:
        """从二进制数据中提取SNMP版本"""
        # 查找版本字节模式
        if len(data) >= 3 and data[0:3] in [b'\x02\x01\x00', b'\x02\x01\x01']:
            version = data[2] if len(data) > 2 else 0
            return self.version_map.get(version, f'Unknown({version})')
        return None

    def extract_community_from_binary(self, data: bytes) -> Optional[str]:
        """从二进制数据中提取community字符串"""
        # 查找ASCII字符串
        for i in range(len(data) - 10):
            if data[i] == 0x04:  # OCTET STRING tag
                length = data[i + 1]
                if length > 0 and length < 32 and i + 1 + length < len(data):
                    community = data[i + 2:i + 2 + length].decode('ascii', errors='ignore')
                    if community.isprintable():
                        return community
        return None

    def extract_ip_from_binary(self, data: bytes) -> Optional[str]:
        """从二进制数据中提取IP地址"""
        # 查找4字节的IP地址
        for i in range(len(data) - 4):
            # 检查是否为有效的IP地址字节
            if (0 < data[i] <= 255 and 0 <= data[i+1] <= 255 and
                0 <= data[i+2] <= 255 and 0 < data[i+3] <= 255):
                # 避免明显不是IP的模式
                if not (data[i] == 255 and data[i+1] == 255):
                    ip = f"{data[i]}.{data[i+1]}.{data[i+2]}.{data[i+3]}"
                    # 检查是否为合理的IP
                    if not ip.startswith('0.') and not ip.startswith('255.'):
                        return ip
        return None

    def extract_enterprise_from_binary(self, data: bytes) -> Optional[str]:
        """从二进制数据中提取enterprise OID"""
        # 查找OID字节模式
        oid_parts = []
        for i in range(len(data) - 1):
            if data[i] == 0x06:  # OBJECT IDENTIFIER tag
                length = data[i + 1]
                if length > 0 and i + 1 + length < len(data):
                    oid_bytes = data[i + 2:i + 2 + length]
                    oid = self.parse_oid_bytes(oid_bytes)
                    if oid and len(oid) > 6:  # 企业OID通常比较长
                        return oid
        return None

    def extract_variables_from_binary(self, data: bytes) -> list:
        """从二进制数据中提取变量绑定"""
        variables = []

        # 提取IP地址
        ip = self.extract_ip_from_binary(data)
        if ip:
            variables.append(('ip_address', ip))

        # 提取接口索引
        for i in range(len(data) - 1):
            if data[i] == 0x02:  # INTEGER tag
                length = data[i + 1]
                if length == 1 and i + 2 < len(data):
                    value = data[i + 2]
                    if 1 <= value <= 9999:
                        variables.append(('interface_index', str(value)))

        return variables

    def parse_oid_bytes(self, oid_bytes: bytes) -> Optional[str]:
        """解析OID字节数组"""
        try:
            if len(oid_bytes) == 0:
                return None

            # 简单的OID解析
            if oid_bytes[0] < 40:
                first = oid_bytes[0]
                second = 0
            else:
                first = oid_bytes[0] // 40
                second = oid_bytes[0] % 40

            oid_parts = [str(first), str(second)]
            i = 1
            while i < len(oid_bytes):
                if oid_bytes[i] & 0x80:
                    # 多字节长度
                    value = 0
                    for j in range(3):  # 最多3个字节
                        if i + j < len(oid_bytes):
                            value = (value << 7) | (oid_bytes[i + j] & 0x7f)
                            if not (oid_bytes[i + j] & 0x80):
                                oid_parts.append(str(value))
                                i += j + 1
                                break
                else:
                    oid_parts.append(str(oid_bytes[i]))
                    i += 1

            return '.'.join(oid_parts)
        except:
            return None

    def extract_readable_strings(self, data: bytes) -> Dict[str, Any]:
        """从二进制数据中提取可读字符串"""
        try:
            text = data.decode('ascii', errors='ignore')

            # 查找所有可打印的字符串
            strings = re.findall(r'[a-zA-Z0-9.-]{3,}', text)

            # 提取IP地址
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, text)

            return {
                'success': True,
                'parse_type': 'extract_strings',
                'readable_strings': strings,
                'ip_addresses': [ip for ip in ips if not ip.startswith('0.')],
                'raw_length': len(data),
                'sample_text': text[:100]
            }
        except:
            return {
                'success': False,
                'error': '无法提取可读字符串',
                'raw_data': data.hex() if isinstance(data, bytes) else str(data)
            }


def parse_snmp_binary_data(data: bytes) -> Dict[str, Any]:
    """
    便捷函数：解析SNMP二进制数据

    Args:
        data: SNMP trap二进制数据

    Returns:
        解析结果字典
    """
    parser = SNMPBinaryParser()
    return parser.parse_snmp_trap(data)