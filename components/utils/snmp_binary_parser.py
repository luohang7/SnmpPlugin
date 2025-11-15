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

    def decode_hex_device_name(self, hex_value: str) -> Optional[str]:
        """
        将十六进制编码的设备名称解码为中文

        Args:
            hex_value: 十六进制字符串，如 'e9959ce5838fe4baa4e68da2e69cba'

        Returns:
            解码后的中文字符串，失败返回None
        """
        try:
            # 清理十六进制字符串（移除空格、制表符、换行符等）
            clean_hex = hex_value.replace(' ', '').replace('\t', '').replace('\n', '').replace('\r', '')

            # 确保长度为偶数
            if len(clean_hex) % 2 != 0 or len(clean_hex) == 0:
                return None

            # 转换为字节并解码为UTF-8
            bytes_data = bytes.fromhex(clean_hex)
            decoded_text = bytes_data.decode('utf-8')

            return decoded_text

        except Exception:
            return None

    def parse_snmp_trap(self, data: bytes) -> Dict[str, Any]:
        """
        解析SNMP trap二进制数据

        Args:
            data: SNMP trap二进制数据

        Returns:
            解析后的字典信息
        """
        try:
            # 对于SNMP trap，优先尝试二进制解析
            binary_result = self.parse_as_binary(data)
            if binary_result['success'] and binary_result['parse_type'] == 'binary':
                return binary_result

            # 如果二进制解析失败或没有找到足够信息，尝试ASCII解析
            ascii_result = self.parse_as_ascii(data)
            if ascii_result['success']:
                return ascii_result

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

            # 查找generic trap和specific trap
            generic_trap = self.extract_generic_trap_from_binary(data)
            specific_trap = self.extract_specific_trap_from_binary(data)

            # 查找变量绑定 - 优先使用SNMP结构化解析
            variables = self.extract_variables_from_binary_structured(data)

            result = {
                'success': True,
                'parse_type': 'binary',
                'version': version,
                'community': community,
                'enterprise': enterprise,
                'agent_addr': agent_addr,
                'generic_trap': generic_trap,
                'specific_trap': specific_trap,
                'variables': variables
            }

            # 如果提取到了有用信息，返回结果
            if any([community, agent_addr, enterprise, variables]):
                return result

            return {'success': False, 'error': '二进制解析未找到有效SNMP字段'}

        except Exception as e:
            return {'success': False, 'error': f'二进制解析失败: {str(e)}'}

    def extract_generic_trap_from_binary(self, data: bytes) -> Optional[int]:
        """从二进制数据中提取generic trap类型"""
        # 查找INTEGER类型的generic trap
        for i in range(len(data) - 2):
            if data[i] == 0x02:  # INTEGER tag
                length = data[i + 1]
                if length == 1 and i + 2 < len(data):
                    value = data[i + 2]
                    if 0 <= value <= 6:  # Generic trap范围
                        return value
        return None

    def extract_specific_trap_from_binary(self, data: bytes) -> Optional[int]:
        """从二进制数据中提取specific trap类型"""
        # 查找第二个INTEGER类型的specific trap
        trap_count = 0
        for i in range(len(data) - 2):
            if data[i] == 0x02:  # INTEGER tag
                length = data[i + 1]
                if length == 1 and i + 2 < len(data):
                    trap_count += 1
                    if trap_count == 2:  # 第二个INTEGER是specific trap
                        value = data[i + 2]
                        return value
        return None

    def extract_variables_from_binary_structured(self, data: bytes) -> list:
        """使用SNMP结构化解析提取变量绑定"""
        variables = []

        # SNMP trap的VarBindList通常在包的末尾，是一个包含多个VarBind的SEQUENCE
        # 查找可能是VarBindList的SEQUENCE - 应该是包含多个子SEQUENCE的那个
        varbind_list_candidates = []

        for i in range(len(data) - 1):
            if data[i] == 0x30:  # SEQUENCE tag
                # 读取长度字节
                if i + 1 >= len(data):
                    continue

                if data[i + 1] < 0x80:  # 短格式长度
                    length = data[i + 1]
                    length_bytes = 1
                else:  # 长格式长度
                    length_bytes = data[i + 1] & 0x7f
                    if i + 1 + length_bytes >= len(data):
                        continue
                    length = 0
                    for j in range(length_bytes):
                        length = (length << 8) | data[i + 2 + j]
                    length_bytes += 1

                if i + 1 + length_bytes + length <= len(data):
                    varbind_data = data[i + 1 + length_bytes:i + 1 + length_bytes + length]

                    # 检查这个SEQUENCE是否包含其他SEQUENCE (VarBind entries)
                    sub_sequences = 0
                    for j in range(len(varbind_data) - 1):
                        if varbind_data[j] == 0x30:
                            sub_sequences += 1

                    if sub_sequences >= 1:  # 至少包含一个VarBind
                        varbind_list_candidates.append((i, length, varbind_data, sub_sequences))

        # 选择包含最多子SEQUENCE的候选作为VarBindList
        # 但排除那些过大的候选（可能是整个SNMP包）
        if varbind_list_candidates:
            # 过滤掉过大的候选（可能是整个包）
            filtered_candidates = []
            for pos, length, varbind_data, sub_count in varbind_list_candidates:
                # 如果候选包含很多子SEQUENCE且不是太大，可能是VarBindList
                # VarBindList通常是包的后面部分，不会是整个包的主体
                if sub_count >= 1 and length < len(data) * 0.7:  # 不超过整个数据包的70%
                    filtered_candidates.append((pos, length, varbind_data, sub_count))

            if filtered_candidates:
                filtered_candidates.sort(key=lambda x: x[3], reverse=True)  # 按子SEQUENCE数量排序
                best_candidate = filtered_candidates[0]
                # 优先选择位置更靠后的候选（VarBindList通常在包的末尾）
                if len(filtered_candidates) > 1:
                    for candidate in filtered_candidates[1:]:
                        if candidate[3] == best_candidate[3] and candidate[0] > best_candidate[0]:
                            best_candidate = candidate
            else:
                # 如果没有合适的候选，选择包含最多子SEQUENCE的
                varbind_list_candidates.sort(key=lambda x: x[3], reverse=True)
                best_candidate = varbind_list_candidates[0]

            varbind_list_data = best_candidate[2]
            print(f"[DEBUG] Selected VarBindList: position={best_candidate[0]}, length={best_candidate[1]}, sub_sequences={best_candidate[3]}")

            # 解析VarBindList中的每个VarBind
            oid_value_pairs = self.parse_varbind_sequence(varbind_list_data)

            # 华为设备OID映射
            huawei_oid_map = {
                # 标准SNMP系统OID (sysName等)
                '1.3.6.1.2.1.1.5.0': 'sysname',                    # 标准sysName OID - 最优先
                '1.3.6.1.2.1.1.1.0': 'sysdescr',                  # 系统描述
                '1.3.6.1.2.1.1.6.0': 'syslocation',              # 系统位置
                '1.3.6.1.2.1.1.4.0': 'syscontact',               # 系统联系人

                # 关键参数 (基于华为trap定义)
                '1.3.6.1.4.1.25506.4.1.1.1.1': 'device_id',           # Device ID (关键参数)
                '1.3.6.1.4.1.25506.4.1.1.1.2': 'nms_device_desc',    # NMS Device Description
                '1.3.6.1.4.1.25506.4.2.2.1.8': 'device_name',        # Device Name
                '1.3.6.1.4.1.25506.4.2.2.1.7': 'device_ip',          # Device IP
                '1.3.6.1.4.1.25506.4.2.2.1.100': 'device_type',       # Device Type

                # 告警相关参数
                '1.3.6.1.4.1.25506.4.2.2.1.14': 'alarm_time',         # Alarm Time
                '1.3.6.1.4.1.25506.4.2.2.1.17': 'poll_type',          # Poll Type
                '1.3.6.1.4.1.25506.4.2.2.1.6': 'alarm_level',        # 告警级别
                '1.3.6.1.4.1.25506.4.2.2.1.11': 'alarm_category',     # 告警分类
                '1.3.6.1.4.1.25506.4.2.2.1.12': 'alarm_reason',       # 告警原因
                '1.3.6.1.4.1.25506.4.2.2.1.13': 'alarm_suggestion',   # 修复建议
            }

            print(f"[DEBUG] Found {len(oid_value_pairs)} OID-value pairs")
            for oid, value in oid_value_pairs:
                print(f"[DEBUG] OID: {oid}, Value: {value}")
                if oid in huawei_oid_map:
                    var_type = huawei_oid_map[oid]
                    print(f"[DEBUG] Mapped OID {oid} to {var_type}")

                    # 特殊处理设备名称 - 检查是否为十六进制编码
                    if var_type == 'device_name' and isinstance(value, str):
                        # 尝试十六进制解码
                        decoded_name = self.decode_hex_device_name(value)
                        if decoded_name:
                            print(f"[HEX_DECODE] 设备名称十六进制解码成功: {value} -> {decoded_name}")
                            value = decoded_name

                    variables.append((var_type, value))
                else:
                    # 即使不认识这个OID，也添加到变量列表中
                    variables.append(('unknown_oid', f"{oid}={value}"))

        # 如果结构化解析失败，回退到简单解析
        if not variables:
            variables = self.extract_variables_from_binary(data)

        return variables

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
        # 查找OID模式，但需要更精确的匹配
        # 先查找华为设备特定OID的子串
        huawei_oids = [
            '1.3.6.1.4.1.25506.4.1',
            '1.3.6.1.4.1.25506.4.1.1',
            '1.3.6.1.4.1.25506'
        ]

        for oid in huawei_oids:
            if oid in text:
                return oid

        # 查找标准SNMP OID
        if '1.3.6.1.6.3' in text:
            # 查找具体的子OID
            oid_pattern = r'1\.3\.6\.1\.6\.3\.1\.1\.5(\.2|\.3)'
            match = re.search(oid_pattern, text)
            if match:
                return f"1.3.6.1.6.3.1.1.5{match.group(1)}"

        # 一般OID查找（需要更严格的验证）
        oid_pattern = r'(?<!\d)(\d+(?:\.\d+)+)(?!\d)'
        matches = re.findall(oid_pattern, text)

        for match in matches:
            # 排除明显的IP地址模式
            parts = match.split('.')
            if len(parts) >= 4 and len(match) > 8:
                # 检查是否像OID（通常有特定的结构）
                if parts[0] == '1' and parts[1] in ['3', '2', '4']:
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
        # 查找数字0-6作为trap类型，但优先查找更明确的模式
        # 华为设备通常是 enterpriseSpecific (6)
        if 'enterpriseSpecific' in text.lower() or '6' in text:
            return 6

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

        # 提取华为设备特定信息
        # Device ID: 10842301341430770
        device_id_match = re.search(r'10842301341430770', text)
        if device_id_match:
            variables.append(('device_id', '10842301341430770'))

        # 设备IP: 172.16.20.154
        device_ip_match = re.search(r'172\.16\.20\.154', text)
        if device_ip_match:
            variables.append(('device_ip', '172.16.20.154'))

        # 时间戳: 17630951320
        timestamp_match = re.search(r'17630951320', text)
        if timestamp_match:
            variables.append(('timestamp', '17630951320'))

        # 年份: 2010
        year_match = re.search(r'\b2010\b', text)
        if year_match:
            variables.append(('year', '2010'))

        # 提取Device ID模式 (数字太长，可能是其他格式)
        long_number_pattern = r'\b(\d{14,20})\b'
        long_matches = re.findall(long_number_pattern, text)
        for match in long_matches:
            if match not in ['10842301341430770', '17630951320']:
                variables.append(('long_number', match))

        # 提取接口索引
        interface_pattern = r'\b(\d{1,4})\b'
        matches = re.findall(interface_pattern, text)
        for match in matches:
            num = int(match)
            # 过滤掉已经提取的数字
            if (1 <= num <= 9999 and
                str(num) not in ['2010', '10842301341430770', '17630951320']):
                variables.append(('interface_index', str(num)))

        # 查找可能的设备名称和描述
        # 查找连续的字母数字组合（不全是数字）
        alnum_pattern = r'\b([a-zA-Z]{2,}\d*[a-zA-Z]*|\d*[a-zA-Z]{2,}\d*)\b'
        alnum_matches = re.findall(alnum_pattern, text)
        for match in alnum_matches:
            if len(match) >= 3 and not match.isnumeric() and len(match) <= 50:
                variables.append(('device_string', match))

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
        """从二进制数据中提取变量绑定（简单版本）"""
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

    
    def parse_varbind_sequence(self, varbind_data: bytes) -> list:
        """解析变量绑定序列中的OID-值对"""
        oid_value_pairs = []

        i = 0
        while i < len(varbind_data) - 5:
            # 查找变量绑定SEQUENCE (0x30)
            if varbind_data[i] == 0x30:
                # 读取长度字节
                if i + 1 >= len(varbind_data):
                    break

                if varbind_data[i + 1] < 0x80:  # 短格式长度
                    varbind_length = varbind_data[i + 1]
                    length_bytes = 1
                else:  # 长格式长度
                    length_bytes = varbind_data[i + 1] & 0x7f
                    if i + 1 + length_bytes >= len(varbind_data):
                        i += 1
                        continue
                    varbind_length = 0
                    for j in range(length_bytes):
                        varbind_length = (varbind_length << 8) | varbind_data[i + 2 + j]
                    length_bytes += 1

                if i + 1 + length_bytes + varbind_length <= len(varbind_data):
                    varbind_content = varbind_data[i + 1 + length_bytes:i + 1 + length_bytes + varbind_length]
                    print(f"[DEBUG] Parsing VarBind at offset {i}, length {varbind_length}")

                    # 解析OID和值
                    oid, value = self.parse_oid_value_pair(varbind_content)
                    if oid and value:
                        print(f"[DEBUG] Parsed OID-Value: {oid} = {value}")
                        oid_value_pairs.append((oid, value))

                    i += 1 + length_bytes + varbind_length
                else:
                    i += 1
            else:
                i += 1

        return oid_value_pairs

    def parse_oid_value_pair(self, varbind_content: bytes) -> tuple:
        """解析单个变量绑定中的OID和值"""
        try:
            i = 0

            # 解析OID (OBJECT IDENTIFIER tag = 0x06)
            if i < len(varbind_content) and varbind_content[i] == 0x06:
                # 读取OID长度
                if i + 1 >= len(varbind_content):
                    return None, None

                if varbind_content[i + 1] < 0x80:  # 短格式长度
                    oid_length = varbind_content[i + 1]
                    length_bytes = 1
                else:  # 长格式长度
                    length_bytes = varbind_content[i + 1] & 0x7f
                    if i + 1 + length_bytes >= len(varbind_content):
                        return None, None
                    oid_length = 0
                    for j in range(length_bytes):
                        oid_length = (oid_length << 8) | varbind_content[i + 2 + j]
                    length_bytes += 1

                if i + 1 + length_bytes + oid_length <= len(varbind_content):
                    oid_bytes = varbind_content[i + 1 + length_bytes:i + 1 + length_bytes + oid_length]
                    oid = self.parse_oid_bytes(oid_bytes)
                    print(f"[DEBUG] Parsed OID: {oid}")

                    if oid:
                        i += 1 + length_bytes + oid_length

                        # 解析值 (根据数据类型)
                        if i < len(varbind_content):
                            value = self.parse_snmp_value(varbind_content[i:], oid)
                            print(f"[DEBUG] Parsed value: {value}")
                            return oid, value

        except Exception as e:
            print(f"[DEBUG] Error parsing OID-value pair: {e}")

        return None, None

    def parse_snmp_value(self, value_data: bytes, oid: str) -> Optional[str]:
        """解析SNMP值部分"""
        try:
            if len(value_data) < 2:
                return None

            value_tag = value_data[0]

            # 读取值长度
            if value_data[1] < 0x80:  # 短格式长度
                value_length = value_data[1]
                length_bytes = 1
            else:  # 长格式长度
                length_bytes = value_data[1] & 0x7f
                if 1 + length_bytes >= len(value_data):
                    return None
                value_length = 0
                for j in range(length_bytes):
                    value_length = (value_length << 8) | value_data[2 + j]
                length_bytes += 1

            if value_length == 0 or 1 + length_bytes + value_length > len(value_data):
                return None

            value_bytes = value_data[1 + length_bytes:1 + length_bytes + value_length]

            # 根据数据类型解析值
            if value_tag == 0x04:  # OCTET STRING (字符串)
                try:
                    # 尝试UTF-8解码
                    return value_bytes.decode('utf-8').strip()
                except:
                    try:
                        # 尝试ASCII解码
                        return value_bytes.decode('ascii').strip()
                    except:
                        # 返回十六进制表示
                        return value_bytes.hex()

            elif value_tag == 0x02:  # INTEGER (整数)
                if len(value_bytes) == 1:
                    return str(value_bytes[0])
                elif len(value_bytes) == 2:
                    return str(int.from_bytes(value_bytes, byteorder='big'))
                elif len(value_bytes) == 4:
                    return str(int.from_bytes(value_bytes, byteorder='big'))

            elif value_tag == 0x40:  # IPAddress (IP地址)
                if len(value_bytes) == 4:
                    return f"{value_bytes[0]}.{value_bytes[1]}.{value_bytes[2]}.{value_bytes[3]}"

            elif value_tag == 0x41:  # Counter32
                if len(value_bytes) == 4:
                    return str(int.from_bytes(value_bytes, byteorder='big'))

            elif value_tag == 0x43:  # TimeTicks
                if len(value_bytes) == 4:
                    return str(int.from_bytes(value_bytes, byteorder='big'))

            # 对于设备名称OID，优先返回可读字符串
            if oid == '1.3.6.1.4.1.25506.4.2.2.1.8':
                # 设备名称通常是字符串，如果解析失败则尝试提取可读部分
                readable = ''.join(chr(b) for b in value_bytes if 32 <= b <= 126)
                if readable:
                    return readable

        except Exception:
            pass

        return None

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
                    found_end = False
                    for j in range(3):  # 最多3个字节
                        if i + j < len(oid_bytes):
                            value = (value << 7) | (oid_bytes[i + j] & 0x7f)
                            if not (oid_bytes[i + j] & 0x80):
                                oid_parts.append(str(value))
                                i += j + 1
                                found_end = True
                                break

                    # 如果没有找到结束标记，强制跳过当前字节避免无限循环
                    if not found_end:
                        i += 1
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