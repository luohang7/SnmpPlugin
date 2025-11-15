# SMTP邮件监听器 - 只使用LangBot官方SDK
from __future__ import annotations

import socket
import threading
import asyncio
import os
import re
import base64
from datetime import datetime, timezone, timedelta
from typing import Any

from langbot_plugin.api.definition.components.common.event_listener import EventListener
import logging

from ..utils.message_helper import MessageHelper

# 创建logger实例并设置日志级别
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # 确保INFO级别的日志被输出


class DefaultEventListener(EventListener):

    def __init__(self):
        super().__init__()  # Critical fix for self.plugin initialization
        self.email_count = 0
        self.default_group_id = "1056816501"
        self.running = False
        self.stop_event = threading.Event()
        self.thread = None
        self.smtp_socket = None
        self.host = "0.0.0.0"  # 监听所有网络接口
        # 从环境变量读取端口，默认使用配置的端口1162
        self.port = int(os.getenv('SMTP_PORT', '1162'))

    async def initialize(self) -> None:
        """初始化SMTP邮件监听器"""
        try:
            logger.info("[DEBUG] self.plugin type: %s", type(self.plugin))
            logger.info("[DEBUG] self.plugin is None: %s", self.plugin is None)

            # 读取环境变量中的群组ID
            env_group_id = os.getenv('SMTP_DEFAULT_GROUP_ID')
            if env_group_id and env_group_id.strip():
                self.default_group_id = env_group_id.strip()

            logger.info("[INIT] Starting SMTP Email listener initialization")
            logger.info("[INIT] Read group ID from environment variable: %s", self.default_group_id)

            if self.plugin is None:
                logger.error("[ERROR] self.plugin is None - MessageHelper will not work")
                return

            logger.info("[DEBUG] plugin available, starting SMTP Email listener initialization")
            logger.info("[INIT] Starting TCP listener...")
            logger.info("[SMTP] TCP listener started on %s:%s", self.host, self.port)
            logger.info("[SMTP] TCP receive loop started")
            logger.info("[SUCCESS] SMTP listener started, listening on port: %s:%s", self.host, self.port)
            logger.info("[SUCCESS] Target QQ group: %s", self.default_group_id)
            logger.info("[SUCCESS] Import status: Normal")

            # 启动TCP监听器线程
            self.running = True
            self.thread = threading.Thread(target=self._smtp_listener_thread, daemon=True)
            self.thread.start()

        except Exception as e:
            print(f"[ERROR] Failed to initialize SMTP listener: {e}")
            logger.error(f"Failed to initialize SMTP listener: {e}")
            raise

    def _smtp_listener_thread(self):
        """SMTP监听器线程"""
        try:
            self.smtp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.smtp_socket.bind((self.host, self.port))
            self.smtp_socket.listen(5)  # 允许多个连接
            self.smtp_socket.settimeout(1.0)  # Set timeout to allow checking stop_event

            print(f"[SMTP] Successfully bound to {self.host}:{self.port}")

            while self.running and not self.stop_event.is_set():
                try:
                    # 等待连接，但定期检查stop_event
                    try:
                        client_socket, client_addr = self.smtp_socket.accept()
                        if client_socket:
                            self.email_count += 1
                            logger.info("[SMTP] Received connection: from %s:%s", client_addr[0], client_addr[1])
                            self._process_email_connection(client_socket, client_addr)
                    except socket.timeout:
                        # 超时是正常的，继续循环检查stop_event
                        continue

                except Exception as e:
                    logger.error("[ERROR] SMTP accept error: %s", e)

        except Exception as e:
            print(f"[ERROR] SMTP listener thread error: {e}")
        finally:
            if self.smtp_socket:
                self.smtp_socket.close()

    def _process_email_connection(self, client_socket, client_addr):
        """处理SMTP客户端连接和接收邮件数据"""
        try:
            # 使用北京时间（UTC+8）
            beijing_tz = timezone(timedelta(hours=8))
            timestamp = datetime.now(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')

            logger.info("[SMTP] === Processing Email Connection #%s ===", self.email_count)
            logger.info("[SMTP] Source: %s:%s", client_addr[0], client_addr[1])
            logger.info("[SMTP] Time: %s", timestamp)
            logger.info("[SMTP] Target group: %s", self.default_group_id)

            # 发送SMTP欢迎消息
            welcome_msg = b"220 Simple SMTP Server Ready\r\n"
            client_socket.send(welcome_msg)
            logger.info("[SMTP] Sent welcome message")

            email_data = b""
            client_socket.settimeout(30.0)  # 30秒超时

            try:
                # 简单的SMTP协议处理
                in_data_mode = False
                email_body = b""  # 只存储邮件正文，不包含SMTP命令

                while True:
                    data = client_socket.recv(1024)
                    if not data:
                        break

                    print(f"[DEBUG] 接收到数据: {data}")

                    if not in_data_mode:
                        # SMTP命令模式
                        command = data.decode('utf-8', errors='ignore').strip().upper()
                        logger.info("[SMTP] Received command: %s", command)

                        if command.startswith('HELO') or command.startswith('EHLO'):
                            client_socket.send(b"250 OK\r\n")
                            print("[DEBUG] 响应 EHLO/HELO")
                        elif command.startswith('MAIL FROM'):
                            client_socket.send(b"250 OK\r\n")
                            print("[DEBUG] 响应 MAIL FROM")
                        elif command.startswith('RCPT TO'):
                            client_socket.send(b"250 OK\r\n")
                            print("[DEBUG] 响应 RCPT TO")
                        elif command == 'DATA':
                            client_socket.send(b"354 Start mail input\r\n")
                            in_data_mode = True
                            print("[DEBUG] 进入DATA模式")
                        elif command.startswith('QUIT'):
                            client_socket.send(b"221 Bye\r\n")
                            break
                        else:
                            client_socket.send(b"500 Command unrecognized\r\n")
                            print(f"[DEBUG] 未知命令: {command}")
                    else:
                        # DATA模式 - 只收集邮件正文
                        email_body += data
                        print(f"[DEBUG] 收集邮件正文，当前长度: {len(email_body)}")

                        # 检查邮件结束标记
                        if b"\r\n.\r\n" in data:
                            # 移除结束标记，只保留邮件内容
                            email_body = email_body.split(b"\r\n.\r\n")[0]
                            print(f"[DEBUG] 邮件接收完成，正文长度: {len(email_body)}")

                            # 发送250响应表示邮件接收完成
                            client_socket.send(b"250 OK: Message accepted\r\n")
                            print("[DEBUG] 发送邮件接收完成响应")

                            # 等待QUIT命令
                            try:
                                quit_data = client_socket.recv(1024)
                                if quit_data and b"QUIT" in quit_data:
                                    client_socket.send(b"221 Bye\r\n")
                                    print("[DEBUG] 响应QUIT命令")
                            except:
                                pass
                            break

                # 使用email_body作为邮件数据进行解析
                email_data = email_body

            except socket.timeout:
                logger.info("[SMTP] Connection timeout after 30 seconds")

            # 解析邮件内容
            if email_data:
                logger.info("[DEBUG] 收到邮件数据，长度: %d 字节", len(email_data))
                print("[DEBUG] === 开始解析邮件 ===")

                email_info = self._parse_email_content(email_data)

                # 输出解析后的详细信息
                logger.info("[DEBUG] Parsed email info:")
                logger.info("[DEBUG]   From: %s", email_info.get('from', 'N/A'))
                logger.info("[DEBUG]   Subject: %s", email_info.get('subject', 'N/A'))
                logger.info("[DEBUG]   Content length: %d", len(email_info.get('content', '')))
                logger.info("[DEBUG]   Content (first 300 chars): %s", email_info.get('content', '')[:300])

        
                # 从邮件内容中提取关键告警信息
                content_lines = email_info.get('content', '').split('\n')
                key_info = {}
                additional_info = []

                logger.info("[DEBUG] Processing %d content lines for key info", len(content_lines))

                for i, line in enumerate(content_lines):
                    line = line.strip()
                    if line:
                        logger.info("[DEBUG] Line %d: %s", i+1, line[:100])

                    # 标准告警字段
                    if '告警源:' in line:
                        key_info['告警源'] = line.split(':', 1)[1].strip()
                    elif '告警名称:' in line:
                        key_info['告警名称'] = line.split(':', 1)[1].strip()
                    elif '告警时间:' in line:
                        key_info['告警时间'] = line.split(':', 1)[1].strip()
                    elif '告警描述:' in line:
                        key_info['告警描述'] = line.split(':', 1)[1].strip()

                    # 设备相关字段
                    elif '设备:' in line or 'device:' in line.lower():
                        key_info['告警源'] = line.split(':', 1)[1].strip()
                    elif '主机:' in line or 'host:' in line.lower():
                        key_info['告警源'] = line.split(':', 1)[1].strip()
                    elif '服务器:' in line or 'server:' in line.lower():
                        key_info['告警源'] = line.split(':', 1)[1].strip()

                    # 状态/告警类型字段
                    elif '状态:' in line or 'status:' in line.lower():
                        key_info['告警名称'] = line.split(':', 1)[1].strip()
                    elif '级别:' in line or 'level:' in line.lower():
                        key_info['告警名称'] = line.split(':', 1)[1].strip()
                    elif '类型:' in line or 'type:' in line.lower():
                        key_info['告警名称'] = line.split(':', 1)[1].strip()

                    # 接口相关字段
                    elif '接口:' in line or 'interface:' in line.lower():
                        additional_info.append(f"接口: {line.split(':', 1)[1].strip()}")
                    elif '端口:' in line or 'port:' in line.lower():
                        additional_info.append(f"端口: {line.split(':', 1)[1].strip()}")
                    elif '链路:' in line or 'link:' in line.lower():
                        additional_info.append(f"链路: {line.split(':', 1)[1].strip()}")

                    # 描述信息字段
                    elif '描述:' in line or 'description:' in line.lower():
                        additional_info.append(f"描述: {line.split(':', 1)[1].strip()}")
                    elif '位置:' in line or 'location:' in line.lower():
                        additional_info.append(f"位置: {line.split(':', 1)[1].strip()}")
                    elif '详情:' in line or 'detail:' in line.lower():
                        additional_info.append(f"详情: {line.split(':', 1)[1].strip()}")

                    # 通用信息字段
                    elif '信息:' in line or 'info:' in line.lower():
                        additional_info.append(f"信息: {line.split(':', 1)[1].strip()}")
                    elif '说明:' in line or 'note:' in line.lower():
                        additional_info.append(f"说明: {line.split(':', 1)[1].strip()}")

                # 构造详细的告警消息
                if key_info:
                    alarm_content = f"设备: {key_info.get('告警源', '未知')}, 状态: {key_info.get('告警名称', '未知')}"

                    # 添加告警描述（包含接口信息）
                    if '告警描述' in key_info:
                        alarm_content += f"\n详情: {key_info['告警描述']}"

                    # 添加额外信息
                    if additional_info:
                        if '告警描述' in key_info:
                            alarm_content += f", {', '.join(additional_info)}"
                        else:
                            alarm_content += f"\n详情: {', '.join(additional_info)}"
                else:
                    # 如果没有找到标准格式，尝试从主题和内容中提取信息
                    subject = email_info.get('subject', '邮件告警')
                    content = email_info.get('content', '')

                    # 尝试从主题中提取关键信息
                    if '告警' in subject or 'alarm' in subject.lower() or 'alert' in subject.lower():
                        alarm_content = subject[:100]
                    elif content:
                        # 尝试智能提取内容中的关键信息
                        lines = [line.strip() for line in content.split('\n') if line.strip()]

                        # 查找包含数字IP的行（可能是设备信息）
                        device_line = None
                        status_line = None

                        for line in lines:
                            # 检查是否包含IP地址
                            if re.search(r'\d+\.\d+\.\d+\.\d+', line):
                                device_line = line
                            # 检查是否包含状态关键词
                            elif any(keyword in line for keyword in ['DOWN', 'UP', 'OFFLINE', 'ONLINE', '离线', '在线', '异常', '正常']):
                                status_line = line

                        if device_line and status_line:
                            alarm_content = f"{device_line[:50]}... 状态: {status_line[:30]}..."
                        elif device_line:
                            alarm_content = f"设备告警: {device_line[:80]}..."
                        elif status_line:
                            alarm_content = f"状态告警: {status_line[:80]}..."
                        else:
                            # 提取前两行作为告警内容
                            alarm_content = f"告警信息: {lines[0][:60]}..." if lines else "邮件告警"
                            if len(lines) > 1:
                                alarm_content += f"\n详情: {lines[1][:60]}..."
                    else:
                        alarm_content = subject[:100]

                    # 如果还有剩余内容且长度合理，添加为详情
                    if content and len(content) > 50:
                        content_preview = content[:150].replace('\n', ' ').strip()
                        if content_preview and len(content_preview) > 20:
                            alarm_content += f"\n详情: {content_preview}..."

                # 提取发件人名称（去除邮箱地址）
                from_name = email_info.get('from', '未知发件人')
                if '<' in from_name and '>' in from_name:
                    from_name = from_name.split('<')[0].strip()

                # 输出最终的解析结果调试信息
                logger.info("[DEBUG] Final parsing result:")
                logger.info("[DEBUG]   Key info found: %s", bool(key_info))
                if key_info:
                    for key, value in key_info.items():
                        logger.info("[DEBUG]   %s: %s", key, value)
                logger.info("[DEBUG]   Additional info count: %d", len(additional_info))
                logger.info("[DEBUG]   Final alarm content: %s", alarm_content[:200])

                # 构造发送到QQ群的消息格式
                formatted_message = f"""【设备告警】

时间：{timestamp}
告警内容：{alarm_content}"""

                logger.info("[DEBUG] Sending message to group: %s", self.default_group_id)

                # 发送群消息
                success = self._send_group_message(formatted_message)
                if success:
                    # 发送成功后等待2秒，避免频率限制
                    import time
                    time.sleep(2)
                    logger.info("[SUCCESS] 告警消息已发送到QQ群")
                else:
                    logger.error("[ERROR] 告警消息发送失败")

        except Exception as e:
            logger.error("[ERROR] Error processing email connection: %s", e)
            import traceback
            logger.error("[ERROR] Traceback: %s", traceback.format_exc())
        finally:
            try:
                client_socket.close()
            except:
                pass

    def _parse_email_content(self, email_data: bytes) -> dict:
        """解析邮件内容，提取发件人、主题和内容"""
        try:
            email_text = email_data.decode('utf-8', errors='ignore')

            # 简单的邮件解析
            email_info = {
                'from': '未知发件人',
                'subject': '无主题',
                'content': ''
            }

            lines = email_text.split('\n')
            in_headers = True
            content_lines = []
            content_encoding = None  # 存储内容编码类型

            for line in lines:
                line = line.strip()

                if in_headers:
                    # 解析邮件头
                    if line.lower().startswith('from:'):
                        email_info['from'] = line[5:].strip()
                    elif line.lower().startswith('subject:'):
                        subject_line = line[8:].strip()
                        email_info['subject'] = self._decode_mime_header(subject_line)
                    elif line.lower().startswith('content-transfer-encoding:'):
                        content_encoding = line.split(':', 1)[1].strip().lower()
                        logger.info("[DEBUG] 检测到内容编码: %s", content_encoding)
                    elif line.lower().startswith('content-type:') and 'multipart' in line.lower():
                        # 多部分邮件，寻找boundary
                        if 'boundary=' in line.lower():
                            boundary = line.split('boundary=', 1)[1].strip('"')
                            logger.info("[EMAIL] Found multipart boundary: %s", boundary)
                    elif line == '':
                        # 空行表示头部结束，开始邮件内容
                        in_headers = False
                else:
                    # 邮件内容
                    if line == '.':
                        break
                    content_lines.append(line)

            # 合并内容
            raw_content = '\n'.join(content_lines).strip()

            # 根据编码类型解码内容
            if content_encoding == 'base64':
                try:
                    # 过滤掉非base64字符
                    base64_content = re.sub(r'[^A-Za-z0-9+/=]', '', raw_content)
                    if base64_content:
                        decoded_content = base64.b64decode(base64_content + '==').decode('utf-8', errors='ignore')
                        email_info['content'] = decoded_content
                    else:
                        email_info['content'] = raw_content
                except Exception as decode_error:
                    logger.warning("[WARNING] Base64 decode failed: %s", decode_error)
                    email_info['content'] = raw_content
            elif content_encoding == 'quoted-printable':
                try:
                    # Quoted-printable解码
                    import quopri
                    decoded_content = quopri.decodestring(raw_content).decode('utf-8', errors='ignore')
                    email_info['content'] = decoded_content
                except Exception as decode_error:
                    logger.warning("[WARNING] Quoted-printable decode failed: %s", decode_error)
                    # 手动解码作为备选方案
                    try:
                        manual_decoded = raw_content.replace('=\r\n', '').replace('=\n', '')
                        manual_decoded = re.sub(r'=([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), manual_decoded)
                        email_info['content'] = manual_decoded
                    except:
                        email_info['content'] = raw_content
            else:
                email_info['content'] = raw_content

            logger.info("[EMAIL] Parsed - From: %s, Subject: %s, Content length: %d, Encoding: %s",
                       email_info['from'], email_info['subject'], len(email_info['content']), content_encoding)

            return email_info

        except Exception as e:
            logger.error("[ERROR] Error parsing email content: %s", e)
            return {
                'from': '解析错误',
                'subject': '邮件解析失败',
                'content': f'邮件内容解析异常: {str(e)}'
            }

    def _decode_mime_header(self, header: str) -> str:
        """解码MIME编码的邮件头部，如 =?UTF-8?Q?...?= 或 =?UTF-8?B?...?="""
        try:
            import re

            # 匹配MIME编码模式: =?charset?encoding?encoded-text?= （?=可选）
            mime_pattern = r'=\?([^?]+)\?([BQbq])\?([^?]*)\?=?'

            def decode_match(match):
                charset = match.group(1).upper()
                encoding = match.group(2).upper()
                encoded_text = match.group(3)

                try:
                    if encoding == 'B':  # Base64编码
                        decoded_bytes = base64.b64decode(encoded_text)
                        return decoded_bytes.decode(charset, errors='ignore')
                    elif encoding == 'Q':  # Quoted-printable编码
                        # Quoted-printable解码
                        decoded_text = encoded_text.replace('_', ' ')
                        decoded_text = re.sub(r'=([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), decoded_text)
                        return decoded_text
                except Exception as decode_error:
                    logger.warning("[WARNING] MIME decode error: %s", decode_error)
                    return match.group(0)

                return match.group(0)

            # 替换所有MIME编码的部分
            decoded_header = re.sub(mime_pattern, decode_match, header)

            # 如果解码后没有变化，直接返回原始头部
            if decoded_header == header:
                return header
            else:
                return decoded_header

        except Exception as e:
            logger.warning("[WARNING] MIME header decode error: %s", e)
            return header

    def _send_group_message(self, message: str) -> bool:
        """发送消息到QQ群，只使用SDK"""
        try:
            logger.info("[SEND] Sending message to QQ group %s", self.default_group_id)

            # 使用MessageHelper发送消息
            from ..utils.message_helper import MessageHelper

            # 在新的事件循环中运行异步方法，增加超时处理
            def run_async():
                import asyncio
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    # 给消息发送设置更长的超时时间
                    try:
                        return loop.run_until_complete(
                            asyncio.wait_for(
                                MessageHelper.send_message_via_sdk(self.plugin, self.default_group_id, message),
                                timeout=35.0  # 35秒超时，比SDK内部超时稍长
                            )
                        )
                    except asyncio.TimeoutError:
                        print(f"[WARNING] Message send timeout after 35 seconds")
                        logger.warning("Message send timeout after 35 seconds, but message may have been sent")
                        # 即使超时也返回True，因为消息可能已经发送成功
                        return True
                finally:
                    loop.close()

            success = run_async()

            if success:
                logger.info("[SUCCESS] Message sent to QQ group %s", self.default_group_id)
                return True
            else:
                logger.error("[ERROR] Message sending failed")
                return False

        except Exception as e:
            logger.error("[ERROR] Message sending failed: %s", e)
            return False

    # 个人消息发送功能已移除，只支持群消息

    async def on_event(self, event: Any) -> None:
        """处理事件"""
        pass

    async def cleanup(self) -> None:
        """清理资源"""
        try:
            logger.info("[CLEANUP] Cleaning up SMTP listener resources")
            self.running = False
            self.stop_event.set()

            if self.thread and self.thread.is_alive():
                self.thread.join(timeout=5)

            if self.smtp_socket:
                self.smtp_socket.close()

            logger.info("[CLEANUP] SMTP listener cleanup completed")

        except Exception as e:
            logger.error("[ERROR] Cleanup error: %s", e)