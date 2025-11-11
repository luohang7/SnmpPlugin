#!/usr/bin/env python3
"""
SNMP Trap Test Script
向本地1162端口发送测试消息
"""

import socket
import time
from datetime import datetime

def send_trap(message):
    """发送单个SNMP Trap消息"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        data = f"SNMP Trap [{timestamp}] {message}".encode('utf-8')

        sock.sendto(data, ('127.0.0.1', 1162))
        sock.close()

        print(f"Sent: {message}")
        return True
    except Exception as e:
        print(f"Failed: {e}")
        return False

def main():
    print("SNMP Trap Test Tool")
    print("=" * 40)

    messages = [
        "CPU utilization is 95% - Critical",
        "Interface GigabitEthernet0/1 is down",
        "Memory usage exceeds threshold",
        "Disk space low on server-01",
        "Temperature sensor critical alert"
    ]

    print("Sending test messages to 127.0.0.1:1162\n")

    for i, message in enumerate(messages, 1):
        print(f"[{i}/{len(messages)}] ", end="")
        if send_trap(message):
            time.sleep(2)

    print("\nAll tests completed!")
    print("Check plugin console for received messages.")

if __name__ == "__main__":
    main()