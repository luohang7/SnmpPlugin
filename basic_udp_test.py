#!/usr/bin/env python3
import socket
import threading
import time

def simple_server():
    """最简单的UDP服务器"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', 1162))
        print("Server bound to 127.0.0.1:1162")

        # 监听10秒
        sock.settimeout(15.0)
        start_time = time.time()

        while time.time() - start_time < 15:
            try:
                data, addr = sock.recvfrom(4096)
                print(f"Received from {addr[0]}:{addr[1]}")
                print(f"Content: {data.decode('utf-8', errors='ignore')}")
                print(f"Length: {len(data)} bytes")
                print("-" * 30)
            except socket.timeout:
                print("Waiting for data...")
                continue

        print("Test finished")
        sock.close()

    except Exception as e:
        print(f"Server error: {e}")

def test_with_running_server():
    """测试与运行中的服务器通信"""
    print("Starting UDP communication test...")
    print("=" * 40)

    # 启动服务器线程
    server_thread = threading.Thread(target=simple_server)
    server_thread.daemon = True
    server_thread.start()

    # 等待服务器启动
    time.sleep(2)

    # 发送测试消息
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        messages = [
            "Test message 1",
            "Test message 2",
            "SNMP Trap: CPU High",
            "SNMP Trap: Network Down"
        ]

        for i, msg in enumerate(messages, 1):
            data = f"[{time.strftime('%H:%M:%S')}] {msg}".encode('utf-8')
            sock.sendto(data, ('127.0.0.1', 1162))
            print(f"Sent message {i}: {msg}")
            time.sleep(1)

        sock.close()
        print("All messages sent")

    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    test_with_running_server()