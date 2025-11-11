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
        print("✅ 服务器成功绑定到 127.0.0.1:1162")

        # 监听10秒
        sock.settimeout(15.0)
        start_time = time.time()

        while time.time() - start_time < 15:
            try:
                data, addr = sock.recvfrom(4096)
                print(f"📨 收到来自 {addr[0]}:{addr[1]} 的数据")
                print(f"📝 内容: {data.decode('utf-8', errors='ignore')}")
                print(f"📏 长度: {len(data)} 字节")
            except socket.timeout:
                print("⏳ 等待数据中...")
                continue

        print("🛑 测试结束")
        sock.close()

    except Exception as e:
        print(f"❌ 服务器错误: {e}")

def test_with_running_server():
    """测试与运行中的服务器通信"""
    print("开始UDP通信测试...")
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
            print(f"📤 发送消息 {i}: {msg}")
            time.sleep(1)

        sock.close()
        print("✅ 所有消息已发送")

    except Exception as e:
        print(f"❌ 客户端错误: {e}")

if __name__ == "__main__":
    test_with_running_server()