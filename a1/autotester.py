import socket
import struct
import time
import sys
import random

# --- 配置 ---
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8888
HEADER_FORMAT = "!H20s20sII"  # ! = Network (Big-Endian), H=short, s=bytes, I=unsigned int
HEADER_SIZE = 50
CLIENT_TIMEOUT = 5.0 # 增加超时以应对潜在的服务器繁忙

# --- 辅助函数 ---
def print_header(title):
    print("\n" + "="*70); print(f"  🧪  {title}"); print("="*70)
def print_result(success, message):
    if success: print(f"  ✅ \033[92mPASS:\033[0m {message}")
    else: print(f"  ❌ \033[91mFAIL:\033[0m {message}"); sys.exit(1)
def create_message(msg_type, source, dest, data=b'', msg_id=0):
    s_bytes=source.encode('ascii'); d_bytes=dest.encode('ascii')
    return struct.pack(HEADER_FORMAT, msg_type, s_bytes, d_bytes, len(data), msg_id) + data
def read_message(sock, description=""):
    try:
        sock.settimeout(CLIENT_TIMEOUT)
        header_data = sock.recv(HEADER_SIZE)
        if not header_data: return None, None
        if len(header_data) < HEADER_SIZE: return "INCOMPLETE", None
        msg_type, s_raw, d_raw, length, msg_id = struct.unpack(HEADER_FORMAT, header_data)
        source=s_raw.decode('ascii').strip('\x00'); dest=d_raw.decode('ascii').strip('\x00')
        data = b''
        if length > 0:
            bytes_read = 0
            while bytes_read < length:
                chunk=sock.recv(min(length - bytes_read, 4096))
                if not chunk: break
                data += chunk; bytes_read += len(chunk)
        return (msg_type, source, dest, length, msg_id), data
    except socket.timeout:
        print(f"  🕒 \033[93mTIMEOUT:\033[0m Reading from socket timed out while {description}.")
        return None, None
    except Exception as e:
        print(f"  💥 \033[91mERROR:\033[0m An error occurred: {e}"); return None, None
def parse_client_list(data):
    if not data: return []
    return [s for s in data.decode('ascii').split('\x00') if s]

# --- 核心测试流程 ---

# 用于在每个阶段验证功能的辅助函数
def _run_feature_checks(all_sockets, absolute_connection_order):
    print("\n  --- [开始阶段性功能验证] ---")
    if len(all_sockets) < 2:
        print("  - 在线用户少于2人，跳过聊天测试。")
        return

    # 1. 随机选择一个“测试员”客户端
    tester_id = random.choice(list(all_sockets.keys()))
    tester_sock = all_sockets[tester_id]
    print(f"  - 使用 '{tester_id}' 作为测试员。")

    # 2. 测试 LIST_REQUEST 功能
    tester_sock.send(create_message(3, tester_id, "Server")) # LIST_REQUEST
    header, data = read_message(tester_sock, f"为 {tester_id} 读取 LIST_REQUEST 的响应")
    print_result(header and header[0] == 4, "功能[LIST_REQUEST]: 服务器正确回复了 CLIENT_LIST (type=4)")
    
    # 3. 验证列表时序
    received_list = parse_client_list(data)
    expected_online_set = set(all_sockets.keys())
    expected_ordered_list = [cid for cid in absolute_connection_order if cid in expected_online_set]
    print_result(received_list == expected_ordered_list, "功能[CLIENT_LIST]: 列表严格遵循首次连接顺序")

    # 4. 测试 CHAT 功能
    receiver_id = random.choice([cid for cid in all_sockets.keys() if cid != tester_id])
    receiver_sock = all_sockets[receiver_id]
    chat_content = f"Message from {tester_id} to {receiver_id}".encode('ascii')
    tester_sock.send(create_message(5, tester_id, receiver_id, data=chat_content, msg_id=555))
    header, data = read_message(receiver_sock, f"等待 {receiver_id} 接收消息")
    print_result(header and header[0] == 5, f"功能[CHAT]: '{receiver_id}' 成功收到 CHAT 消息")
    print_result(data == chat_content, "功能[CHAT]: 消息内容正确")

    # 5. 测试 ERROR(CANNOT_DELIVER)
    ghost_user = "non_existent_user_123"
    tester_sock.send(create_message(5, tester_id, ghost_user, data=b'ghost message', msg_id=666))
    header, data = read_message(tester_sock, f"等待 {tester_id} 接收 ERROR")
    print_result(header and header[0] == 8, "功能[ERROR(CANNOT_DELIVER)]: 服务器正确回复了 ERROR (type=8)")
    if header:
        print_result(header[4] == 666, f"功能[ERROR(CANNOT_DELIVER)]: Message-ID ({header[4]}) 正确返回")
    
    print("  --- [阶段性功能验证完毕] ---")


def run_churn_scenario_and_verify_order():
    """主测试场景：模拟客户端高强度进出，并在每阶段验证功能与时序"""
    print_header("主测试场景: 客户端高强度进出与时序验证")
    
    all_sockets = {}
    absolute_connection_order = []
    client_counter = 0

    def _add_clients(count):
        nonlocal client_counter
        print(f"\n  PHASE: 增加 {count} 个新客户端...")
        for _ in range(count):
            client_id = f"client_{client_counter}"
            client_counter += 1
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect((SERVER_IP, SERVER_PORT))
            all_sockets[client_id] = sock; absolute_connection_order.append(client_id)
            sock.send(create_message(1, client_id, "Server")) # HELLO
            h, _ = read_message(sock, f"为 {client_id} 读取 HELLO_ACK"); print_result(h and h[0] == 2, f"功能[HELLO/HELLO_ACK]: {client_id} 收到ACK")
            read_message(sock) # CLIENT_LIST
        print(f"  - 完成。当前在线客户端: {len(all_sockets)}")
    
    def _remove_clients(count):
        print(f"\n  PHASE: 随机退出 {count} 个客户端...")
        clients_to_remove = random.sample(list(all_sockets.keys()), count)
        for client_id in clients_to_remove:
            sock = all_sockets.pop(client_id)
            sock.send(create_message(6, client_id, "Server")) # EXIT
            sock.close()
        print(f"  - 完成。当前在线客户端: {len(all_sockets)}")

    # 阶段 1: +10
    _add_clients(10)
    _run_feature_checks(all_sockets, absolute_connection_order)

    # 阶段 2: -5, +10
    _remove_clients(5)
    _add_clients(10)
    _run_feature_checks(all_sockets, absolute_connection_order)

    # 阶段 3: -5, +10
    _remove_clients(5)
    _add_clients(10)
    _run_feature_checks(all_sockets, absolute_connection_order)
    
    # 阶段 4: -10
    _remove_clients(10)
    _run_feature_checks(all_sockets, absolute_connection_order)

    print("\n  - 清理所有剩余连接...")
    for sock in all_sockets.values(): sock.close()
    print("  - 主测试场景完成。")


def test_robustness_and_errors():
    """独立测试：验证服务器对所有错误和违规行为的处理"""
    print_header("纠错机制与健壮性测试 (犯错即踢)")

    # 场景 1: ClientID 冲突
    print("\n  - 场景1: ClientID 冲突 (ERROR_CLIENT_ALREADY_PRESENT)")
    sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock1.connect((SERVER_IP, SERVER_PORT))
    sock1.send(create_message(1, "duplicate_user", "Server")); read_message(sock1); read_message(sock1)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock2.connect((SERVER_IP, SERVER_PORT))
    sock2.send(create_message(1, "duplicate_user", "Server"))
    header, _ = read_message(sock2)
    print_result(header and header[0] == 7, "纠错[ID冲突]: 服务器正确回复 ERROR (type=7)")
    header, _ = read_message(sock2)
    print_result(header is None, "纠错[ID冲突]: 服务器在发送错误后关闭连接")
    sock1.close(); sock2.close()

    # 场景 2: 未认证先聊天
    print("\n  - 场景2: 未发送HELLO就发送CHAT")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect((SERVER_IP, SERVER_PORT))
    sock.send(create_message(5, "unauth_actor", "some_user", data=b'illegal chat'))
    header, _ = read_message(sock)
    print_result(header is None, "纠错[未认证聊天]: 服务器直接关闭连接")

    # 场景 3: 非法CHAT目的地
    print("\n  - 场景3: CHAT目的地为自己或为空")
    sock_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock_self.connect((SERVER_IP, SERVER_PORT))
    sock_self.send(create_message(1, "self_chatter", "Server")); read_message(sock_self); read_message(sock_self)
    sock_self.send(create_message(5, "self_chatter", "self_chatter", data=b'hi me'))
    header, _ = read_message(sock_self)
    print_result(header is None, "纠错[CHAT to self]: 服务器直接关闭连接")
    sock_empty = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock_empty.connect((SERVER_IP, SERVER_PORT))
    sock_empty.send(create_message(1, "empty_chatter", "Server")); read_message(sock_empty); read_message(sock_empty)
    sock_empty.send(create_message(5, "empty_chatter", "", data=b'to nobody'))
    header, _ = read_message(sock_empty)
    print_result(header is None, "纠错[CHAT to empty]: 服务器直接关闭连接")

    # 场景 4: 无效消息类型
    print("\n  - 场景4: 发送无效消息类型 (e.g., KKK, FUCKU)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect((SERVER_IP, SERVER_PORT))
    sock.send(create_message(1, "bad_type_sender", "Server")); read_message(sock); read_message(sock)
    sock.send(create_message(999, "bad_type_sender", "Server")) # 无效类型
    header, _ = read_message(sock)
    print_result(header is None, "纠错[无效类型]: 服务器直接关闭连接")

    # 场景 5: 客户端突然掉线
    print("\n  - 场景5: 客户端突然掉线 (模拟Ctrl+C)")
    sock_abrupt = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock_abrupt.connect((SERVER_IP, SERVER_PORT))
    sock_abrupt.send(create_message(1, "abrupt_user", "Server")); read_message(sock_abrupt); read_message(sock_abrupt)
    sock_abrupt.close() # 强制关闭
    time.sleep(1) # 等待服务器处理
    sock_checker = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock_checker.connect((SERVER_IP, SERVER_PORT))
    sock_checker.send(create_message(1, "checker", "Server")); read_message(sock_checker); read_message(sock_checker)
    _, data = read_message(sock_checker)
    final_list = parse_client_list(data)
    print_result("abrupt_user" not in final_list, "纠错[突然掉线]: 掉线用户被成功移除")
    sock_checker.close()
    
    # 场景 6: 消息帧错误 (Data part与声称的length不符)
    print("\n  - 场景6: 消息帧错误 (length > 实际数据)")
    sock_frame = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock_frame.connect((SERVER_IP, SERVER_PORT))
    sock_frame.send(create_message(1, "frame_user", "Server")); read_message(sock_frame); read_message(sock_frame)
    # 头部声称有50字节数据，但我们只发送10字节
    bad_message = create_message(5, "frame_user", "some_user", data=b'x'*10, msg_id=777)
    bad_header = struct.pack(HEADER_FORMAT, 5, b'frame_user', b'some_user', 50, 777) # 伪造的头部
    sock_frame.send(bad_header + b'x'*10)
    # 服务器应该因为超时(等待剩余40字节)而断开连接，或者客户端在这里超时
    header, _ = read_message(sock_frame)
    print_result(header is None, "纠错[帧错误]: 服务器因超时或其他错误关闭了连接")
    
    print("\n  - 纠错机制与健壮性测试完成。")


if __name__ == "__main__":
    if len(sys.argv) > 1: SERVER_PORT = int(sys.argv[1])
    print(f"*** 开始终极全自动测试，目标服务器 {SERVER_IP}:{SERVER_PORT} ***")
    try:
        run_churn_scenario_and_verify_order()
        test_robustness_and_errors()
        print("\n" + "="*70); print("  🎉 \033[92m所有测试用例均已通过！服务器表现稳健！\033[0m"); print("="*70)
    except ConnectionRefusedError: print(f"  ❌ \033[91m连接失败:\033[0m 无法连接。请确认服务器 `./a.out` 正在运行，且端口为 {SERVER_PORT}。")
    except SystemExit: print("\n  -- 测试因断言失败而终止 --")
    except Exception as e: print(f"\n  💥 \033[91m测试过程中出现意外错误:\033[0m {e}")