import socket
import json
import struct

# ---------- Hằng số ----------

DEFAULT_PORT = 65432
CHUNK_SIZE = 64 * 1024  # 64KB mỗi chunk

TYPE_JSON = b"J"
TYPE_BINARY = b"B"


# ---------- Gửi/nhận mức thấp (đảm bảo đọc đủ byte) ----------

def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Nhận đúng n byte, gộp lại nếu TCP chia nhỏ gói tin."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Kết nối bị đóng giữa chừng khi đang nhận dữ liệu")
        buf += chunk
    return buf


def send_frame(sock: socket.socket, msg_type: bytes, payload: bytes):
    """
    Khung gói tin: 4 byte độ dài (big-endian) + 1 byte loại (J/B) + payload
    """
    header = struct.pack(">I", len(payload)) + msg_type
    sock.sendall(header + payload)


def recv_frame(sock: socket.socket):
    """
    Trả về tuple (msg_type: bytes, payload: bytes)
    """
    header = _recv_exact(sock, 5)  # 4 byte length + 1 byte type
    length = struct.unpack(">I", header[:4])[0]
    msg_type = header[4:5]
    payload = _recv_exact(sock, length)
    return msg_type, payload


# ---------- Gửi/nhận JSON ----------

def send_json(sock: socket.socket, obj: dict):
    payload = json.dumps(obj).encode("utf-8")
    send_frame(sock, TYPE_JSON, payload)


def recv_json(sock: socket.socket) -> dict:
    msg_type, payload = recv_frame(sock)
    if msg_type != TYPE_JSON:
        raise ValueError(f"Mong đợi JSON nhưng nhận loại: {msg_type}")
    return json.loads(payload.decode("utf-8"))


# ---------- Gửi/nhận dữ liệu nhị phân (chunk đã mã hóa) ----------

def send_binary(sock: socket.socket, data: bytes):
    send_frame(sock, TYPE_BINARY, data)


def recv_binary(sock: socket.socket) -> bytes:
    msg_type, payload = recv_frame(sock)
    if msg_type != TYPE_BINARY:
        raise ValueError(f"Mong đợi Binary nhưng nhận loại: {msg_type}")
    return payload