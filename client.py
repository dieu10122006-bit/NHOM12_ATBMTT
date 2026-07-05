import os
import sys
import json

from common.protocol import (
    send_frame, recv_json, send_json, send_binary,
    DEFAULT_PORT, TYPE_JSON, TYPE_BINARY, CHUNK_SIZE
)
from common.crypto_utils import (
    load_private_key, load_public_key,
    rsa_encrypt, sign_data,
    generate_aes_key, aes_encrypt,
    sha256_hex, sha256_file
)

import socket

CLIENT_PRIVATE_KEY_PATH = "keys/client_private.pem"
SERVER_PUBLIC_KEY_PATH = "keys/server_public.pem"


def split_file_into_chunks(path: str, chunk_size: int):
    """Đọc file, trả về list các chunk dạng bytes."""
    chunks = []
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            chunks.append(data)
    return chunks


def submit_file(file_path: str, msv: str, assignment_id: int):
    if not os.path.exists(file_path):
        print(f"❌ Khong tim thay file: {file_path}")
        return

    ten_file = os.path.basename(file_path)

    # ---- 5.1 + 5.2: doc file, chia chunk ----
    chunks = split_file_into_chunks(file_path, CHUNK_SIZE)
    tong_so_chunk = len(chunks)
    print(f"📄 File '{ten_file}' co {tong_so_chunk} chunk (chunk size = {CHUNK_SIZE} bytes)")

    # ---- 5.3: sinh khoa phien AES ----
    aes_key = generate_aes_key()

    # ---- 5.4: ma hoa khoa phien bang RSA-OAEP voi server_public.pem ----
    server_public_key = load_public_key(SERVER_PUBLIC_KEY_PATH)
    encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)

    # ---- 5.5: tinh hash tung chunk ----
    chunk_hashes = [sha256_hex(c) for c in chunks]

    # ---- 5.6: tinh hash toan file, dung manifest ----
    file_hash = sha256_file(file_path)

    manifest = {
        "msv": msv,
        "assignment_id": assignment_id,
        "ten_file": ten_file,
        "tong_so_chunk": tong_so_chunk,
        "chunk_hashes": chunk_hashes,
        "file_hash": file_hash
    }
    # Chuyển thành bytes CỐ ĐỊNH — đây chính là dữ liệu sẽ được ký,
    # và server phải nhận đúng y hệt bytes này để verify chữ ký khớp.
    manifest_bytes = json.dumps(manifest).encode("utf-8")

    # ---- 5.7: ky manifest bang RSA-PSS voi client_private.pem ----
    client_private_key = load_private_key(CLIENT_PRIVATE_KEY_PATH)
    signature = sign_data(client_private_key, manifest_bytes)

    # ---- 5.8: ket noi server, gui tuan tu ----
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", DEFAULT_PORT))
    print("🔌 Da ket noi toi server")

    try:
        # Gui khoa phien da ma hoa
        send_frame(sock, TYPE_BINARY, encrypted_aes_key)

        # Gui manifest (dung bytes da ky) + chu ky
        send_frame(sock, TYPE_JSON, manifest_bytes)
        send_binary(sock, signature)

        # Nhan phan hoi ve manifest
        response = recv_json(sock)
        print("📩 Server phan hoi manifest:", response)

        if response.get("status") != "manifest_accepted":
            print("❌ Server tu choi phien, dung lai")
            return

        submission_id = response["submission_id"]
        print(f"✅ Submission id = {submission_id}, bat dau gui chunk...")

        # ---- 5.8 (tiep): gui tung chunk da ma hoa AES-GCM ----
        for index, chunk in enumerate(chunks):
            result = aes_encrypt(aes_key, chunk)
            nonce_hex = result["nonce"].hex()
            ciphertext = result["ciphertext"]

            send_json(sock, {"index": index, "nonce_hex": nonce_hex})
            send_binary(sock, ciphertext)

            # ---- 5.9: nhan phan hoi tung chunk ----
            chunk_response = recv_json(sock)
            status = chunk_response.get("status")
            if status == "valid":
                print(f"  ✅ Chunk #{index} duoc chap nhan")
            else:
                print(f"  ❌ Chunk #{index} bi tu choi: {chunk_response}")

        # ---- Nhan phan hoi cuoi cung ----
        final_response = recv_json(sock)
        print("📦 Ket qua cuoi cung:", final_response)

        if final_response.get("status") == "completed":
            print("🎉 Nop bai THANH CONG!")
        else:
            print("⚠️ Nop bai THAT BAI:", final_response.get("reason"))

    finally:
        sock.close()
        print("🔌 Da dong ket noi")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Cach dung: python client.py <duong_dan_file> [msv] [assignment_id]")
        sys.exit(1)

    file_path = sys.argv[1]
    msv = sys.argv[2] if len(sys.argv) > 2 else "SV001"
    assignment_id = int(sys.argv[3]) if len(sys.argv) > 3 else 1

    submit_file(file_path, msv, assignment_id)