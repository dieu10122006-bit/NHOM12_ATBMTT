import os
import json
import socket
import time

from common.protocol import (
    send_frame, send_json, recv_json, send_binary,
    DEFAULT_PORT, TYPE_JSON, TYPE_BINARY, CHUNK_SIZE
)
from common.crypto_utils import (
    load_private_key, load_public_key,
    rsa_encrypt, sign_data,
    generate_aes_key, aes_encrypt,
    sha256_hex, sha256_file
)

CLIENT_PRIVATE_KEY_PATH = "keys/client_private.pem"
SERVER_PUBLIC_KEY_PATH = "keys/server_public.pem"
TEST_FILE = "demo_files/test_multi.txt"
MSV = "SV001"
ASSIGNMENT_ID = 1


def prepare_submission(file_path):
    """Chuẩn bị toàn bộ dữ liệu cần thiết: chunk, khóa AES, manifest, chữ ký."""
    chunks = []
    with open(file_path, "rb") as f:
        while True:
            data = f.read(CHUNK_SIZE)
            if not data:
                break
            chunks.append(data)

    aes_key = generate_aes_key()
    server_public_key = load_public_key(SERVER_PUBLIC_KEY_PATH)
    encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)

    chunk_hashes = [sha256_hex(c) for c in chunks]
    file_hash = sha256_file(file_path)

    manifest = {
        "msv": MSV,
        "assignment_id": ASSIGNMENT_ID,
        "ten_file": os.path.basename(file_path),
        "tong_so_chunk": len(chunks),
        "chunk_hashes": chunk_hashes,
        "file_hash": file_hash
    }
    manifest_bytes = json.dumps(manifest).encode("utf-8")

    client_private_key = load_private_key(CLIENT_PRIVATE_KEY_PATH)
    signature = sign_data(client_private_key, manifest_bytes)

    return chunks, aes_key, encrypted_aes_key, manifest_bytes, signature


def connect():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("localhost", DEFAULT_PORT))
    return sock


def send_chunk(sock, aes_key, index, chunk):
    result = aes_encrypt(aes_key, chunk)
    send_json(sock, {"index": index, "nonce_hex": result["nonce"].hex()})
    send_binary(sock, result["ciphertext"])


def print_header(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


# ---------- Kich ban A: sua 1 byte trong 1 chunk ----------

def scenario_a_tamper_chunk():
    print_header("KICH BAN A: Sua 1 byte trong chunk truoc khi gui")
    chunks, aes_key, encrypted_aes_key, manifest_bytes, signature = prepare_submission(TEST_FILE)

    sock = connect()
    try:
        send_frame(sock, TYPE_BINARY, encrypted_aes_key)
        send_frame(sock, TYPE_JSON, manifest_bytes)
        send_binary(sock, signature)

        response = recv_json(sock)
        print("Server phan hoi manifest:", response)
        if response.get("status") != "manifest_accepted":
            print("❌ Manifest bi tu choi som, khong the test tiep")
            return

        for index, chunk in enumerate(chunks):
            if index == 0:
                # Gia mao: sua 1 byte cua chunk truoc khi ma hoa
                chunk = bytearray(chunk)
                chunk[0] ^= 0xFF  # dao nguoc bit dau tien
                chunk = bytes(chunk)
                print(f"⚠️ Da sua 1 byte cua chunk #{index} (gia lap tan cong)")

            send_chunk(sock, aes_key, index, chunk)
            chunk_response = recv_json(sock)
            print(f"  Chunk #{index} ->", chunk_response)

        final_response = recv_json(sock)
        print("Ket qua cuoi cung:", final_response)
        print("✅ KY VONG: 'failed' (do chunk #0 bi phat hien sai/hong)")
    finally:
        sock.close()


# ---------- Kich ban B: gia mao chu ky manifest ----------

def scenario_b_tamper_signature():
    print_header("KICH BAN B: Gia mao chu ky manifest")
    chunks, aes_key, encrypted_aes_key, manifest_bytes, signature = prepare_submission(TEST_FILE)

    # Gia mao: doi 1 byte trong chu ky
    tampered_signature = bytearray(signature)
    tampered_signature[0] ^= 0xFF
    tampered_signature = bytes(tampered_signature)
    print("⚠️ Da sua 1 byte trong chu ky RSA-PSS (gia lap tan cong)")

    sock = connect()
    try:
        send_frame(sock, TYPE_BINARY, encrypted_aes_key)
        send_frame(sock, TYPE_JSON, manifest_bytes)
        send_binary(sock, tampered_signature)

        response = recv_json(sock)
        print("Server phan hoi:", response)
        print("✅ KY VONG: 'rejected', reason 'invalid_signature'")
    finally:
        sock.close()


# ---------- Kich ban C: co tinh bo bot 1 chunk ----------

def scenario_c_missing_chunk():
    print_header("KICH BAN C: Bo bot 1 chunk khi gui")
    chunks, aes_key, encrypted_aes_key, manifest_bytes, signature = prepare_submission(TEST_FILE)

    if len(chunks) < 2:
        print("⚠️ File demo chi co 1 chunk, khong the mo phong thieu chunk ro rang."
              " Van tiep tuc: se bo qua chunk duy nhat -> gia lap khong gui gi.")

    sock = connect()
    try:
        send_frame(sock, TYPE_BINARY, encrypted_aes_key)
        send_frame(sock, TYPE_JSON, manifest_bytes)
        send_binary(sock, signature)

        response = recv_json(sock)
        print("Server phan hoi manifest:", response)
        if response.get("status") != "manifest_accepted":
            print("❌ Manifest bi tu choi som, khong the test tiep")
            return

        # Chi gui chunk dau tien den chunk ap chot (bo qua chunk cuoi cung)
        chunks_to_send = chunks[:-1] if len(chunks) > 1 else []
        print(f"⚠️ Chi gui {len(chunks_to_send)}/{len(chunks)} chunk, roi dong ket noi som")

        for index, chunk in enumerate(chunks_to_send):
            send_chunk(sock, aes_key, index, chunk)
            chunk_response = recv_json(sock)
            print(f"  Chunk #{index} ->", chunk_response)

    finally:
        sock.close()  # dong ket noi som, gia lap mat ket noi giua chung
        print("🔌 Da chu dong dong ket noi som (gia lap loi)")
        time.sleep(1)  # doi server kip xu ly va ghi log
        print("✅ KY VONG: server bao 'failed', reason 'missing_chunks'")


# ---------- Kich ban D: gui lai 1 chunk hai lan (replay) ----------

def scenario_d_duplicate_chunk():
    print_header("KICH BAN D: Gui lai dung 1 chunk hai lan (replay)")
    chunks, aes_key, encrypted_aes_key, manifest_bytes, signature = prepare_submission(TEST_FILE)

    sock = connect()
    try:
        send_frame(sock, TYPE_BINARY, encrypted_aes_key)
        send_frame(sock, TYPE_JSON, manifest_bytes)
        send_binary(sock, signature)

        response = recv_json(sock)
        print("Server phan hoi manifest:", response)
        if response.get("status") != "manifest_accepted":
            print("❌ Manifest bi tu choi som, khong the test tiep")
            return

        # Gui chunk #0 truoc, RIENG mot lan du thua (replay)
        print("⚠️ Gui chunk #0 mot lan du thua (replay) truoc khi gui binh thuong")
        send_chunk(sock, aes_key, 0, chunks[0])
        dup_response = recv_json(sock)
        print("  Chunk #0 (lan gui thua) ->", dup_response)

        # Gui du toan bo chunk theo dung thu tu (bao gom lai chunk #0)
        for index, chunk in enumerate(chunks):
            send_chunk(sock, aes_key, index, chunk)
            chunk_response = recv_json(sock)
            print(f"  Chunk #{index} ->", chunk_response)

        final_response = recv_json(sock)
        print("Ket qua cuoi cung:", final_response)
        print("✅ KY VONG: 'completed' (he thong khong bi anh huong boi replay)")
    finally:
        sock.close()


if __name__ == "__main__":
    scenario_a_tamper_chunk()
    time.sleep(1)

    scenario_b_tamper_signature()
    time.sleep(1)

    scenario_c_missing_chunk()
    time.sleep(1)

    scenario_d_duplicate_chunk()

    print("\n" + "=" * 60)
    print("HOAN TAT CA 4 KICH BAN. Kiem tra logs/server.log va bang chunk_logs de doi chieu.")
    print("=" * 60)