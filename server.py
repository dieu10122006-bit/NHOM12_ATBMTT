import os
import socket
import json
import datetime

from common.protocol import (
    recv_frame, recv_json, send_json, recv_binary,
    DEFAULT_PORT, TYPE_JSON
)
from common.crypto_utils import (
    load_private_key, rsa_decrypt,
    public_key_from_pem_str, verify_signature,
    aes_decrypt, sha256_hex
)
from common.db import (
    get_student_by_msv, create_submission, log_chunk,
    update_submission_status
)

SERVER_PRIVATE_KEY_PATH = "keys/server_private.pem"
RECEIVED_DIR = "received"
LOG_FILE = "logs/server.log"


def log(message: str):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    os.makedirs("logs", exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


def handle_client(conn: socket.socket, addr, server_private_key):
    log(f"Ket noi moi tu {addr}")
    conn.settimeout(5)  # cho phep toi da 5 giay cho moi lan nhan du lieu

    try:
        # ---- 4.2: nhan khoa phien AES da ma hoa bang RSA-OAEP ----
        msg_type, encrypted_key = recv_frame(conn)
        aes_key = rsa_decrypt(server_private_key, encrypted_key)
        log("Da giai ma khoa phien AES thanh cong")

        # ---- 4.3: nhan manifest (JSON) + chu ky ----
        msg_type, manifest_bytes = recv_frame(conn)
        if msg_type != TYPE_JSON:
            raise ValueError("Khong nhan duoc manifest dang JSON")
        manifest = json.loads(manifest_bytes.decode("utf-8"))
        signature = recv_binary(conn)

        msv = manifest["msv"]
        assignment_id = manifest["assignment_id"]
        ten_file = manifest["ten_file"]
        tong_so_chunk = manifest["tong_so_chunk"]
        chunk_hashes = manifest["chunk_hashes"]
        file_hash_expected = manifest["file_hash"]

        # ---- 4.4: tra cuu sinh vien, xac thuc chu ky ----
        student = get_student_by_msv(msv)
        if student is None:
            log(f"❌ Khong tim thay sinh vien MSV={msv}, tu choi phien")
            send_json(conn, {"status": "rejected", "reason": "unknown_student"})
            return

        student_public_key = public_key_from_pem_str(student["public_key"])
        is_valid_sig = verify_signature(student_public_key, manifest_bytes, signature)

        if not is_valid_sig:
            log(f"❌ Chu ky manifest KHONG HOP LE cho MSV={msv}, tu choi phien")
            send_json(conn, {"status": "rejected", "reason": "invalid_signature"})
            return

        log(f"✅ Chu ky manifest hop le cho MSV={msv}, file={ten_file}")

        submission_id = create_submission(
            student_id=student["id"],
            assignment_id=assignment_id,
            ten_file=ten_file,
            tong_so_chunk=tong_so_chunk
        )
        log(f"Da tao submission id={submission_id}, trang thai=receiving")
        send_json(conn, {"status": "manifest_accepted", "submission_id": submission_id})

        # ---- 4.5: nhan tung chunk ----
        
        received_chunks = {}
        seen_indices = set()

        max_attempts = tong_so_chunk + 5  # cho phep du sai so (trung lap, gui lai)
        attempts = 0

        while len(received_chunks) < tong_so_chunk and attempts < max_attempts:
            attempts += 1
            try:
                frame = recv_json(conn)
            except ConnectionError:
                log("⚠️ Ket noi dong som, co the client gui thieu chunk")
                break
            except socket.timeout:
                log("⚠️ Het thoi gian cho chunk tiep theo (5s), dung lai xu ly")
                break

            chunk_index = frame["index"]
            nonce = bytes.fromhex(frame["nonce_hex"])
            ciphertext = recv_binary(conn)

            if chunk_index in seen_indices:
                log(f"⚠️ Chunk #{chunk_index} bi gui trung lap, bo qua")
                log_chunk(submission_id, chunk_index, "", "duplicate")
                send_json(conn, {"status": "duplicate", "index": chunk_index})
                continue

            try:
                plaintext = aes_decrypt(aes_key, nonce, ciphertext)
            except Exception:
                log(f"❌ Chunk #{chunk_index} giai ma AES-GCM that bai (co the bi sua doi)")
                log_chunk(submission_id, chunk_index, "", "decrypt_failed")
                send_json(conn, {"status": "invalid", "index": chunk_index, "reason": "decrypt_failed"})
                continue

            actual_hash = sha256_hex(plaintext)
            expected_hash = chunk_hashes[chunk_index]

            if actual_hash != expected_hash:
                log(f"❌ Chunk #{chunk_index} SAI HASH")
                log_chunk(submission_id, chunk_index, actual_hash, "invalid_hash")
                send_json(conn, {"status": "invalid", "index": chunk_index, "reason": "hash_mismatch"})
                continue

            received_chunks[chunk_index] = plaintext
            seen_indices.add(chunk_index)
            log_chunk(submission_id, chunk_index, actual_hash, "valid")
            send_json(conn, {"status": "valid", "index": chunk_index})

        # ---- 4.6: rap file, kiem tra hash tong ----
        if len(received_chunks) != tong_so_chunk:
            log(f"❌ Thieu chunk: nhan {len(received_chunks)}/{tong_so_chunk}, danh dau FAILED")
            update_submission_status(submission_id, "failed")
            send_json(conn, {"status": "failed", "reason": "missing_chunks"})
            return

        os.makedirs(RECEIVED_DIR, exist_ok=True)
        output_path = os.path.join(RECEIVED_DIR, f"{submission_id}_{ten_file}")

        with open(output_path, "wb") as f:
            for i in range(tong_so_chunk):
                f.write(received_chunks[i])

        with open(output_path, "rb") as f:
            actual_file_hash = sha256_hex(f.read())

        if actual_file_hash == file_hash_expected:
            log(f"✅ File '{ten_file}' rap thanh cong, hash khop. Submission COMPLETED")
            update_submission_status(submission_id, "completed", actual_file_hash)
            send_json(conn, {"status": "completed", "submission_id": submission_id})
        else:
            log(f"❌ Hash toan file KHONG khop sau khi rap. Submission FAILED")
            update_submission_status(submission_id, "failed", actual_file_hash)
            send_json(conn, {"status": "failed", "reason": "file_hash_mismatch"})

    except Exception as e:
        log(f"❌ Loi xu ly ket noi: {e}")
    finally:
        conn.close()
        log(f"Da dong ket noi voi {addr}")


def main():
    server_private_key = load_private_key(SERVER_PRIVATE_KEY_PATH)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("localhost", DEFAULT_PORT))
    srv.listen(5)

    log(f"🚀 Server dang lang nghe tai localhost:{DEFAULT_PORT}")

    try:
        while True:
            conn, addr = srv.accept()
            handle_client(conn, addr, server_private_key)
    except KeyboardInterrupt:
        log("Server dung boi nguoi dung (Ctrl+C)")
    finally:
        srv.close()


if __name__ == "__main__":
    main()