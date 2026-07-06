import os
import json
import socket
import time

from flask import Flask, render_template, request, url_for, flash

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from werkzeug.utils import secure_filename

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
from common.db import get_all_submissions, get_chunk_logs

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLIENT_PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "client_private.pem")
SERVER_PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "keys", "server_public.pem")
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.secret_key = "sact-demo-secret"


def split_file_into_chunks(path, chunk_size):
    chunks = []
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk_size)
            if not data:
                break
            chunks.append(data)
    return chunks


def submit_file_web(file_path, msv, assignment_id):
    """Giống hệt logic client.py, nhưng trả ve danh sach log de hien thi tren web."""
    logs = []
    ten_file = os.path.basename(file_path)

    chunks = split_file_into_chunks(file_path, CHUNK_SIZE)
    tong_so_chunk = len(chunks)
    logs.append(("info", f"File '{ten_file}' co {tong_so_chunk} chunk"))

    aes_key = generate_aes_key()
    server_public_key = load_public_key(SERVER_PUBLIC_KEY_PATH)
    encrypted_aes_key = rsa_encrypt(server_public_key, aes_key)

    chunk_hashes = [sha256_hex(c) for c in chunks]
    file_hash = sha256_file(file_path)

    manifest = {
        "msv": msv,
        "assignment_id": assignment_id,
        "ten_file": ten_file,
        "tong_so_chunk": tong_so_chunk,
        "chunk_hashes": chunk_hashes,
        "file_hash": file_hash
    }
    manifest_bytes = json.dumps(manifest).encode("utf-8")

    client_private_key = load_private_key(CLIENT_PRIVATE_KEY_PATH)
    signature = sign_data(client_private_key, manifest_bytes)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    success = False
    try:
        sock.connect(("localhost", DEFAULT_PORT))
        logs.append(("info", "Da ket noi toi server"))

        send_frame(sock, TYPE_BINARY, encrypted_aes_key)
        send_frame(sock, TYPE_JSON, manifest_bytes)
        send_binary(sock, signature)

        response = recv_json(sock)
        logs.append(("manifest", response))

        if response.get("status") != "manifest_accepted":
            logs.append(("error", "Server tu choi phien"))
            return logs, False

        for index, chunk in enumerate(chunks):
            result = aes_encrypt(aes_key, chunk)
            send_json(sock, {"index": index, "nonce_hex": result["nonce"].hex()})
            send_binary(sock, result["ciphertext"])
            chunk_response = recv_json(sock)
            logs.append(("chunk", chunk_response))

        final_response = recv_json(sock)
        logs.append(("final", final_response))
        success = final_response.get("status") == "completed"

    except (socket.timeout, ConnectionError) as e:
        logs.append(("error", f"Loi ket noi: {e}"))
    finally:
        sock.close()

    return logs, success


@app.route("/", methods=["GET", "POST"])
def index():
    result_logs = None
    success = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        msv = request.form.get("msv", "SV001").strip()
        assignment_id = int(request.form.get("assignment_id", 1))

        if uploaded_file and uploaded_file.filename:
            filename = secure_filename(uploaded_file.filename)
            save_path = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{filename}")
            uploaded_file.save(save_path)

            result_logs, success = submit_file_web(save_path, msv, assignment_id)
        else:
            flash("Vui long chon 1 file de nop")

    return render_template("index.html", logs=result_logs, success=success)


@app.route("/dashboard")
def dashboard():
    submissions = get_all_submissions()
    return render_template("dashboard.html", submissions=submissions)


@app.route("/dashboard/<int:submission_id>")
def submission_detail(submission_id):
    chunk_logs = get_chunk_logs(submission_id)
    return render_template("submission_detail.html", chunk_logs=chunk_logs, submission_id=submission_id)


if __name__ == "__main__":
    app.run(debug=True, port=5000)