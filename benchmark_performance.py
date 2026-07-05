import time
from common.crypto_utils import (
    generate_aes_key, aes_encrypt, aes_decrypt,
    load_public_key, load_private_key, rsa_encrypt, rsa_decrypt,
    sha256_hex
)

FILES_TO_TEST = [
    ("1MB", "demo_files/test_1mb.bin"),
    ("10MB", "demo_files/test_10mb.bin"),
]

CHUNK_SIZES = [16 * 1024, 64 * 1024, 256 * 1024]  # 16KB, 64KB, 256KB


def read_file(path):
    with open(path, "rb") as f:
        return f.read()


def split_into_chunks(data: bytes, chunk_size: int):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def benchmark_full_file_aes(label, data):
    """Đo thời gian mã hóa/giải mã AES-GCM cho toàn bộ file (1 khối duy nhất)."""
    aes_key = generate_aes_key()

    start = time.perf_counter()
    result = aes_encrypt(aes_key, data)
    encrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    plaintext = aes_decrypt(aes_key, result["nonce"], result["ciphertext"])
    decrypt_time = time.perf_counter() - start

    assert plaintext == data, "Giai ma khong khop du lieu goc!"

    print(f"  [{label}] AES-GCM ma hoa toan file: {encrypt_time:.4f}s | giai ma: {decrypt_time:.4f}s")
    return encrypt_time, decrypt_time


def benchmark_rsa(server_public_key, server_private_key):
    """Đo thời gian mã hóa/giải mã RSA-OAEP cho khóa phiên AES (kích thước cố định 32 byte)."""
    aes_key = generate_aes_key()

    start = time.perf_counter()
    encrypted = rsa_encrypt(server_public_key, aes_key)
    encrypt_time = time.perf_counter() - start

    start = time.perf_counter()
    decrypted = rsa_decrypt(server_private_key, encrypted)
    decrypt_time = time.perf_counter() - start

    assert decrypted == aes_key

    print(f"  RSA-OAEP ma hoa khoa phien: {encrypt_time:.4f}s | giai ma: {decrypt_time:.4f}s")


def benchmark_chunking(label, data):
    """Đo ảnh hưởng của kích thước chunk tới tổng thời gian mã hóa + băm."""
    aes_key = generate_aes_key()

    print(f"  [{label}] Anh huong kich thuoc chunk:")
    for chunk_size in CHUNK_SIZES:
        chunks = split_into_chunks(data, chunk_size)

        start = time.perf_counter()
        encrypted_chunks = []
        for chunk in chunks:
            result = aes_encrypt(aes_key, chunk)
            chunk_hash = sha256_hex(chunk)
            encrypted_chunks.append((result, chunk_hash))
        total_time = time.perf_counter() - start

        chunk_size_kb = chunk_size // 1024
        print(f"    Chunk size {chunk_size_kb}KB -> {len(chunks)} chunk, "
              f"tong thoi gian ma hoa+bam: {total_time:.4f}s "
              f"({total_time / len(chunks) * 1000:.2f} ms/chunk)")


def main():
    print("=" * 70)
    print("DO HIEU NANG HE THONG SACT")
    print("=" * 70)

    server_public_key = load_public_key("keys/server_public.pem")
    server_private_key = load_private_key("keys/server_private.pem")

    print("\n--- RSA-OAEP (khong phu thuoc kich thuoc file, chi ma hoa khoa AES) ---")
    benchmark_rsa(server_public_key, server_private_key)

    for label, path in FILES_TO_TEST:
        print(f"\n--- File {label} ---")
        data = read_file(path)

        benchmark_full_file_aes(label, data)
        benchmark_chunking(label, data)

    print("\n" + "=" * 70)
    print("HOAN TAT DO HIEU NANG")
    print("=" * 70)


if __name__ == "__main__":
    main()