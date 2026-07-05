import sys
import os

# Cho phép import common từ thư mục gốc (vì seed.py nằm trong db/)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from common.db import add_student, add_assignment


def read_public_key_pem(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def main():
    # Đường dẫn tới public key của "sinh viên mẫu" (dùng chung client_public.pem)
    keys_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "keys"))
    client_pub_path = os.path.join(keys_dir, "client_public.pem")

    public_key_pem = read_public_key_pem(client_pub_path)

    # Thêm sinh viên mẫu
    student_id = add_student(
        ho_ten="Bui Dieu",
        msv="SV001",
        public_key_pem=public_key_pem
    )
    print(f"✅ Đã thêm sinh viên mẫu, id = {student_id}")

    # Thêm bài tập mẫu
    assignment_id = add_assignment(
        ten_bai_tap="Bai tap An toan thong tin - Nop qua Secure Chunk Transfer",
        han_nop=None,
        mo_ta="Bai tap demo cho he thong truyen file bao mat"
    )
    print(f"✅ Đã thêm bài tập mẫu, id = {assignment_id}")


if __name__ == "__main__":
    main()