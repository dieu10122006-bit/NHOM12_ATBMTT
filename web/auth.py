import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from werkzeug.security import generate_password_hash, check_password_hash
from common.crypto_utils import generate_rsa_keypair, save_private_key, public_key_to_pem_str
from common.db import create_student_account, get_student_by_msv

STUDENT_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "keys", "students")
os.makedirs(STUDENT_KEYS_DIR, exist_ok=True)


def register_student(ho_ten: str, msv: str, password: str):
    """Dang ky sinh vien moi: sinh khoa RSA rieng, luu private key vao server (moi truong demo)."""
    existing = get_student_by_msv(msv)
    if existing:
        return None, "Ma so sinh vien da ton tai"

    private_key, public_key = generate_rsa_keypair()

    private_key_path = os.path.join(STUDENT_KEYS_DIR, f"{msv}_private.pem")
    save_private_key(private_key, private_key_path)

    public_key_pem = public_key_to_pem_str(public_key)
    password_hash = generate_password_hash(password)

    student_id = create_student_account(ho_ten, msv, password_hash, public_key_pem)
    return student_id, None


def verify_login(msv: str, password: str):
    """Kiem tra dang nhap, tra ve thong tin sinh vien neu dung."""
    student = get_student_by_msv(msv)
    if not student or not student.get("password_hash"):
        return None
    if check_password_hash(student["password_hash"], password):
        return student
    return None


def get_student_private_key_path(msv: str) -> str:
    return os.path.join(STUDENT_KEYS_DIR, f"{msv}_private.pem")


from werkzeug.security import check_password_hash as _check_admin_pw
from common.db import get_admin_by_username


def verify_admin_login(username: str, password: str):
    admin = get_admin_by_username(username)
    if admin and check_password_hash(admin["password_hash"], password):
        return admin
    return None