import mysql.connector
from mysql.connector import Error
from common import config


def get_connection():
    """Tạo và trả về kết nối MySQL mới."""
    return mysql.connector.connect(
        host=config.DB_HOST,
        port=config.DB_PORT,
        user=config.DB_USER,
        password=config.DB_PASSWORD,
        database=config.DB_NAME
    )


def create_submission(student_id: int, assignment_id: int, ten_file: str, tong_so_chunk: int) -> int:
    """Tạo bản ghi submission mới, trạng thái ban đầu 'receiving'. Trả về submission_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO submissions (student_id, assignment_id, ten_file, tong_so_chunk, trang_thai)
        VALUES (%s, %s, %s, %s, 'receiving')
        """,
        (student_id, assignment_id, ten_file, tong_so_chunk)
    )
    conn.commit()
    submission_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return submission_id


def log_chunk(submission_id: int, chunk_index: int, hash_chunk: str, ket_qua: str):
    """Ghi log kết quả xác thực của 1 chunk."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO chunk_logs (submission_id, chunk_index, hash_chunk, ket_qua)
        VALUES (%s, %s, %s, %s)
        """,
        (submission_id, chunk_index, hash_chunk, ket_qua)
    )
    conn.commit()
    cursor.close()
    conn.close()


def update_submission_status(submission_id: int, trang_thai: str, hash_toan_file: str = None):
    """Cập nhật trạng thái cuối cùng: completed / failed, kèm hash tổng nếu có."""
    conn = get_connection()
    cursor = conn.cursor()
    if hash_toan_file:
        cursor.execute(
            "UPDATE submissions SET trang_thai = %s, hash_toan_file = %s WHERE id = %s",
            (trang_thai, hash_toan_file, submission_id)
        )
    else:
        cursor.execute(
            "UPDATE submissions SET trang_thai = %s WHERE id = %s",
            (trang_thai, submission_id)
        )
    conn.commit()
    cursor.close()
    conn.close()


def get_submission_history(student_id: int):
    """Truy vấn lịch sử nộp bài của 1 sinh viên."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        """
        SELECT s.id, s.ten_file, s.tong_so_chunk, s.hash_toan_file,
               s.trang_thai, s.thoi_gian_nop, a.ten_bai_tap
        FROM submissions s
        JOIN assignments a ON s.assignment_id = a.id
        WHERE s.student_id = %s
        ORDER BY s.thoi_gian_nop DESC
        """,
        (student_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_student_by_msv(msv: str):
    """Tra cứu sinh viên theo mã số sinh viên (dùng để lấy public_key khi xác thực chữ ký)."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM students WHERE msv = %s", (msv,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row


def add_student(ho_ten: str, msv: str, public_key_pem: str) -> int:
    """Thêm sinh viên mới, trả về student_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO students (ho_ten, msv, public_key) VALUES (%s, %s, %s)",
        (ho_ten, msv, public_key_pem)
    )
    conn.commit()
    student_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return student_id


def add_assignment(ten_bai_tap: str, han_nop=None, mo_ta: str = "") -> int:
    """Thêm bài tập mới, trả về assignment_id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO assignments (ten_bai_tap, han_nop, mo_ta) VALUES (%s, %s, %s)",
        (ten_bai_tap, han_nop, mo_ta)
    )
    conn.commit()
    assignment_id = cursor.lastrowid
    cursor.close()
    conn.close()
    return assignment_id
def get_all_submissions():
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM submissions ORDER BY thoi_gian_nop DESC")
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_chunk_logs(submission_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM chunk_logs WHERE submission_id = %s ORDER BY chunk_index",
        (submission_id,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows