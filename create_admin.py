from werkzeug.security import generate_password_hash
from common.db import get_connection

def create_admin(username: str, password: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO admins (username, password_hash) VALUES (%s, %s)",
        (username, generate_password_hash(password))
    )
    conn.commit()
    cursor.close()
    conn.close()
    print(f"✅ Da tao admin: {username}")

if __name__ == "__main__":
    create_admin("admin", "dieu1012")