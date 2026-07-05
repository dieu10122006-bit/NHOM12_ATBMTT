from common.crypto_utils import generate_rsa_keypair, save_private_key, save_public_key
import os

def make_keypair(name: str):
    private_key, public_key = generate_rsa_keypair()

    os.makedirs("keys", exist_ok=True)
    save_private_key(private_key, f"keys/{name}_private.pem")
    save_public_key(public_key, f"keys/{name}_public.pem")

    print(f"✅ Đã tạo keys/{name}_private.pem và keys/{name}_public.pem")

if __name__ == "__main__":
    make_keypair("server")
    make_keypair("client")