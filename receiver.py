import os
import json
import base64
from tkinter import Tk, Button, Label, messagebox
from getpass import getpass
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512

# Hàm bỏ padding PKCS#5/7 khỏi dữ liệu giải mã DES
def unpad(data):
    return data[:-data[-1]] #

# Hàm đọc khóa riêng của người nhận từ file, yêu cầu nhập mật khẩu để mở khóa
def load_receiver_private_key():
    try:
        # Đọc file khóa riêng (đã được mã hóa)
        with open("keys/receiver_private.pem", "rb") as f: #
            private_key_data = f.read() #
    except FileNotFoundError: #
        # Nếu file không tồn tại, báo lỗi popup và trả về None
        messagebox.showerror("Lỗi", "Không tìm thấy file 'keys/receiver_private.pem'") #
        return None

    # Thử nhập mật khẩu tối đa 3 lần
    for attempt in range(3): #
        passphrase = getpass(f"🔐 Nhập mật khẩu giải mã khóa riêng (lần {attempt+1}/3): ") #
        try:
            # Cố gắng giải mã khóa riêng với passphrase nhập vào
            private_key = RSA.import_key(private_key_data, passphrase=passphrase) #
            return private_key  # Thành công trả về khóa riêng đã giải mã
        except ValueError: #
            print(" Mật khẩu sai.")  # Nhập sai pass, thử lại
    print(" Đã vượt quá số lần thử. Hủy nhận bài.") #
    return None  # Quá số lần thử, trả về None

# Hàm chính nhận bài tập
def receive_assignment():
    os.makedirs("data", exist_ok=True) #

    try:
        # Đọc khóa công khai của người gửi (dùng để kiểm tra chữ ký)
        with open("keys/sender_public.pem", "r") as f: #
            sender_public = RSA.import_key(f.read()) #
    except FileNotFoundError: #
        return " Không tìm thấy khóa công khai của sender (sender_public.pem)." #

    # Load khóa riêng của người nhận
    receiver_private = load_receiver_private_key() #
    if receiver_private is None: #
        return "Không thể mở khóa riêng. Nhận bài thất bại." #

    try:
        # Đọc file dữ liệu bài tập đã gửi, dạng JSON
        with open("sent/sent_packets.json", "r") as f: #
            data = json.load(f) #
    except FileNotFoundError: #
        return " Không tìm thấy file gửi đến (sent_packets.json)." #

    try:
        # Giải mã các trường base64 trong file JSON
        metadata = base64.b64decode(data["metadata"]) #
        meta_sig = base64.b64decode(data["meta_sig"]) #
        enc_key = base64.b64decode(data["enc_session_key"]) #
        parts = data["parts"]  # Danh sách các phần mã hóa bài tập
    except Exception: #
        return "Lỗi đọc dữ liệu gói tin." #

    # --- 2. Xác thực & Trao khóa (phía Người nhận) ---
    # Kiểm tra chữ ký của metadata với khóa công khai sender
    try:
        pkcs1_15.new(sender_public).verify(SHA512.new(metadata), meta_sig) #
    except (ValueError, TypeError): #
        # Nếu chữ ký metadata không hợp lệ, từ chối và gửi NACK (mô phỏng)
        print("NACK: Chữ ký metadata không hợp lệ.")
        return " Chữ ký metadata không hợp lệ."

    # --- 1. Handshake: Người nhận trả lời "Ready!" ---
    # Sau khi metadata được xác minh, kiểm tra tin nhắn "Hello!"
    metadata_str_decoded = metadata.decode()
    if metadata_str_decoded.startswith("Hello!"):
        print(" Đã nhận được 'Hello!' từ người gửi.")
        messagebox.showinfo("Handshake", "Người nhận đã sẵn sàng: Ready!") # Mô phỏng gửi "Ready!"
    else:
        # Nếu không có "Hello!" hoặc không đúng định dạng, từ chối
        print(" NACK: Không tìm thấy thông điệp 'Hello!' hợp lệ trong metadata.")
        return " Handshake thất bại: Không nhận được 'Hello!'."

    # Giải mã khóa phiên DES bằng khóa riêng của người nhận
    cipher_rsa = PKCS1_v1_5.new(receiver_private) #
    session_key = cipher_rsa.decrypt(enc_key, None) #
    if not session_key: #
        print("NACK: Không giải mã được khóa phiên.")
        return " Không giải mã được khóa phiên." #

    full_content = b""  # Biến chứa toàn bộ nội dung bài tập sau khi giải mã
    integrity_ok = True # Cờ kiểm tra tính toàn vẹn tổng thể

    # --- 4. Phía Người nhận: Kiểm tra hash và chữ ký mỗi phần & Giải mã ---
    # Xử lý từng phần bài tập
    for idx, part in enumerate(parts): #
        try:
            # Giải mã iv, ciphertext, chữ ký và lấy hash từ JSON
            iv = base64.b64decode(part["iv"]) #
            ciphertext = base64.b64decode(part["cipher"]) #
            sig = base64.b64decode(part["sig"]) #
            hash_hex = part["hash"] #
        except Exception: #
            integrity_ok = False
            print(f"NACK: Lỗi định dạng ở phần {idx+1}")
            break # Thoát khỏi vòng lặp nếu có lỗi định dạng

        # Tính hash: SHA-512(IV || ciphertext)
        digest = SHA512.new(iv + ciphertext) #

        # Kiểm tra hash đã tính với hash lưu trong JSON
        if digest.hexdigest() != hash_hex: #
            integrity_ok = False
            print(f" NACK (lỗi integrity): Hash không khớp ở phần {idx+1}")
            break # Thoát khỏi vòng lặp nếu hash không khớp

        # Kiểm tra chữ ký của phần (signature) với khóa sender
        try:
            pkcs1_15.new(sender_public).verify(digest, sig) #
        except (ValueError, TypeError): #
            integrity_ok = False
            print(f" NACK (lỗi integrity): Chữ ký không hợp lệ ở phần {idx+1}")
            break # Thoát khỏi vòng lặp nếu chữ ký không hợp lệ

        # Nếu tất cả hợp lệ – Giải mã từng phần bằng DES
        des = DES.new(session_key, DES.MODE_CBC, iv) #
        plaintext = des.decrypt(ciphertext) #

        # Bỏ padding và nối vào full_content
        full_content += unpad(plaintext) #

    if integrity_ok:
        # Nếu tất cả hợp lệ – Ghép và lưu file assignment.txt
        output_path = "data/assignment_received.txt" #
        with open(output_path, "wb") as f: #
            f.write(full_content) #
        print("ACK: Đã nhận bài thành công.") # Gửi ACK tới Người gửi (mô phỏng)
        return f" Nhận bài thành công. Đã lưu vào: {output_path}" #
    else:
        # Ngược lại nếu hash hoặc chữ ký không hợp lệ – Từ chối, gửi NACK (lỗi integrity) tới Người gửi (mô phỏng)
        return "Nhận bài thất bại do lỗi toàn vẹn dữ liệu (hash hoặc chữ ký không hợp lệ)." #

# Hàm dùng để gọi nhận bài và hiện popup thông báo kết quả
def gui_receive():
    result = receive_assignment()
    messagebox.showinfo("Kết quả", result)

# Tạo giao diện GUI với Tkinter
def main():
    root = Tk()
    root.title("Nhận bài tập")

    Label(root, text=" Nhận & kiểm tra bài tập được mã hóa", font=("Arial", 12)).pack(pady=10)
    Button(root, text=" Nhận bài tập", command=gui_receive, width=30).pack(pady=15)

    root.mainloop()

# Chạy chương trình
if __name__ == "__main__":
    main()