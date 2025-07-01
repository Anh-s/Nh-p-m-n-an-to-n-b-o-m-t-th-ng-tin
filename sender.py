# Gửi bài tập chia thành nhiều phần
import os
import base64
import json
import time
from tkinter import Tk, Button, Label, filedialog, messagebox
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_v1_5
from tkinter.simpledialog import askstring

#  TẠO CẶP KHÓA RSA CHO SENDER & RECEIVER ===

def generate_keys_gui():
    os.makedirs("keys", exist_ok=True) #

    # Tạo cặp khóa RSA cho người gửi (sender)
    sender_key = RSA.generate(1024) #
    with open("keys/sender_private.pem", "wb") as f: #
        f.write(sender_key.export_key()) #
    with open("keys/sender_public.pem", "wb") as f: #
        f.write(sender_key.publickey().export_key()) #

    # Tạo cặp khóa RSA cho người nhận (receiver), khóa riêng được mã hóa bằng mật khẩu người dùng nhập
    passphrase = askstring("Nhập mật khẩu", " Nhập mật khẩu để mã hóa khóa riêng của receiver:", show="*") #
    if not passphrase: #
        messagebox.showwarning("Hủy", "Không tạo khóa do không có mật khẩu.") #
        return

    receiver_key = RSA.generate(1024) #
    with open("keys/receiver_private.pem", "wb") as f: #
        f.write(receiver_key.export_key(passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC")) #
    with open("keys/receiver_public.pem", "wb") as f: #
        f.write(receiver_key.publickey().export_key()) #

    messagebox.showinfo("Thành công", "🔐 Đã tạo cặp khóa và lưu vào thư mục 'keys/'.") #

# GỬI FILE BÀI TẬP - CHIA NHỎ, MÃ HÓA VÀ KÝ SỐ 

# Hàm padding dữ liệu để vừa block DES (8 byte)
def pad(data):
    pad_len = 8 - len(data) % 8 #
    return data + bytes([pad_len] * pad_len) #

def send_assignment(filepath):
    os.makedirs("sent", exist_ok=True) #tạo thư mục lưu file gửi
    os.makedirs("keys", exist_ok=True) #đảm bảo thư mục khóa tồn tại

    # Tải khóa riêng của sender và khóa công khai của receiver
    try:
        sender_private = RSA.import_key(open("keys/sender_private.pem").read()) #đọc khóa riêng sender
        receiver_public = RSA.import_key(open("keys/receiver_public.pem").read()) #đọc khóa công khai receiver
    except FileNotFoundError: #
        return " Thiếu file khóa trong thư mục keys/" #

    # --- 1. Handshake: Người gửi gửi "Hello!" ---
    # Tin nhắn "Hello!" sẽ được nhúng vào metadata để người nhận có thể kiểm tra
    
    # Tạo metadata gồm tên file, timestamp, số phần chia, và tin nhắn "Hello!"
    filename = os.path.basename(filepath) #
    timestamp = str(int(time.time())) #
    metadata_str = f"Hello!|{filename}|{timestamp}|3" #
    metadata = metadata_str.encode() #

    # --- 2. Xác thực & Trao khóa ---
    # Người gửi ký metadata (tên file + timestamp + số phần) bằng RSA/SHA-512
    meta_hash = SHA512.new(metadata) #
    meta_sig = pkcs1_15.new(sender_private).sign(meta_hash) #

    # Người gửi mã hóa SessionKey bằng RSA 1024-bit (PKCS#1 v1.5) và gửi
    session_key = get_random_bytes(8)  # Khóa DES 8 byte (64 bit)
    cipher_rsa = PKCS1_v1_5.new(receiver_public) #
    enc_key = cipher_rsa.encrypt(session_key) #

    # Đọc toàn bộ nội dung file
    with open(filepath, 'rb') as f: #
        content = f.read() #

    # Chia file thành 3 phần
    size = len(content) // 3 #
    parts_data = [content[i*size:(i+1)*size] for i in range(2)] + [content[2*size:]] #

    # --- 3. Mã hóa & Kiểm tra toàn vẹn ---
    packets = [] #
    for part in parts_data: #
        iv = get_random_bytes(8)  # Tạo IV (8 byte) cho DES
        cipher_des = DES.new(session_key, DES.MODE_CBC, iv) #
        ciphertext = cipher_des.encrypt(pad(part)) # Mã hóa mỗi phần bằng DES

        # Tính hash: SHA-512(IV || ciphertext) cho mỗi phần
        digest = SHA512.new(iv + ciphertext) #
        # Ký số hash của mỗi phần
        signature = pkcs1_15.new(sender_private).sign(digest) #

        # Gói tin gửi (mỗi phần)
        packets.append({
            "iv": base64.b64encode(iv).decode(), #
            "cipher": base64.b64encode(ciphertext).decode(), #
            "hash": digest.hexdigest(), #
            "sig": base64.b64encode(signature).decode() #
        })

    # Lưu toàn bộ dữ liệu đã xử lý vào file JSON
    sent_filepath = "sent/sent_packets.json" #
    with open(sent_filepath, "w") as f: #
        json.dump({
            "metadata": base64.b64encode(metadata).decode(), #
            "meta_sig": base64.b64encode(meta_sig).decode(), #
            "enc_session_key": base64.b64encode(enc_key).decode(), #
            "parts": packets #
        }, f, indent=2) #

    return f"Gửi file '{filename}' thành công. Đã chia và mã hóa 3 phần vào '{sent_filepath}'." #

#  GIAO DIỆN GUI

def gui_send():
    filepath = filedialog.askopenfilename(title="Chọn file bài tập", initialfile="assignment.txt")
    if not filepath:
        return
    result = send_assignment(filepath)
    messagebox.showinfo("Kết quả", result)

def main():
    root = Tk()
    root.title(" Gửi bài tập")

    Label(root, text="Gửi file bài tập lớn chia 3 phần (DES + RSA)", font=("Arial", 12)).pack(pady=10)
    Button(root, text="📁 Chọn và Gửi bài tập", command=gui_send, width=30).pack(pady=5)
    Button(root, text="🔑 Tạo khóa (Sender & Receiver)", command=generate_keys_gui, width=30).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()