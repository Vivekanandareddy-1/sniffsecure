import smtplib
from email.message import EmailMessage
import os



import sys
import os

def resource_path(relative_path):
    """Get absolute path to resource, for PyInstaller and normal run"""
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)



import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP
import threading
import winsound
import smtplib, ssl
from email.message import EmailMessage

# ===== Email Config =====
sender_email = "chittitherobotmachine2.0@gmail.com"
app_password = "awyw fvoy czqq acao"
recipient_email = "vivekuses2006@gmail.com"

# ===== Port Lists =====
safe_ports = [80, 443, 53, 22]
dangerous_ports = [23, 21, 25, 445, 3389]

# ===== GUI =====
root = tk.Tk()
root.title("SniffSecure Intrusion Detection")
root.geometry("700x400")

# Text display area
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=80, height=20)
text_area.pack(pady=10)

# ===== Email Alert Function =====
def send_email_alert(src_ip, dst_ip, port, danger_type):
    try:
        msg = EmailMessage()
        msg['Subject'] = f"SniffSecure Alert: {danger_type}"
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg.set_content(f"""
        Suspicious packet detected!

        Type: {danger_type}
        Source IP: {src_ip}
        Destination IP: {dst_ip}
        Port: {port}
        """)
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
        text_area.insert(tk.END, "📧 Email alert sent!\n")
    except Exception as e:
        text_area.insert(tk.END, f"❌ Email error: {e}\n")

# ===== Packet Processing =====
sniffing = False

def process_packet(packet):
    global sniffing
    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        port = tcp_layer.dport
        msg = f"{src_ip} → {dst_ip} | Port: {port}"

        if port in dangerous_ports:
            text_area.insert(tk.END, f"🚨 Dangerous Port: {msg}\n")
            winsound.PlaySound(resource_path("alert.wav"),winsound.SND_FILENAME)
            winsound.Beep(500, 2000)

            send_email_alert(src_ip, dst_ip, port, "Dangerous Port")
        elif port not in safe_ports or port > 1024:
            text_area.insert(tk.END, f"⚠️ Unknown/High Port: {msg}\n")
            winsound.PlaySound(resource_path("alert.wav"),winsound.SND_FILENAME)
            winsound.Beep(500, 2000)

            send_email_alert(src_ip, dst_ip, port, "Unknown/High Port")
        else:
            text_area.insert(tk.END, f"[+] Normal: {msg}\n")

        text_area.see(tk.END)

# ===== Sniff Control =====
def start_sniffing():
    global sniffing
    sniffing = True
    text_area.insert(tk.END, "🔍 Sniffing Started...\n")
    text_area.see(tk.END)

    def sniff_thread():
        sniff(prn=process_packet, store=False, stop_filter=lambda p: not sniffing)

    threading.Thread(target=sniff_thread, daemon=True).start()


def stop_sniffing():
    global sniffing
    sniffing = False
    text_area.insert(tk.END, "🛑 Sniffing Stopped (Close the app to stop completely)\n")

# ===== Buttons =====
start_btn = tk.Button(root, text="▶ Start Sniffing", command=start_sniffing, bg="green", fg="white")
start_btn.pack(pady=5)

stop_btn = tk.Button(root, text="■ Stop Sniffing", command=stop_sniffing, bg="red", fg="white")
stop_btn.pack()

def on_closing():
    global sniffing
    sniffing = False
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)




# ===== Run App =====
root.mainloop()
