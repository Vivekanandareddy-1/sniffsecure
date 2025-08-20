
import sys
import os

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and PyInstaller """
    try:
        base_path = sys._MEIPASS  # When using PyInstaller
    except Exception:
        base_path = os.path.abspath(".")  # When running normally
    return os.path.join(base_path, relative_path)



import smtplib, ssl
from email.message import EmailMessage

def send_email_alert(src_ip, dst_ip, port, danger_type):
    sender_email = "(your sender email)"
    app_password = "(app mail password)"
    recipient_email = "(to which email address the notifications have to sent)"

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

    print("📧 Email alert sent!")


from scapy.all import sniff, IP, TCP
import winsound
# include send_email_alert function here

safe_ports = [80, 443, 53, 22]
dangerous_ports = [23, 21, 25, 445, 3389]
    # Alert logic


def process_packet(packet):
    

    if IP in packet and TCP in packet:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        port = tcp_layer.dport

        if port in dangerous_ports:
            print(f"🚨 Dangerous Port: {port} from {src_ip} -> {dst_ip}")
            winsound.PlaySound(resource_path("alert.wav"), winsound.SND_FILENAME)
            winsound.Beep(500, 2000) 



            send_email_alert(src_ip, dst_ip, port, "Dangerous Port")
        elif port not in safe_ports or port > 1024:
            print(f"⚠️ Unknown/High Port: {port} from {src_ip} -> {dst_ip}")
            winsound.PlaySound(resource_path("alert.wav"), winsound.SND_FILENAME)
            winsound.Beep(500, 2000)


            send_email_alert(src_ip, dst_ip, port, "High/Unknown Port")
        else:
            print(f"[+] Safe Packet: {src_ip} -> {dst_ip} (Port {port})")

print("🔍 Sniffing Started... Press CTRL+C to stop")
sniff(prn=process_packet, store=False)

