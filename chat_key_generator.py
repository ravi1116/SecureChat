#!/usr/bin/env python3
"""
ESP32-CAM Key Generator for SecureChat
Keys are stored in chat.db and consumed on login.
Run this alongside chat_server.py.
"""

import cv2, time, hashlib, hmac, os, threading, struct, string, sqlite3
import tkinter as tk
from tkinter import scrolledtext
from collections import deque
from datetime import datetime

STREAM_URL  = "https://test-streams.mux.dev/x36xhzz/x36xhzz.m3u8"
# ESP32_IP   = "192.168.1.100"
# STREAM_URL = f"http://{ESP32_IP}/stream"

DB_PATH     = "chat.db"
KEY_LENGTH  = 16
MINI_SIZE   = (16, 16)
FRAME_DELAY = 0.3
READ_TIMEOUT = 3.0  # seconds
BASE62      = string.ascii_letters + string.digits

# -- DB --

def init_db():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            key       TEXT    NOT NULL UNIQUE,
            key_hash  TEXT    NOT NULL,
            used      INTEGER NOT NULL DEFAULT 0,
            issued    INTEGER NOT NULL DEFAULT 0,
            created   TEXT    NOT NULL,
            used_at   TEXT,
            issued_at TEXT,
            issued_to TEXT
        )
    """)
    con.commit()
    con.close()

def store_key(key, key_hash):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("INSERT INTO keys (key, key_hash, created) VALUES (?,?,?)",
                    (key, key_hash, datetime.now().isoformat()))
        con.commit()
        con.close()
        return True
    except sqlite3.IntegrityError:
        return False

def available_keys():
    con   = sqlite3.connect(DB_PATH)
    count = con.execute("SELECT COUNT(*) FROM keys WHERE used=0").fetchone()[0]
    con.close()
    return count

# -- Entropy --

class EntropyPool:
    def __init__(self):
        self.pool  = bytearray(os.urandom(32))
        self.lock  = threading.Lock()
        self.count = 0

    def mix(self, data):
        with self.lock:
            h = hashlib.sha256(data + struct.pack('>Q', self.count)).digest()
            for i in range(32): self.pool[i] ^= h[i % len(h)]
            self.pool[:] = bytearray(hashlib.sha256(bytes(self.pool)).digest())
            self.count  += 1

    def extract(self):
        with self.lock:
            return hashlib.sha256(bytes(self.pool) + os.urandom(16)).digest()

pool = EntropyPool()

def to_base62(data, length):
    num, chars = int.from_bytes(data, 'big'), []
    while num > 0 or len(chars) < length:
        num, rem = divmod(num, 62)
        chars.append(BASE62[rem])
    return ''.join(reversed(chars))[-length:]

def generate_key(frame, prev, index):
    gray   = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    visual = cv2.resize(gray, MINI_SIZE).tobytes()
    motion = b''
    if prev is not None:
        motion = cv2.resize(
            cv2.cvtColor(cv2.absdiff(frame, prev), cv2.COLOR_BGR2GRAY), MINI_SIZE
        ).tobytes()
    pool.mix(visual + motion + struct.pack('>Q', time.time_ns()) +
             struct.pack('>Q', index) + os.urandom(32))
    raw      = pool.extract()
    final    = hmac.new(os.urandom(32), raw, hashlib.sha256).digest()
    key      = to_base62(final, KEY_LENGTH)
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    return key, key_hash

# -- Stream --

running = False

def open_capture():
    cap = cv2.VideoCapture(STREAM_URL)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    if hasattr(cv2, "CAP_PROP_OPEN_TIMEOUT_MSEC"):
        cap.set(cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, int(READ_TIMEOUT * 1000))
    if hasattr(cv2, "CAP_PROP_READ_TIMEOUT_MSEC"):
        cap.set(cv2.CAP_PROP_READ_TIMEOUT_MSEC, int(READ_TIMEOUT * 1000))
    return cap

def read_with_timeout(cap, timeout_s):
    result = {"ret": False, "frame": None}
    done = threading.Event()

    def _read():
        result["ret"], result["frame"] = cap.read()
        done.set()

    t = threading.Thread(target=_read, daemon=True)
    t.start()
    done.wait(timeout_s)
    if not done.is_set():
        return False, None, True
    return result["ret"], result["frame"], False

def process_stream(on_key, on_status):
    global running
    on_status("Connecting...\n")
    cap = open_capture()
    if not cap.isOpened():
        on_status("Failed\n"); running = False; return
    on_status("Connected\n")

    prev, index, fails = None, 0, 0
    history = deque(maxlen=10)

    while running:
        ret, frame, timed_out = read_with_timeout(cap, READ_TIMEOUT)
        if timed_out:
            on_status("Read timeout - reconnecting...\n")
            cap.release(); time.sleep(1.0)
            cap = open_capture()
            if not cap.isOpened():
                on_status("Failed\n"); running = False; break
            continue
        if not ret:
            fails += 1
            on_status("Buffering...\n")
            time.sleep(0.5)
            if fails > 20:
                cap.release(); time.sleep(2)
                cap = open_capture(); fails = 0
            continue
        fails = 0
        fh = hashlib.md5(
            cv2.resize(cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY), MINI_SIZE).tobytes()
        ).digest()
        if fh in history: time.sleep(0.2); continue
        history.append(fh)
        key, kh = generate_key(frame, prev, index)
        prev    = frame.copy()
        stored  = store_key(key, kh)
        on_key(index + 1, key, stored, available_keys())
        index  += 1
        time.sleep(FRAME_DELAY)

    cap.release()
    on_status("Stopped\n")

# -- GUI --

def build_gui():
    root = tk.Tk()
    root.title("SecureChat Key Generator")
    root.geometry("580x420")
    root.configure(bg="#07080a")
    root.resizable(False, False)

    BG, FG, DIM = "#07080a", "#00e676", "#2a3040"
    MONO = ("Courier New", 11)

    hdr = tk.Frame(root, bg=BG)
    hdr.pack(fill="x", padx=16, pady=(14,4))
    tk.Label(hdr, text="SecureChat  KEY GENERATOR", font=("Courier New",13,"bold"),
             bg=BG, fg=FG).pack(side="left")
    avail_var = tk.StringVar(value="available: 0")
    tk.Label(hdr, textvariable=avail_var, font=MONO, bg=BG, fg=DIM).pack(side="right")

    log = scrolledtext.ScrolledText(root, font=MONO, bg="#030404", fg=FG,
                                    relief="flat", bd=0, height=16)
    log.pack(fill="both", expand=True, padx=16, pady=8)
    log.tag_configure("key",  foreground=FG)
    log.tag_configure("info", foreground=DIM)
    log.tag_configure("warn", foreground="#ffab40")
    log.tag_configure("err",  foreground="#ef5350")

    bf = tk.Frame(root, bg=BG)
    bf.pack(pady=(0,12))

    def append(text, tag="info"):
        root.after(0, lambda: (log.insert(tk.END, text, tag), log.see(tk.END)))

    def on_key(idx, key, stored, avail):
        root.after(0, lambda: (
            log.insert(tk.END, f"[{idx:>4}]  {key}{'  (dup)' if not stored else ''}\n",
                       "key" if stored else "info"),
            log.see(tk.END),
            avail_var.set(f"available: {avail}")
        ))

    def on_status(msg):
        tag = "warn" if "Buffering" in msg or "timeout" in msg else "info"
        append(msg, tag)

    def start():
        global running
        if running: return
        running = True
        threading.Thread(target=process_stream, args=(on_key, on_status), daemon=True).start()

    def stop():
        global running
        running = False

    def make_btn(txt, cmd, fg):
        tk.Button(bf, text=txt, command=cmd, font=MONO, bg="#0e1014", fg=fg,
                  activebackground=fg, activeforeground="#000",
                  relief="flat", padx=14, pady=5, cursor="hand2").pack(side="left", padx=6)

    make_btn("START", start, FG)
    make_btn("STOP",  stop,  "#ef5350")

    init_db()
    avail_var.set(f"available: {available_keys()}")
    root.mainloop()

if __name__ == "__main__":
    build_gui()
