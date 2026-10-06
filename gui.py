"""
DanServe GUI.
Запускается ярлыком от имени администратора.
"""
import sys
import platform
import threading
import tkinter as tk
from tkinter import ttk, messagebox

from engine import (
    DanServeEngine,
    start_coord_server, gc_loop,
    SERVER_PORT, PUBLIC_SERVERS,
    wg_installed, is_admin,
)


class DanServeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DanServe VPN")
        self.root.geometry("700x640")
        self.engine = None
        self.server = None

        if not wg_installed():
            messagebox.showerror(
                "DanServe",
                "WireGuard не найден.\n\n"
                "Установи: https://www.wireguard.com/install/\n"
                "Затем запусти DanServe снова."
            )
            sys.exit(1)

        if not is_admin():
            messagebox.showerror(
                "DanServe",
                "Нужны права администратора.\n"
                "Запусти ярлык «DanServe» с правами админа."
            )
            sys.exit(1)

        self._build_ui()
        self._tick()

    # ---------- UI ----------
    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        f_net = ttk.LabelFrame(self.root, text="Сеть")
        f_net.pack(fill="x", **pad)

        ttk.Label(f_net, text="Имя сети:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.e_name = ttk.Entry(f_net, width=32)
        self.e_name.insert(0, "my-network")
        self.e_name.grid(row=0, column=1, padx=6, pady=4, sticky="we")

        ttk.Label(f_net, text="Пароль:").grid(row=1, column=0, sticky="w", padx=6, pady=4)
        self.e_pass = ttk.Entry(f_net, width=32, show="•")
        self.e_pass.insert(0, "changeme")
        self.e_pass.grid(row=1, column=1, padx=6, pady=4, sticky="we")

        ttk.Label(f_net, text="Имя узла:").grid(row=2, column=0, sticky="w", padx=6, pady=4)
        self.e_node = ttk.Entry(f_net, width=32)
        self.e_node.insert(0, platform.node())
        self.e_node.grid(row=2, column=1, padx=6, pady=4, sticky="we")
        f_net.columnconfigure(1, weight=1)

        f_srv = ttk.LabelFrame(self.root, text="Координатор")
        f_srv.pack(fill="x", **pad)

        self.srv_mode = tk.StringVar(value="own")
        ttk.Radiobutton(f_srv, text="Свой (запустить локально)",
                        variable=self.srv_mode, value="own",
                        command=self._toggle_srv)\
            .grid(row=0, column=0, columnspan=2, sticky="w", padx=6, pady=2)
        ttk.Radiobutton(f_srv, text="Указать URL сервера",
                        variable=self.srv_mode, value="remote",
                        command=self._toggle_srv)\
            .grid(row=1, column=0, columnspan=2, sticky="w", padx=6, pady=2)

        ttk.Label(f_srv, text="URL:").grid(row=2, column=0, sticky="w", padx=6, pady=4)
        self.e_url = ttk.Entry(f_srv, width=42)
        self.e_url.insert(0, "http://127.0.0.1:8765")
        self.e_url.grid(row=2, column=1, padx=6, pady=4, sticky="we")
        self.e_url.configure(state="disabled")

        if PUBLIC_SERVERS:
            ttk.Label(f_srv, text="Публичный:").grid(row=3, column=0, sticky="w", padx=6, pady=4)
            self.cb_pub = ttk.Combobox(f_srv, values=PUBLIC_SERVERS,
                                       state="readonly", width=40)
            self.cb_pub.grid(row=3, column=1, padx=6, pady=4, sticky="we")
            self.cb_pub.bind(
                "<<ComboboxSelected>>",
                lambda e: (self.e_url.delete(0, "end"),
                           self.e_url.insert(0, self.cb_pub.get())),
            )
        f_srv.columnconfigure(1, weight=1)

        f_btn = ttk.Frame(self.root)
        f_btn.pack(fill="x", **pad)
        self.btn_conn = ttk.Button(f_btn, text="Подключиться к сети",
                                   command=self._connect)
        self.btn_conn.pack(side="left", padx=6)
        self.btn_srv = ttk.Button(f_btn, text="Только координатор",
                                  command=self._toggle_srv_only)
        self.btn_srv.pack(side="left", padx=6)

        f_st = ttk.LabelFrame(self.root, text="Статус")
        f_st.pack(fill="x", **pad)
        self.lbl_status = ttk.Label(f_st, text="Отключено",
                                    font=("TkDefaultFont", 10, "bold"))
        self.lbl_status.pack(anchor="w", padx=6, pady=2)
        self.lbl_ip = ttk.Label(f_st, text="Виртуальный IP: —")
        self.lbl_ip.pack(anchor="w", padx=6, pady=2)
        self.lbl_net = ttk.Label(f_st, text="Сеть: —")
        self.lbl_net.pack(anchor="w", padx=6, pady=2)

        f_peers = ttk.LabelFrame(self.root, text="Участники сети")
        f_peers.pack(fill="both", expand=True, **pad)
        cols = ("name", "ip", "endpoint")
        self.tree = ttk.Treeview(f_peers, columns=cols, show="headings", height=6)
        for c, t, w in [("name", "Имя", 140), ("ip", "IP", 130),
                        ("endpoint", "Endpoint", 240)]:
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w)
        self.tree.pack(fill="both", expand=True, padx=6, pady=6)

        f_log = ttk.LabelFrame(self.root, text="Лог")
        f_log.pack(fill="both", expand=True, **pad)
        self.txt_log = tk.Text(f_log, height=8, wrap="word")
        self.txt_log.pack(fill="both", expand=True, padx=6, pady=6)
        self.txt_log.configure(state="disabled")

    # ---------- логика ----------
    def _toggle_srv(self):
        self.e_url.configure(
            state="normal" if self.srv_mode.get() == "remote" else "disabled")

    def _toggle_srv_only(self):
        if self.server:
            self.server = None
            self.lbl_status.configure(text="Координатор остановлен")
            self.btn_srv.configure(text="Только координатор")
            return
        self.server = start_coord_server(SERVER_PORT)
        threading.Thread(target=gc_loop, daemon=True).start()
        self.lbl_status.configure(text=f"Координатор на :{SERVER_PORT}")
        self.btn_srv.configure(text="Остановить координатор")
        self._log(f"Координатор запущен на :{SERVER_PORT}")

    def _connect(self):
        if self.engine and self.engine.running:
            self._disconnect()
            return
        net_name = self.e_name.get().strip()
        net_pass = self.e_pass.get()
        node = self.e_node.get().strip() or "node"
        if not net_name:
            messagebox.showerror("DanServe", "Введи имя сети.")
            return
        local = self.srv_mode.get() == "own"
        url = "" if local else self.e_url.get().strip()
        if not local and not url:
            messagebox.showerror("DanServe", "Укажи URL сервера.")
            return
        self.engine = DanServeEngine()
        self.engine.start(url, net_name, net_pass, node, run_local_server=local)
        self.lbl_status.configure(text="Подключение...")
        self.btn_conn.configure(text="Отключиться")
        self._log(f"Клиент: сеть '{net_name}', узел '{node}'")

    def _disconnect(self):
        if self.engine:
            self.engine.stop()
            self.engine = None
        self.lbl_status.configure(text="Отключено")
        self.lbl_ip.configure(text="Виртуальный IP: —")
        self.lbl_net.configure(text="Сеть: —")
        self.btn_conn.configure(text="Подключиться к сети")
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _log(self, line):
        self.txt_log.configure(state="normal")
        self.txt_log.insert("end", line + "\n")
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    def _tick(self):
        if self.engine:
            new = self.engine.log_lines
            if new:
                self.txt_log.configure(state="normal")
                self.txt_log.delete("1.0", "end")
                self.txt_log.insert("end", "\n".join(new) + "\n")
                self.txt_log.see("end")
                self.txt_log.configure(state="disabled")
            if self.engine.my_virtual_ip:
                self.lbl_ip.configure(
                    text=f"Виртуальный IP: {self.engine.my_virtual_ip}")
            if self.engine.network_name:
                self.lbl_net.configure(text=f"Сеть: {self.engine.network_name}")
            self.lbl_status.configure(
                text="Подключено" if self.engine.running else "Отключено")
            remote = {p["pubkey"]: p for p in self.engine.get_peers()}
            for pk in list(self.tree.get_children()):
                if pk not in remote:
                    self.tree.delete(pk)
            for pk, p in remote.items():
                vals = (p["name"], p["virtual_ip"], p.get("endpoint") or "—")
                if self.tree.exists(pk):
                    self.tree.item(pk, values=vals)
                else:
                    self.tree.insert("", "end", iid=pk, values=vals)
        self.root.after(1000, self._tick)


if __name__ == "__main__":
    root = tk.Tk()
    DanServeApp(root)
    root.mainloop()