import tkinter as tk
from tkinter import filedialog
import quick_scan
import structural_scan
import os
import webbrowser


class CyberScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberScan")
        self.root.geometry("900x600")
        self.root.configure(bg="#1e1e1e")

        self.file_path = None

        # ---------------- TOP BAR ----------------
        topbar = tk.Frame(root, bg="#252526", height=50)
        topbar.pack(fill="x")

        tk.Label(
            topbar,
            text="CyberScan Security Analyzer",
            font=("Segoe UI", 14, "bold"),
            fg="white",
            bg="#252526"
        ).pack(side="left", padx=15, pady=10)

        # ---------------- MAIN AREA ----------------
        main = tk.Frame(root, bg="#1e1e1e")
        main.pack(fill="both", expand=True)

        # ---------------- LEFT PANEL ----------------
        sidebar = tk.Frame(main, bg="#2d2d2d", width=220)
        sidebar.pack(side="left", fill="y")

        tk.Label(
            sidebar,
            text="TOOLS",
            bg="#2d2d2d",
            fg="#aaaaaa",
            font=("Segoe UI", 10, "bold")
        ).pack(anchor="w", padx=20, pady=(20, 10))

        button_style = {
            "font": ("Segoe UI", 10),
            "bg": "#3a3a3a",
            "fg": "white",
            "activebackground": "#505050",
            "activeforeground": "white",
            "bd": 0,
            "width": 18,
            "anchor": "w",
            "padx": 15,
            "pady": 8
        }

        tk.Button(
            sidebar,
            text="Upload File",
            command=self.upload_file,
            **button_style
        ).pack(pady=4)

        tk.Button(
            sidebar,
            text="Quick Scan",
            command=self.open_quick_scan,
            **button_style
        ).pack(pady=4)

        tk.Button(
            sidebar,
            text="Structural Parsing",
            command=self.open_structural_scan,
            **button_style
        ).pack(pady=4)

        # ---------------- RIGHT WORKSPACE ----------------
        workspace = tk.Frame(main, bg="#1e1e1e")
        workspace.pack(side="left", fill="both", expand=True)

        self.workspace_label = tk.Label(
            workspace,
            text="Select a file to begin analysis",
            font=("Segoe UI", 16),
            fg="#bbbbbb",
            bg="#1e1e1e"
        )
        self.workspace_label.pack(expand=True)

        # ---------------- STATUS BAR ----------------
        statusbar = tk.Frame(root, bg="#252526", height=25)
        statusbar.pack(fill="x", side="bottom")

        self.status = tk.Label(
            statusbar,
            text="No file selected",
            bg="#252526",
            fg="#cccccc",
            font=("Segoe UI", 9)
        )
        self.status.pack(side="left", padx=10)

    def upload_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path = path
            filename = os.path.basename(path)

            # update center text
            self.workspace_label.config(text=f"Loaded File:\n{filename}")

            # update status bar
            self.status.config(text=f"Loaded: {filename}")

    def open_quick_scan(self):
        if not self.file_path:
            return
        QuickScanWindow(self.root, self.file_path)

    def open_structural_scan(self):
        if not self.file_path:
            return
        StructuralScanWindow(self.root, self.file_path)


# -------------------------------------------------
# QUICK SCAN WINDOW
# -------------------------------------------------
class QuickScanWindow:
    def __init__(self, parent, file_path):
        self.file_path = file_path

        self.window = tk.Toplevel(parent)
        self.window.title("Quick Scan")
        self.window.geometry("900x700")
        self.window.configure(bg="#2c3e50")

        tk.Label(
            self.window,
            text="🔍 Quick Scan Analysis",
            font=("Arial", 16, "bold"),
            fg="white",
            bg="#2c3e50",
            pady=15
        ).pack()

        # ✅ ADDED HEX VIEW (no existing code modified)
        tk.Label(
            self.window,
            text="File Bytes (Hex View)",
            fg="white",
            bg="#2c3e50"
        ).pack()

        self.hex_view = tk.Text(
            self.window,
            height=10,
            width=110,
            bg="#1e272e",
            fg="#00ffcc",
            font=("Courier New", 9)
        )
        self.hex_view.pack(pady=10)
        self.hex_view.tag_config("highlight", background="yellow", foreground="black")

        # Results view
        tk.Label(
            self.window,
            text="Scan Results",
            fg="white",
            bg="#2c3e50"
        ).pack()

        self.result_view = tk.Text(
            self.window,
            height=20,
            width=110,
            bg="#ecf0f1",
            font=("Courier New", 10)
        )
        self.result_view.pack(pady=10)

        self.load_bytes()  # <-- ADDED CALL
        self.run_scan()

    def log(self, message):
        self.result_view.insert(tk.END, message + "\n")
        self.result_view.see(tk.END)

    # ✅ ADDED FUNCTION — DOES NOT REMOVE ANYTHING
    def load_bytes(self):
        try:
            with open(self.file_path, "rb") as f:
                data = f.read(256)

            hex_string = " ".join(f"{b:02X}" for b in data)

            self.hex_view.insert(tk.END, hex_string)

        except Exception as e:
            self.hex_view.insert(tk.END, f"Error reading file: {e}")

    def highlight_bytes(self, start, length):
        start_index = start * 3
        end_index = (start + length) * 3

        self.hex_view.tag_add(
            "highlight",
            f"1.{start_index}",
            f"1.{end_index}"
        )

    def run_scan(self):

        result = quick_scan.scan(self.file_path, self.log)

        if result:
            self.highlight_bytes(result["offset"], result["length"])


# -------------------------------------------------
# STRUCTURAL SCAN WINDOW
# -------------------------------------------------
# -------------------------------------------------
# STRUCTURAL SCAN WINDOW
# -------------------------------------------------
class StructuralScanWindow:
    def __init__(self, parent, file_path):
        self.file_path = file_path

        self.window = tk.Toplevel(parent)
        self.window.title("Structural Parsing")
        self.window.geometry("900x700")
        self.window.configure(bg="#2c3e50")

        tk.Label(
            self.window,
            text="🧩 Structural Parsing Analysis",
            font=("Arial", 16, "bold"),
            fg="white",
            bg="#2c3e50",
            pady=15
        ).pack()

        # ✅ HEX VIEW
        tk.Label(
            self.window,
            text="File Bytes (Hex View)",
            fg="white",
            bg="#2c3e50"
        ).pack()

        self.hex_view = tk.Text(
            self.window,
            height=15,
            width=110,
            bg="#1e272e",
            fg="#00ffcc",
            font=("Courier New", 9)
        )
        self.hex_view.pack(pady=5)

        # Configure highlight tag
        # Required structure
        self.hex_view.tag_config(
            "required",
            background="yellow",
            foreground="black"
        )

        # Optional structure
        self.hex_view.tag_config(
            "optional",
            background="#4da6ff",
            foreground="black"
        )

        # ✅ RESULT VIEW
        tk.Label(
            self.window,
            text="Scan Results",
            fg="white",
            bg="#2c3e50"
        ).pack()

        self.result_view = tk.Text(
            self.window,
            height=15,
            width=110,
            bg="#ecf0f1",
            font=("Courier New", 10)
        )
        self.result_view.pack(pady=5)

        self.data = b""
        self.load_bytes()
        self.run_scan()

    def log(self, message, error=False):
        self.result_view.tag_config("error", foreground="red", font=("Courier New", 10, "bold"))


        self.result_view.insert(tk.END, message + "\n")
        self.result_view.see(tk.END)


    def log_link(self, text, file_path):
        start = self.result_view.index(tk.END)

        self.result_view.insert(tk.END, text + "\n")

        end = self.result_view.index(tk.END)

        self.result_view.tag_add(file_path, start, end)
        self.result_view.tag_config(file_path, foreground="blue", underline=1)

        self.result_view.tag_bind(
            file_path,
            "<Button-1>",
            lambda e: webbrowser.open(file_path)
        )

    def load_bytes(self):
        try:
            with open(self.file_path, "rb") as f:
                self.data = f.read(512)  # read first 512 bytes

            hex_string = " ".join(f"{b:02X}" for b in self.data)
            self.hex_view.insert(tk.END, hex_string)

        except Exception as e:
            self.hex_view.insert(tk.END, f"Error reading file: {e}")



    def run_scan(self):

        result = structural_scan.scan(self.file_path, self.log)


# -------------------------------------------------
# RUN APP
# -------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = CyberScanApp(root)
    root.mainloop()
