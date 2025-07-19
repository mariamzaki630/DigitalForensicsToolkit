
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess

def perform_action(action):
    try:
        output_text.delete(1.0, tk.END)
        if action == "Network Scan (Nmap)":
            result = subprocess.run(["nmap", "-sP", "127.0.0.1"], capture_output=True, text=True)
            output_text.insert(tk.END, result.stdout)
        elif action == "Capture Packets (Wireshark)":
            messagebox.showinfo("Info", "Please install Wireshark and run it for detailed packet capture.")
        elif action == "Disk Image Analysis":
            file_path = filedialog.askopenfilename(title="Select Disk Image")
            if file_path:
                output_text.insert(tk.END, f"Selected Disk Image: {file_path}\n")
        elif action == "Analyze Registry":
            result = subprocess.run(["reg", "query", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"],
                                    capture_output=True, text=True)
            output_text.insert(tk.END, result.stdout)
        elif action == "Event Log Analysis":
            result = subprocess.run(["wevtutil", "qe", "System", "/c:5", "/f:text"],
                                    capture_output=True, text=True)
            output_text.insert(tk.END, result.stdout)
        elif action == "File Hashing":
            file_path = filedialog.askopenfilename(title="Select File for Hashing")
            if file_path:
                result = subprocess.run(["certutil", "-hashfile", file_path, "SHA256"],
                                        capture_output=True, text=True)
                output_text.insert(tk.END, result.stdout)
        elif action == "Email Parsing":
            output_text.insert(tk.END, "Email parsing requires specific email file formats.\n")
        elif action == "Malware Scan":
            output_text.insert(tk.END, "Please install ClamAV or YARA for malware analysis.\n")
        elif action == "Timeline Creation":
            output_text.insert(tk.END, "Install Plaso for advanced timeline creation.\n")
        else:
            output_text.insert(tk.END, "Invalid Action Selected.\n")
    except Exception as e:
        output_text.insert(tk.END, f"Error: {str(e)}\n")

app = tk.Tk()
app.title("Digital Forensics Toolkit")
app.geometry("900x650")
app.configure(bg="#2d2f36")

style = ttk.Style()
style.configure("TLabel", font=("Arial", 14), background="#2d2f36", foreground="#ffffff")
style.configure("TButton", font=("Arial", 12), background="#007acc", foreground="#ffffff", padding=10)
style.configure("TCombobox", font=("Arial", 12), width=40)
style.configure("TFrame", background="#2d2f36")

header_frame = ttk.Frame(app)
header_frame.pack(fill=tk.X, padx=10, pady=20)

header_label = ttk.Label(header_frame, text="Digital Forensics Toolkit", font=("Arial", 24, "bold"))
header_label.pack()

action_frame = ttk.Frame(app)
action_frame.pack(fill=tk.X, padx=20, pady=10)

action_label = ttk.Label(action_frame, text="Select an Action:", font=("Arial", 16))
action_label.pack(side=tk.LEFT, padx=5)

actions = [
    "Network Scan (Nmap)",
    "Capture Packets (Wireshark)",
    "Disk Image Analysis",
    "Analyze Registry",
    "Event Log Analysis",
    "File Hashing",
    "Email Parsing",
    "Malware Scan",
    "Timeline Creation"
]

selected_action = tk.StringVar(value=actions[0])
action_dropdown = ttk.Combobox(action_frame, textvariable=selected_action, values=actions, state="readonly", width=40)
action_dropdown.pack(side=tk.LEFT, padx=10)

execute_button = ttk.Button(action_frame, text="Execute", command=lambda: perform_action(selected_action.get()))
execute_button.pack(side=tk.LEFT, padx=10)

output_frame = ttk.Frame(app)
output_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

output_label = ttk.Label(output_frame, text="Output:", font=("Arial", 16))
output_label.pack(anchor="w")

output_text = tk.Text(output_frame, wrap=tk.WORD, height=15, bg="#3c3f47", font=("Courier New", 10), fg="#ffffff")
output_text.pack(fill=tk.BOTH, expand=True, pady=5)

footer_frame = ttk.Frame(app)
footer_frame.pack(fill=tk.X, padx=10, pady=10)

footer_label = ttk.Label(footer_frame, text="Developed by Your Trusted Assistant", font=("Arial", 10, "italic"))
footer_label.pack()

app.mainloop()
