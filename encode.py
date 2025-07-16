import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
import urllib.parse
import binascii
import hashlib
import json

class EncoderDecoderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encoder/Decoder Tool")
        self.root.geometry("800x600")

        # Input Text
        self.input_label = ttk.Label(root, text="Input Text:")
        self.input_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.input_text = scrolledtext.ScrolledText(root, height=10, width=80, wrap=tk.WORD)
        self.input_text.grid(row=0, column=1, padx=10, pady=10, columnspan=2)

        # Output Text
        self.output_label = ttk.Label(root, text="Output Text:")
        self.output_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.output_text = scrolledtext.ScrolledText(root, height=10, width=80, wrap=tk.WORD)
        self.output_text.grid(row=1, column=1, padx=10, pady=10, columnspan=2)

        # Encoding Options
        self.encoding_label = ttk.Label(root, text="Encoding Options:")
        self.encoding_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.encoding_options = ttk.Combobox(
            root,
            values=[
                "Base64 Encode",
                "Base64 Decode",
                "URL Encode",
                "URL Decode",
                "Hex Encode",
                "Hex Decode",
                "MD5 Hash",
                "SHA1 Hash",
                "SHA256 Hash",
                "JSON Beautify",
                "JSON Minify",
            ],
        )
        self.encoding_options.grid(row=2, column=1, padx=10, pady=10)
        self.encoding_options.current(0)

        # Buttons
        self.process_button = ttk.Button(root, text="Process", command=self.process_text)
        self.process_button.grid(row=3, column=1, padx=10, pady=10)

        self.copy_button = ttk.Button(root, text="Copy Output", command=self.copy_output)
        self.copy_button.grid(row=3, column=2, padx=10, pady=10)

        self.clear_button = ttk.Button(root, text="Clear", command=self.clear_text)
        self.clear_button.grid(row=4, column=1, padx=10, pady=10)

    def process_text(self):
        input_text = self.input_text.get("1.0", tk.END).strip()
        encoding_option = self.encoding_options.get()

        try:
            output_lines = []
            for line in input_text.splitlines():
                if encoding_option == "Base64 Encode":
                    output_line = base64.b64encode(line.encode()).decode()
                elif encoding_option == "Base64 Decode":
                    output_line = base64.b64decode(line.encode()).decode()
                elif encoding_option == "URL Encode":
                    output_line = urllib.parse.quote(line)
                elif encoding_option == "URL Decode":
                    output_line = urllib.parse.unquote(line)
                elif encoding_option == "Hex Encode":
                    output_line = line.encode().hex()
                elif encoding_option == "Hex Decode":
                    output_line = bytes.fromhex(line).decode()
                elif encoding_option == "MD5 Hash":
                    output_line = hashlib.md5(line.encode()).hexdigest()
                elif encoding_option == "SHA1 Hash":
                    output_line = hashlib.sha1(line.encode()).hexdigest()
                elif encoding_option == "SHA256 Hash":
                    output_line = hashlib.sha256(line.encode()).hexdigest()
                elif encoding_option == "JSON Beautify":
                    output_line = json.dumps(json.loads(line), indent=4)
                elif encoding_option == "JSON Minify":
                    output_line = json.dumps(json.loads(line), separators=(",", ":"))
                else:
                    output_line = "Invalid option"
                output_lines.append(output_line)

            output_text = "\n".join(output_lines)
        except Exception as e:
            output_text = f"Error: {str(e)}"

        self.output_text.delete("1.0", tk.END)
        self.output_text.insert("1.0", output_text)

    def copy_output(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.output_text.get("1.0", tk.END).strip())
        messagebox.showinfo("Copied", "Output copied to clipboard!")

    def clear_text(self):
        self.input_text.delete("1.0", tk.END)
        self.output_text.delete("1.0", tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = EncoderDecoderApp(root)
    root.mainloop()