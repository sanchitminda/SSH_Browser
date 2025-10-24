import os
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import paramiko
from mutagen import File
import logging
from cryptography.fernet import Fernet
import json

class FileManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Manager")

        # Server details
        self.server_ip = ""
        self.server_port = 22
        self.username = ""
        self.password = ""

        # UI Elements
        self.menu = tk.Menu(self.root)
        self.root.config(menu=self.menu)

        self.server_menu = tk.Menu(self.menu, tearoff=0)
        self.server_menu.add_command(label="Configure Server", command=self.configure_server)
        self.menu.add_cascade(label="Server", menu=self.server_menu)

        self.file_listbox = tk.Listbox(self.root, selectmode=tk.SINGLE, width=80, height=20)
        self.file_listbox.pack(pady=10)
        self.file_listbox.bind('<<ListboxSelect>>', self.display_metadata)

        self.metadata_text = tk.Text(self.root, height=10, width=80)
        self.metadata_text.pack(pady=10)

        self.delete_button = tk.Button(self.root, text="Delete File", command=self.delete_file)
        self.delete_button.pack(pady=5)

        self.back_button = tk.Button(self.root, text="Back", command=self.go_to_parent_directory)
        self.back_button.pack(pady=5)

        self.sftp = None

        # Configure logging
        logging.basicConfig(
            filename="file_manager.log",
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

        # Generate or load encryption key
        KEY_FILE = "encryption.key"
        if not os.path.exists(KEY_FILE):
            with open(KEY_FILE, "wb") as key_file:
                key_file.write(Fernet.generate_key())
        with open(KEY_FILE, "rb") as key_file:
            self.encryption_key = key_file.read()
        self.fernet = Fernet(self.encryption_key)

        self.server_details_file = "server_details.enc"

    def configure_server(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("Configure Server")

        tk.Label(config_window, text="Server IP:").grid(row=0, column=0, padx=10, pady=5, sticky="e")
        server_ip_entry = tk.Entry(config_window)
        server_ip_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(config_window, text="Server Port:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
        server_port_entry = tk.Entry(config_window)
        server_port_entry.grid(row=1, column=1, padx=10, pady=5)

        tk.Label(config_window, text="Username:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
        username_entry = tk.Entry(config_window)
        username_entry.grid(row=2, column=1, padx=10, pady=5)

        tk.Label(config_window, text="Password:").grid(row=3, column=0, padx=10, pady=5, sticky="e")
        password_entry = tk.Entry(config_window, show="*")
        password_entry.grid(row=3, column=1, padx=10, pady=5)

        def save_server_details():
            server_details = {
                "server_ip": server_ip_entry.get(),
                "server_port": server_port_entry.get(),
                "username": username_entry.get(),
                "password": password_entry.get()
            }
            encrypted_data = self.fernet.encrypt(json.dumps(server_details).encode())
            with open(self.server_details_file, "wb") as file:
                file.write(encrypted_data)
            logging.info("Server details saved and encrypted.")
            messagebox.showinfo("Success", "Server details saved successfully!")
            config_window.destroy()

        def load_saved_server():
            if os.path.exists(self.server_details_file):
                with open(self.server_details_file, "rb") as file:
                    encrypted_data = file.read()
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                server_details = json.loads(decrypted_data)

                server_ip_entry.delete(0, tk.END)
                server_ip_entry.insert(0, server_details["server_ip"])

                server_port_entry.delete(0, tk.END)
                server_port_entry.insert(0, server_details["server_port"])

                username_entry.delete(0, tk.END)
                username_entry.insert(0, server_details["username"])

                password_entry.delete(0, tk.END)
                password_entry.insert(0, server_details["password"])

                logging.info("Loaded saved server details into the form.")
            else:
                messagebox.showerror("Error", "No saved server details found.")

        def connect_with_details():
            self.server_ip = server_ip_entry.get()
            self.server_port = int(server_port_entry.get())
            self.username = username_entry.get()
            self.password = password_entry.get()

            if self.server_ip and self.server_port and self.username and self.password:
                logging.info("Attempting to connect with provided server details.")
                config_window.destroy()
                self.connect_to_server()
            else:
                logging.error("Connection failed: Missing server details.")
                messagebox.showerror("Error", "All fields are required to connect to the server.")

        tk.Button(config_window, text="Load Saved Server", command=load_saved_server).grid(row=4, column=0, padx=10, pady=10)
        tk.Button(config_window, text="Save", command=save_server_details).grid(row=4, column=1, padx=10, pady=10)
        tk.Button(config_window, text="Connect", command=connect_with_details).grid(row=5, column=0, columnspan=2, pady=10)

    def connect_to_server(self):
        loading_screen = tk.Toplevel(self.root)
        loading_screen.title("Connecting...")
        tk.Label(loading_screen, text="Connecting to server, please wait...").pack(padx=20, pady=20)
        self.root.update()

        try:
            logging.info("Attempting to connect to server %s:%d", self.server_ip, self.server_port)
            transport = paramiko.Transport((self.server_ip, self.server_port))
            transport.connect(username=self.username, password=self.password)
            self.sftp = paramiko.SFTPClient.from_transport(transport)
            logging.info("Connected to server successfully")
            messagebox.showinfo("Success", "Connected to server successfully!")

            # Start with the root directory
            self.list_files("/")
        except Exception as e:
            logging.error("Connection error: %s", str(e))
            messagebox.showerror("Connection Error", str(e))
        finally:
            loading_screen.destroy()

    def list_files(self, remote_path="."):
        try:
            if not self.sftp:
                messagebox.showerror("Error", "Not connected to server.")
                return

            self.file_listbox.delete(0, tk.END)
            self.current_path = remote_path

            if remote_path != ".":
                self.file_listbox.insert(tk.END, "[PARENT DIR] ..")

            self.file_paths = []  # Store full paths of files and directories

            for entry in self.sftp.listdir_attr(remote_path):
                full_path = f"{remote_path.rstrip('/')}/{entry.filename}"  # Removed lstrip('/')
                self.file_paths.append(full_path)

                if entry.st_mode & 0o40000:  # Directory
                    self.file_listbox.insert(tk.END, f"[DIR] {entry.filename}")
                else:
                    self.file_listbox.insert(tk.END, entry.filename)

                # Log the file or directory being listed
                logging.info("Listed: %s", full_path)

            self.file_listbox.bind('<<ListboxSelect>>', self.on_file_select)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def on_file_select(self, event):
        try:
            selected_item = self.file_listbox.get(self.file_listbox.curselection())

            if selected_item == "[PARENT DIR] ..":
                self.current_path = os.path.dirname(self.current_path.rstrip("/")) or "/"
                self.list_files(self.current_path)
            elif selected_item.startswith("[DIR] "):
                directory_name = selected_item[6:]
                self.current_path = f"/{self.current_path.rstrip('/')}/{directory_name}".lstrip("/")
                if not self.current_path.startswith("/"):
                    self.current_path = "/" + self.current_path
                self.list_files(self.current_path)
        except Exception as e:
            logging.error("Error while navigating directories: %s", str(e))
            messagebox.showerror("Error", str(e))

    def go_to_root(self):
        try:
            self.list_files(".")
        except Exception as e:
            logging.error("Error while returning to root directory: %s", str(e))

    def display_metadata(self, event):
        try:
            selected_file = self.file_listbox.get(self.file_listbox.curselection())
            if selected_file.startswith("[DIR]"):
                return

            local_file = f"/tmp/{selected_file}"
            self.sftp.get(selected_file, local_file)

            audio = File(local_file)
            self.metadata_text.delete(1.0, tk.END)
            if audio:
                for key, value in audio.items():
                    self.metadata_text.insert(tk.END, f"{key}: {value}\n")
            else:
                self.metadata_text.insert(tk.END, "No metadata available.")

            os.remove(local_file)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def delete_file(self):
        try:
            selected_index = self.file_listbox.curselection()
            if not selected_index:
                messagebox.showerror("Error", "No file selected.")
                return

            selected_file = self.file_listbox.get(selected_index)
            full_path = self.file_paths[selected_index[0] - 1]  # Adjust for [PARENT DIR] ..

            if selected_file.startswith("[DIR]"):
                messagebox.showerror("Error", "Cannot delete a directory.")
                return

            self.sftp.remove(full_path)
            logging.info("Deleted: %s", full_path)  # Log the deleted file
            messagebox.showinfo("Success", f"Deleted {full_path} successfully!")
            self.list_files(self.current_path)
        except Exception as e:
            logging.error("Error while deleting file: %s", str(e))
            messagebox.showerror("Error", str(e))

    def go_to_parent_directory(self):
        try:
            if self.current_path and self.current_path != ".":
                self.current_path = os.path.dirname(self.current_path)
                self.list_files(self.current_path)
            else:
                messagebox.showinfo("Info", "Already at the root directory.")
        except Exception as e:
            logging.error("Error while navigating to parent directory: %s", str(e))

    def load_server_details(self):
        if os.path.exists(self.server_details_file):
            try:
                with open(self.server_details_file, "rb") as file:
                    encrypted_data = file.read()
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                server_details = json.loads(decrypted_data)

                self.server_ip = server_details["server_ip"]
                self.server_port = int(server_details["server_port"])
                self.username = server_details["username"]
                self.password = server_details["password"]

                logging.info("Server details loaded successfully on startup.")
            except Exception as e:
                logging.error("Failed to load server details: %s", str(e))
                messagebox.showerror("Error", "Failed to load server details.")

    def auto_login(self):
        if os.path.exists(self.server_details_file):
            try:
                with open(self.server_details_file, "rb") as file:
                    encrypted_data = file.read()
                decrypted_data = self.fernet.decrypt(encrypted_data).decode()
                server_details = json.loads(decrypted_data)

                self.server_ip = server_details["server_ip"]
                self.server_port = int(server_details["server_port"])
                self.username = server_details["username"]
                self.password = server_details["password"]

                logging.info("Server details loaded successfully. Attempting auto-login.")
                self.connect_to_server()
            except Exception as e:
                logging.error("Auto-login failed: %s", str(e))
                messagebox.showerror("Error", "Auto-login failed. Please configure the server manually.")

# Load server details on startup
if __name__ == "__main__":
    root = tk.Tk()
    app = FileManagerApp(root)
    app.auto_login()
    root.mainloop()