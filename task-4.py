import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import base64

class FileEncryptor:
    def __init__(self):
        self.backend = default_backend()
        self.salt = b'salt_1234'  # In production, generate random salt per file

    def _get_key(self, password, salt=None):
        """Derive a 256-bit key from the password using PBKDF2"""
        salt = salt or self.salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_file(self, input_file, output_file, password):
        """Encrypt a file using AES-256-CBC"""
        try:
            # Generate key from password
            key = self._get_key(password)
            
            # Generate random IV
            iv = os.urandom(16)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Create padder
            padder = padding.PKCS7(128).padder()
            
            with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
                # Write salt and IV to output file
                f_out.write(b'Salted__')
                f_out.write(self.salt)
                f_out.write(iv)
                
                # Encrypt file in chunks
                while True:
                    chunk = f_in.read(64 * 1024)  # 64KB chunks
                    if not chunk:
                        break
                    padded_data = padder.update(chunk)
                    encrypted_chunk = encryptor.update(padded_data)
                    f_out.write(encrypted_chunk)
                
                # Finalize encryption and padding
                final_padded = padder.finalize()
                final_encrypted = encryptor.update(final_padded) + encryptor.finalize()
                f_out.write(final_encrypted)
            
            return True
        except Exception as e:
            print(f"Encryption failed: {e}")
            return False

    def decrypt_file(self, input_file, output_file, password):
        """Decrypt a file encrypted with AES-256-CBC"""
        try:
            with open(input_file, 'rb') as f_in:
                # Read salt and IV from input file
                header = f_in.read(8)  # 'Salted__'
                if header != b'Salted__':
                    raise ValueError("Not a valid encrypted file")
                
                salt = f_in.read(8)
                iv = f_in.read(16)
                
                # Generate key from password and salt
                key = self._get_key(password, salt)
                
                # Create cipher
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=self.backend
                )
                decryptor = cipher.decryptor()
                
                # Create unpadder
                unpadder = padding.PKCS7(128).unpadder()
                
                with open(output_file, 'wb') as f_out:
                    # Decrypt file in chunks
                    while True:
                        chunk = f_in.read(64 * 1024)  # 64KB chunks
                        if not chunk:
                            break
                        decrypted_chunk = decryptor.update(chunk)
                        unpadded_data = unpadder.update(decrypted_chunk)
                        f_out.write(unpadded_data)
                    
                    # Finalize decryption and unpadding
                    final_decrypted = decryptor.finalize()
                    final_unpadded = unpadder.update(final_decrypted) + unpadder.finalize()
                    f_out.write(final_unpadded)
            
            return True
        except Exception as e:
            print(f"Decryption failed: {e}")
            return False

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced File Encryption Tool (AES-256)")
        self.encryptor = FileEncryptor()
        
        # Configure window
        self.root.geometry("500x300")
        self.root.resizable(False, False)
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Mode selection
        self.mode_var = tk.StringVar(value="encrypt")
        ttk.Label(self.main_frame, text="Select Operation:").grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(self.main_frame, text="Encrypt", variable=self.mode_var, value="encrypt").grid(row=1, column=0, sticky=tk.W)
        ttk.Radiobutton(self.main_frame, text="Decrypt", variable=self.mode_var, value="decrypt").grid(row=1, column=1, sticky=tk.W)
        
        # File selection
        ttk.Label(self.main_frame, text="Input File:").grid(row=2, column=0, sticky=tk.W, pady=(10,0))
        self.input_file_var = tk.StringVar()
        self.input_file_entry = ttk.Entry(self.main_frame, textvariable=self.input_file_var, width=40)
        self.input_file_entry.grid(row=3, column=0, columnspan=2, sticky=tk.W)
        ttk.Button(self.main_frame, text="Browse...", command=self.browse_input_file).grid(row=3, column=2, padx=(5,0))
        
        # Output file
        ttk.Label(self.main_frame, text="Output File:").grid(row=4, column=0, sticky=tk.W, pady=(10,0))
        self.output_file_var = tk.StringVar()
        self.output_file_entry = ttk.Entry(self.main_frame, textvariable=self.output_file_var, width=40)
        self.output_file_entry.grid(row=5, column=0, columnspan=2, sticky=tk.W)
        ttk.Button(self.main_frame, text="Browse...", command=self.browse_output_file).grid(row=5, column=2, padx=(5,0))
        
        # Password
        ttk.Label(self.main_frame, text="Password:").grid(row=6, column=0, sticky=tk.W, pady=(10,0))
        self.password_entry = ttk.Entry(self.main_frame, show="*", width=40)
        self.password_entry.grid(row=7, column=0, columnspan=2, sticky=tk.W)
        
        # Execute button
        self.execute_button = ttk.Button(self.main_frame, text="Execute", command=self.execute_operation)
        self.execute_button.grid(row=8, column=0, pady=(20,0))
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(self.main_frame, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.grid(row=9, column=0, columnspan=3, sticky=tk.EW, pady=(20,0))
        
    def browse_input_file(self):
        filetypes = [("All files", "*.*")]
        filename = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if filename:
            self.input_file_var.set(filename)
            if not self.output_file_var.get():
                base, ext = os.path.splitext(filename)
                if self.mode_var.get() == "encrypt":
                    self.output_file_var.set(f"{base}.enc")
                else:
                    self.output_file_var.set(f"{base}.decrypted{ext}")

    def browse_output_file(self):
        initial_file = self.output_file_var.get() or "output"
        filetypes = [("All files", "*.*")]
        filename = filedialog.asksaveasfilename(
            title="Select output file",
            initialfile=initial_file,
            filetypes=filetypes
        )
        if filename:
            self.output_file_var.set(filename)

    def execute_operation(self):
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        password = self.password_entry.get()
        
        if not input_file or not output_file or not password:
            messagebox.showerror("Error", "All fields are required")
            return
        
        try:
            if self.mode_var.get() == "encrypt":
                self.status_var.set("Encrypting...")
                self.root.update()
                success = self.encryptor.encrypt_file(input_file, output_file, password)
                if success:
                    messagebox.showinfo("Success", "File encrypted successfully")
                    self.status_var.set("Ready - File encrypted")
                else:
                    messagebox.showerror("Error", "Encryption failed")
                    self.status_var.set("Error - Encryption failed")
            else:
                self.status_var.set("Decrypting...")
                self.root.update()
                success = self.encryptor.decrypt_file(input_file, output_file, password)
                if success:
                    messagebox.showinfo("Success", "File decrypted successfully")
                    self.status_var.set("Ready - File decrypted")
                else:
                    messagebox.showerror("Error", "Decryption failed - Wrong password or corrupt file?")
                    self.status_var.set("Error - Decryption failed")
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")
            self.status_var.set(f"Error - {str(e)}")

def command_line_interface():
    parser = argparse.ArgumentParser(description="Advanced File Encryption Tool (AES-256)")
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input_file', help='Input file to encrypt')
    encrypt_parser.add_argument('output_file', help='Output encrypted file')
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input_file', help='Input file to decrypt')
    decrypt_parser.add_argument('output_file', help='Output decrypted file')
    
    args = parser.parse_args()
    
    encryptor = FileEncryptor()
    password = getpass.getpass("Enter password: ")
    
    if args.command == 'encrypt':
        if encryptor.encrypt_file(args.input_file, args.output_file, password):
            print("File encrypted successfully")
        else:
            print("Encryption failed")
    elif args.command == 'decrypt':
        if encryptor.decrypt_file(args.input_file, args.output_file, password):
            print("File decrypted successfully")
        else:
            print("Decryption failed - Wrong password or corrupt file?")

if __name__ == "__main__":
    # Check if running in command line mode
    if len(sys.argv) > 1:
        command_line_interface()
    else:
        # Launch GUI
        root = tk.Tk()
        app = EncryptionApp(root)
        root.mainloop()