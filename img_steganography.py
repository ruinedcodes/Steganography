import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
from pathlib import Path
import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import hashlib
from tqdm import tqdm

class AdvancedSteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Image Steganography")
        self.root.geometry("1000x800")
        
        # Initialize variables
        self.selected_file = None
        self.preview_size = (250, 250)
        self.supported_formats = [("All Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.tiff"),
                                ("PNG Files", "*.png"),
                                ("JPEG Files", "*.jpg;*.jpeg"),
                                ("BMP Files", "*.bmp"),
                                ("TIFF Files", "*.tiff")]
        
        # Create encryption key
        self.salt = os.urandom(16)
        self.setup_ui()

    def setup_ui(self):
        # Main frame with notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)

        # Create tabs
        self.encode_frame = ttk.Frame(self.notebook)
        self.decode_frame = ttk.Frame(self.notebook)
        self.analysis_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.encode_frame, text='Encode')
        self.notebook.add(self.decode_frame, text='Decode')
        self.notebook.add(self.analysis_frame, text='Analysis')

        self.setup_encode_frame()
        self.setup_decode_frame()
        self.setup_analysis_frame()

    def setup_encode_frame(self):
        # Left side - Image selection and preview
        left_frame = ttk.LabelFrame(self.encode_frame, text="Source Image", padding="10")
        left_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")

        ttk.Button(left_frame, text="Select Source Image", command=self.browse_file).pack(pady=5)
        self.file_label = ttk.Label(left_frame, text="No source image selected", wraplength=200)
        self.file_label.pack(pady=5)

        self.original_preview = ttk.Label(left_frame)
        self.original_preview.pack(pady=5)

        # Right side - Encoding options
        right_frame = ttk.LabelFrame(self.encode_frame, text="Encoding Options", padding="10")
        right_frame.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

        # Data type selection
        ttk.Label(right_frame, text="Data Type:").pack(pady=5)
        self.data_type = tk.StringVar(value="text")
        ttk.Radiobutton(right_frame, text="Text Message", variable=self.data_type, 
                       value="text", command=self.toggle_data_input).pack()
        ttk.Radiobutton(right_frame, text="File", variable=self.data_type, 
                       value="file", command=self.toggle_data_input).pack()

        # Text input
        self.text_frame = ttk.Frame(right_frame)
        self.text_frame.pack(pady=5, fill='x')
        ttk.Label(self.text_frame, text="Enter Message:").pack()
        self.message_text = tk.Text(self.text_frame, height=5, width=30)
        self.message_text.pack(pady=5)

        # File input
        self.file_frame = ttk.Frame(right_frame)
        ttk.Button(self.file_frame, text="Select File to Hide", 
                  command=self.select_hide_file).pack(pady=5)
        self.hide_file_label = ttk.Label(self.file_frame, text="No file selected", 
                                       wraplength=200)
        self.hide_file_label.pack(pady=5)

        # Encryption options
        enc_frame = ttk.LabelFrame(right_frame, text="Encryption", padding="5")
        enc_frame.pack(pady=5, fill='x')
        
        ttk.Label(enc_frame, text="Password (optional):").pack()
        self.password_entry = ttk.Entry(enc_frame, show="*")
        self.password_entry.pack(pady=5)

        # Channel selection
        channel_frame = ttk.LabelFrame(right_frame, text="Channels", padding="5")
        channel_frame.pack(pady=5, fill='x')
        
        self.use_red = tk.BooleanVar(value=True)
        self.use_green = tk.BooleanVar(value=False)
        self.use_blue = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(channel_frame, text="Red", variable=self.use_red).pack()
        ttk.Checkbutton(channel_frame, text="Green", variable=self.use_green).pack()
        ttk.Checkbutton(channel_frame, text="Blue", variable=self.use_blue).pack()

        # Progress
        self.encode_progress = ttk.Progressbar(right_frame, length=200, mode='determinate')
        self.encode_progress.pack(pady=5)
        
        self.status_label = ttk.Label(right_frame, text="Ready", wraplength=200)
        self.status_label.pack(pady=5)

        # Encode button
        ttk.Button(right_frame, text="Encode and Save", 
                  command=self.encode_message).pack(pady=10)

        # Initially hide file frame
        self.file_frame.pack_forget()

    def setup_decode_frame(self):
        # Left side - Image selection and preview
        left_frame = ttk.LabelFrame(self.decode_frame, text="Stego Image", padding="10")
        left_frame.grid(row=0, column=0, padx=10, pady=5, sticky="nsew")

        ttk.Button(left_frame, text="Select Image to Decode", 
                  command=self.select_decode_image).pack(pady=5)
        
        self.stego_preview = ttk.Label(left_frame)
        self.stego_preview.pack(pady=5)

        # Right side - Decoding options and output
        right_frame = ttk.LabelFrame(self.decode_frame, text="Decoding Options", padding="10")
        right_frame.grid(row=0, column=1, padx=10, pady=5, sticky="nsew")

        # Password entry
        ttk.Label(right_frame, text="Password (if encrypted):").pack()
        self.decode_password_entry = ttk.Entry(right_frame, show="*")
        self.decode_password_entry.pack(pady=5)

        # Channel selection for decoding
        channel_frame = ttk.LabelFrame(right_frame, text="Channels to Check", padding="5")
        channel_frame.pack(pady=5, fill='x')
        
        self.decode_red = tk.BooleanVar(value=True)
        self.decode_green = tk.BooleanVar(value=False)
        self.decode_blue = tk.BooleanVar(value=False)
        
        ttk.Checkbutton(channel_frame, text="Red", variable=self.decode_red).pack()
        ttk.Checkbutton(channel_frame, text="Green", variable=self.decode_green).pack()
        ttk.Checkbutton(channel_frame, text="Blue", variable=self.decode_blue).pack()

        # Decode button
        ttk.Button(right_frame, text="Decode", command=self.decode_message).pack(pady=10)

        # Output
        output_frame = ttk.LabelFrame(right_frame, text="Decoded Output", padding="5")
        output_frame.pack(pady=5, fill='both', expand=True)

        self.decoded_text = tk.Text(output_frame, height=10, width=40, state='disabled')
        self.decoded_text.pack(pady=5, fill='both', expand=True)

        # Save button for decoded file
        self.save_decoded_button = ttk.Button(right_frame, text="Save Decoded File",
                                            command=self.save_decoded_file)
        self.save_decoded_button.pack(pady=5)
        self.save_decoded_button.pack_forget()  # Initially hidden

    def setup_analysis_frame(self):
        # Image analysis tools
        analysis_tools = ttk.LabelFrame(self.analysis_frame, text="Image Analysis", padding="10")
        analysis_tools.pack(fill='both', expand=True, padx=10, pady=5)

        # Capacity calculator
        cap_frame = ttk.LabelFrame(analysis_tools, text="Capacity Calculator", padding="5")
        cap_frame.pack(pady=5, fill='x')

        ttk.Label(cap_frame, text="Maximum data capacity:").pack()
        self.capacity_label = ttk.Label(cap_frame, text="No image selected")
        self.capacity_label.pack(pady=5)

        # Image comparison
        comp_frame = ttk.LabelFrame(analysis_tools, text="Image Comparison", padding="5")
        comp_frame.pack(pady=5, fill='x')

        ttk.Label(comp_frame, text="Image Statistics:").pack()
        self.stats_text = tk.Text(comp_frame, height=6, width=40, state='disabled')
        self.stats_text.pack(pady=5)

    def toggle_data_input(self):
        if self.data_type.get() == "text":
            self.file_frame.pack_forget()
            self.text_frame.pack(pady=5, fill='x')
        else:
            self.text_frame.pack_forget()
            self.file_frame.pack(pady=5, fill='x')

    def browse_file(self):
        self.selected_file = filedialog.askopenfilename(filetypes=self.supported_formats)
        if self.selected_file:
            self.file_label.config(text=f"Selected: {Path(self.selected_file).name}")
            self.show_preview(self.selected_file, self.original_preview)
            self.calculate_capacity()

    def show_preview(self, image_path, label):
        try:
            image = Image.open(image_path)
            image.thumbnail(self.preview_size)
            photo = ImageTk.PhotoImage(image)
            label.config(image=photo)
            label.image = photo
        except Exception as e:
            messagebox.showerror("Preview Error", f"Could not load image preview: {str(e)}")

    def calculate_capacity(self):
        try:
            if self.selected_file:
                img = Image.open(self.selected_file)
                width, height = img.size
                channels = sum([self.use_red.get(), self.use_green.get(), self.use_blue.get()])
                total_bits = width * height * channels
                bytes_capacity = total_bits // 8
                
                self.capacity_label.config(
                    text=f"Maximum capacity:\n{bytes_capacity:,} bytes\n"
                         f"({bytes_capacity/1024:.2f} KB)\n"
                         f"Using {channels} color channel(s)")
                
                # Update statistics
                self.update_image_stats(img)
        except Exception as e:
            self.capacity_label.config(text=f"Error calculating capacity: {str(e)}")

    def update_image_stats(self, img):
        try:
            # Convert image to numpy array for analysis
            img_array = np.array(img)
            
            stats = f"Image Size: {img.size[0]}x{img.size[1]}\n"
            stats += f"Color Mode: {img.mode}\n"
            
            if len(img_array.shape) >= 3:
                stats += "\nChannel Statistics:\n"
                for i, channel in enumerate(['Red', 'Green', 'Blue']):
                    stats += f"{channel}: Mean={img_array[...,i].mean():.2f}, "
                    stats += f"Std={img_array[...,i].std():.2f}\n"
            
            self.stats_text.config(state='normal')
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, stats)
            self.stats_text.config(state='disabled')
        except Exception as e:
            self.stats_text.config(state='normal')
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(tk.END, f"Error calculating statistics: {str(e)}")
            self.stats_text.config(state='disabled')

    def get_encryption_key(self, password):
        if not password:
            return None
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encode_data(self, data, channels):
        # Convert data to binary string
        binary_data = ''.join(format(b, '08b') for b in data)
        
        # Add end marker
        binary_data += '1111111111111110'
        
        return binary_data

    def encode_to_channels(self, img, binary_data):
        pixels = list(img.getdata())
        width, height = img.size
        
        # Determine which channels to use
        channels = []
        if self.use_red.get(): channels.append(0)
        if self.use_green.get(): channels.append(1)
        if self.use_blue.get(): channels.append(2)
        
        if not channels:
            raise ValueError("At least one color channel must be selected")

        # Calculate capacity
        total_capacity = width * height * len(channels)
        if len(binary_data) > total_capacity:
            raise ValueError(f"Data too large for image capacity. Maximum: {total_capacity//8} bytes")

        # Encode data
        new_pixels = []
        data_index = 0
        
        for pixel in tqdm(pixels, desc="Encoding", unit="pixels"):
            r, g, b, a = pixel
            
            if data_index < len(binary_data):
                if 0 in channels and data_index < len(binary_data):
                    r = (r & ~1) | int(binary_data[data_index])
                    data_index += 1
                if 1 in channels and data_index < len(binary_data):
                    g = (g & ~1) | int(binary_data[data_index])
                    data_index += 1
                if 2 in channels and data_index < len(binary_data):
                    b = (b & ~1) | int(binary_data[data_index])
                    data_index += 1
                    
            new_pixels.append((r, g, b, a))

        return new_pixels

    def encode_message(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a source image first")
            return

        try:
            # Get data to hide
            if self.data_type.get() == "text":
                message = self.message_text.get("1.0", tk.END).strip()
                if not message:
                    messagebox.showerror("Error", "Please enter a message to encode")
                    return
                data = message.encode()
                is_file = False
            else:
                if not hasattr(self, 'hide_file_path'):
                    messagebox.showerror("Error", "Please select a file to hide")
                    return
                with open(self.hide_file_path, 'rb') as f:
                    data = f.read()
                is_file = True

            # Prepare metadata
            metadata = {
                "is_file": is_file,
                "filename": Path(self.hide_file_path).name if is_file else None,
                "salt": base64.b64encode(self.salt).decode()
            }
            
            # Convert metadata to bytes and prepare final data
            metadata_bytes = json.dumps(metadata).encode()
            final_data = len(metadata_bytes).to_bytes(4, 'big') + metadata_bytes + data

            # Encrypt if password provided
            password = self.password_entry.get()
            if password:
                f = self.get_encryption_key(password)
                final_data = f.encrypt(final_data)

            # Convert to binary
            binary_data = self.encode_data(final_data, [])

            # Open and prepare image
            img = Image.open(self.selected_file)
            if img.mode != 'RGBA':
                img = img.convert('RGBA')

            # Encode data
            new_pixels = self.encode_to_channels(img, binary_data)

            # Save encoded image
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Files", "*.png")],
                title="Save Encoded Image As",
                initialfile="encoded_image.png"
            )
            
            if not save_path:
                return

            # Create new image with encoded data
            new_img = Image.new('RGBA', img.size)
            new_img.putdata(new_pixels)
            new_img.save(save_path, 'PNG')

            self.show_preview(save_path, self.stego_preview)
            messagebox.showinfo("Success", "Data encoded successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode_message(self):
        try:
            if not hasattr(self, 'decode_file_path'):
                messagebox.showerror("Error", "Please select an image to decode")
                return

            # Open image
            img = Image.open(self.decode_file_path)
            if img.mode != 'RGBA':
                img = img.convert('RGBA')

            # Get channels to check
            channels = []
            if self.decode_red.get(): channels.append(0)
            if self.decode_green.get(): channels.append(1)
            if self.decode_blue.get(): channels.append(2)

            if not channels:
                messagebox.showerror("Error", "Please select at least one channel to check")
                return

            # Extract binary data
            binary_message = ""
            pixels = list(img.getdata())
            
            for pixel in tqdm(pixels, desc="Extracting data", unit="pixels"):
                r, g, b, a = pixel
                if 0 in channels: binary_message += str(r & 1)
                if 1 in channels: binary_message += str(g & 1)
                if 2 in channels: binary_message += str(b & 1)

            # Find end marker
            end_marker = "1111111111111110"
            if end_marker in binary_message:
                binary_message = binary_message.split(end_marker)[0]
            else:
                raise ValueError("No hidden data found or invalid format")

            # Convert binary to bytes
            data_bytes = bytearray()
            for i in range(0, len(binary_message), 8):
                byte = binary_message[i:i+8]
                if len(byte) == 8:
                    data_bytes.append(int(byte, 2))

            # Try to decrypt if password provided
            password = self.decode_password_entry.get()
            if password:
                try:
                    f = self.get_encryption_key(password)
                    data_bytes = f.decrypt(bytes(data_bytes))
                except Exception as e:
                    raise ValueError("Invalid password or data not encrypted")

            # Extract metadata
            metadata_length = int.from_bytes(data_bytes[:4], 'big')
            metadata = json.loads(data_bytes[4:4+metadata_length].decode())
            actual_data = data_bytes[4+metadata_length:]

            # Handle the data based on metadata
            if metadata["is_file"]:
                self.decoded_file_data = actual_data
                self.decoded_filename = metadata["filename"]
                self.save_decoded_button.pack()
                
                self.decoded_text.config(state='normal')
                self.decoded_text.delete(1.0, tk.END)
                self.decoded_text.insert(tk.END, 
                    f"Found hidden file: {self.decoded_filename}\n"
                    f"Size: {len(actual_data):,} bytes\n"
                    f"Click 'Save Decoded File' to save it.")
                self.decoded_text.config(state='disabled')
            else:
                self.save_decoded_button.pack_forget()
                self.decoded_text.config(state='normal')
                self.decoded_text.delete(1.0, tk.END)
                self.decoded_text.insert(tk.END, actual_data.decode())
                self.decoded_text.config(state='disabled')

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def select_hide_file(self):
        self.hide_file_path = filedialog.askopenfilename(title="Select File to Hide")
        if self.hide_file_path:
            self.hide_file_label.config(text=f"Selected: {Path(self.hide_file_path).name}")

    def select_decode_image(self):
        self.decode_file_path = filedialog.askopenfilename(
            filetypes=self.supported_formats,
            title="Select Image to Decode"
        )
        if self.decode_file_path:
            self.show_preview(self.decode_file_path, self.stego_preview)

    def save_decoded_file(self):
        if hasattr(self, 'decoded_file_data') and hasattr(self, 'decoded_filename'):
            save_path = filedialog.asksaveasfilename(
                initialfile=self.decoded_filename,
                title="Save Decoded File As"
            )
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(self.decoded_file_data)
                messagebox.showinfo("Success", "File saved successfully!")

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedSteganographyApp(root)
    root.mainloop() 