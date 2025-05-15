# Image Steganography 🔐
A Python application that allows hiding secret messages within images using steganography techniques.

## What is Image Steganography?
Steganography is the art and science of hiding information within other information, making it appear as if nothing is hidden. Image steganography specifically refers to the technique of concealing data within digital images. Unlike encryption, which makes data unreadable, steganography hides the very existence of the data.

### How Image Steganography Works
Digital images consist of pixels, and each pixel contains color values (typically RGB - Red, Green, Blue). We can embed secret information by making subtle, imperceptible changes to these values. The most common technique is the Least Significant Bit (LSB) method, where we modify the last bit of color values to store our hidden data.

### Applications and Use Cases
1. **Cybersecurity and Privacy**
   - Secure communication in sensitive environments
   - Whistleblower protection
   - Private data transmission in restricted regions
   - Digital watermarking for copyright protection

2. **Military and Intelligence**
   - Covert communication
   - Secret data sharing between allies
   - Battlefield communications
   - Agent-handler secure messaging

3. **Digital Forensics**
   - Hidden watermarks for authenticity verification
   - Tracking source of leaked documents
   - Evidence preservation
   - Chain of custody documentation

4. **Medical Field**
   - Embedding patient information in medical images
   - Protecting sensitive health records
   - Secure sharing of medical data
   - HIPAA compliance support

### Advantages of Image Steganography
- Provides security through obscurity
- No apparent evidence of hidden communication
- Can bypass communication restrictions
- Maintains visual quality of the carrier image
- Complements existing encryption methods

### Ethical Considerations
This tool is designed for educational purposes and legitimate privacy protection. Users should comply with applicable privacy laws and regulations, respecting individual rights and data protection guidelines.

## Features
- Support for multiple image formats (PNG, JPG, JPEG, BMP, GIF, TIFF)
- Real-time image preview
- Progress bar for encoding process
- Modern and intuitive user interface
- Error handling and input validation
- Message length validation
- Automatic image format conversion

## Requirements

```
Python 3.x
Pillow (PIL)
tkinter (usually comes with Python)
cryptography
numpy
tqdm
```

### Installation
1. Clone the repository
```bash
git clone https://github.com/ruinedpov/Steganography.git
cd Steganography
```

2. Install required packages
```bash
pip install -r requirements.txt
```

### Usage
1. Run the application:
```bash
python img_steganography.py
```
2. To encode a message:
   - Click "Select Image" and choose an image file
   - Enter your secret message in the text box
   - Click "Encode" and choose where to save the new image
   - The encoded image will be saved as a PNG file

3. To decode a message:
   - Click "Select Image to Decode" and choose an encoded image
   - The hidden message will be displayed in the text box (if present)

## How it Works
The application uses the Least Significant Bit (LSB) steganography technique:
- Each character in the secret message is converted to its binary representation
- The least significant bit of the red channel of each pixel is modified to store the message
- A special end marker is used to identify where the message ends
- The modified image looks virtually identical to the original

## Limitations
- The length of the message that can be hidden depends on the image size
- The encoded image is always saved as PNG to prevent data loss
- Some image formats may be automatically converted to ensure compatibility

## Security Considerations 🔒
- This implementation includes basic security features
- Suitable for educational and personal use
- Consider additional encryption for sensitive data
- Always follow best practices for data protection

## License 📝
This project is protected under the GNU General Public License v3.0 (GPLv3) with additional usage restrictions - see the [LICENSE](LICENSE) file for details.
```
License Terms:
- ❌ You CANNOT modify and distribute this software
- ✔️ You CAN use this software for educational purposes
- ❗ You MUST keep the source code as is
- ❗ You MUST include the original license
- ❗ You MUST NOT make any changes
- ❗ You MUST NOT redistribute the software
- ❗ You MUST include copyright notice

Usage Restrictions:
This software CANNOT be used for:
- ❌ Any modification or redistribution of the code
- ❌ Any military or defense purposes
- ❌ Any governmental surveillance activities
- ❌ Any malicious or harmful activities
- ❌ Any illegal activities or purposes
- ❌ Commercial use without explicit permission
- ❌ Any activities that could harm individual privacy
- ❌ Distribution without including these restrictions

Additional Terms:
1. The software must be used exactly as provided
2. Usage in academic research requires proper citation
3. The software may not be included in any other product
4. No modifications are allowed
```
This strict license ensures that the software remains under the control of the original author while preventing any unauthorized modifications or distributions.
