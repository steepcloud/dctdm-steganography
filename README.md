# DCTDM Steganography

**Hide encrypted messages in JPEG images using DCT Difference Modulation**

A Python-based steganography tool that embeds secret messages into JPEG images by modulating differences between adjacent DCT (Discrete Cosine Transform) coefficients in the frequency domain. Features AES-256 encryption, custom JPEG encoding/decoding, and a user-friendly PyQt6 GUI.

## Features

- **DCT Difference Modulation**: Embeds 2 bits per coefficient pair by manipulating DCT coefficient differences
- **AES-256 Encryption**: Optional password-protected message encryption using Fernet (PBKDF2-HMAC-SHA256)
- **Direct JPEG Extraction**: No intermediate `.dct` files required - extract directly from stego JPEG
- **Custom JPEG Codec**: Preserves exact DCT coefficients without requantization that destroys hidden data
- **PyQt6 GUI**: Clean interface with tabs for embedding, extraction, analysis, and documentation
- **High Imperceptibility**: PSNR > 40 dB - visually identical to original images
- **Configurable Robustness**: Adjustable delta (δ) parameter for imperceptibility vs. robustness trade-off

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/steepcloud/dctdm-steganography.git
cd dctdm-steganography
```

### GUI Mode

```bash
python DCTDM_GUI.py
```

### Command Line

```bash
# Embed message
python DCTDM.py --stego

# Follow interactive prompts for:
# - Input image path
# - Secret message
# - Encryption password (optional)
# - Delta value (default: 10)
# - Output filename
```

## How It Works

### 1. **DCTDM Algorithm** (DCTDM.py)

The core steganography engine operates in the JPEG frequency domain:

1. **Decode JPEG**: Extract DCT coefficients from 8×8 blocks
2. **Coefficient Selection**: Target AC coefficients in luminance (Y) channel
3. **Difference Modulation**: For adjacent coefficients AC₁ and AC₂:
   - Calculate difference: D = AC₁ - AC₂
   - Quantize to embedding regions based on delta (δ)
   - Embed 2 bits by setting D to ε₁ or ε₂ (positive/negative)
4. **Encode JPEG**: Reconstruct JPEG with modified coefficients

**Mathematical Foundation:**
```
ε₁ = k·δ + δ/4
ε₂ = k·δ + 3δ/4

Embedding:
- (0,0) → D = +ε₁
- (0,1) → D = +ε₂
- (1,0) → D = -ε₂
- (1,1) → D = -ε₁
```

### 2. **Custom JPEG Encoder** (jpeg_encoder.py)

Standard JPEG libraries (PIL, OpenCV) requantize coefficients during save operations, destroying embedded data. Our encoder:

- Reconstructs Huffman tables from decoder trees
- Performs differential DC encoding
- Implements proper zigzag ordering and run-length encoding
- Preserves exact DCT values for perfect extraction

### 3. **GUI Application** (DCTDM_GUI.py)

PyQt6-based interface with four tabs:

- **Hide Message**: Embed text with optional encryption
- **Reveal Message**: Extract and decrypt hidden messages
- **Analyze Detection**: Compare original vs stego with PSNR/MSE metrics
- **About DCTDM**: Technical documentation and algorithm details

## Technical Details

### Architecture

```
DCTDM.py
├── JPEG class: Complete baseline JPEG decoder
│   ├── Huffman decoding (DHT marker support)
│   ├── Quantization table parsing (DQT)
│   ├── DCT coefficient extraction
│   └── IDCT (Chen-Wang algorithm)
├── DCTDM class: Steganography engine
│   ├── embed_message(): Hide text in DCT domain
│   ├── extract_message(): Recover hidden text
│   ├── _encrypt_message(): AES-256 encryption
│   └── _decrypt_message(): Fernet decryption
└── Helper classes: Stream (bitstream), HuffmanTable

jpeg_encoder.py
└── JPEGEncoder class: Lossless DCT preservation
    ├── Huffman table reconstruction
    ├── Coefficient quantization
    ├── Bit stuffing (0xFF → 0xFF00)
    └── Marker writing (SOI, DQT, DHT, SOF0, SOS, EOI)

DCTDM_GUI.py
└── DCTDMApp: PyQt6 main window
    ├── WorkerThread: Background processing
    ├── Embed tab: Message hiding interface
    ├── Extract tab: Message recovery interface
    └── Analysis tab: Image quality metrics
```

### Key Innovations

1. **No File Dependencies**: Direct JPEG-to-JPEG embedding/extraction
2. **Auto-Baseline Conversion**: Handles progressive/optimized JPEGs automatically
3. **Encryption Layer**: Secure messages with industry-standard AES-256
4. **Optimized Bitstream**: 3-5× faster Huffman decoding with bitwise operations

## Performance

| Metric | Value |
|--------|-------|
| **PSNR** | > 40 dB (excellent imperceptibility) |
| **Capacity** | ~2 bits per AC coefficient pair |
| **Encoding Speed** | ~0.5s for 640×480 image |
| **Detection Resistance** | Statistical analysis required (not visually detectable) |

## Security

- **Encryption**: AES-256-CBC via Fernet
- **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
- **Random Salt**: 16-byte unique salt per message
- **Metadata**: Separate `.meta` file indicates encryption status

## Requirements

```
Python 3.11+
PyQt6 >= 6.4.0
Pillow >= 9.0.0
NumPy >= 1.23.0
cryptography >= 41.0.0
```

## Use Cases

- Covert communication in images
- Copyright watermarking research
- Digital forensics studies
- Steganography education
- Security testing

## Limitations

- **JPEG-only**: Does not support PNG, BMP, or other formats
- **Baseline DCT**: Progressive/arithmetic-coded JPEGs require conversion
- **No Robustness**: Not resistant to image modifications (cropping, rotation, recompression)
- **Capacity**: Limited by image dimensions (≈ width×height÷32 characters)

## Contributing

Contributions welcome! Areas for improvement:

- Support for adaptive delta selection
- Multi-channel embedding (Cb/Cr)
- Steganalysis resistance enhancements
- Compression robustness features

## References

- Chen-Wang IDCT Algorithm
- JPEG Standard (ITU-T T.81)
- Fernet Specification (Cryptographic Message Syntax)
- DCT-based Steganography Research
