"""
DCTDM (DCT Difference Modulation) Steganography Module

This module implements steganography in JPEG images by modulating differences 
between adjacent DCT coefficients in the frequency domain. It includes support 
for AES-256 encryption, custom JPEG encoding/decoding, and direct extraction 
from JPEG files without requiring intermediate .dct files.

Classes:
    IDCT: Inverse Discrete Cosine Transform implementation
    Stream: Bitstream reader for Huffman decoding
    HuffmanTable: Huffman tree builder and decoder
    JPEG: Complete JPEG decoder with DCT extraction
    DCTDM: Main steganography interface with encryption support
    JPEGThread: Threading wrapper for JPEG decoding
"""

import os
from struct import unpack
from tkinter import Tk, Canvas, mainloop
from PIL import Image
from jpeg_encoder import JPEGEncoder
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import numpy as np
import pickle
import math
import copy
import threading
import base64

MCU = 8  # Minimum Coded Unit (8x8 blocks)
marker_dict = {
    0xFFC0: "Start of Frame 0",  # Baseline DCT
    0xFFC1: "Start of Frame 1",  # Extended Sequential DCT
    0xFFC2: "Start of Frame 2",  # Progressive DCT
    0xFFC3: "Start of Frame 3",  # Lossless (sequential)
    0xFFC4: "Define Huffman Table",
    0xFFC5: "Start of Frame 5",  # Differential sequential DCT
    0xFFC6: "Start of Frame 6",  # Differential progressive DCT
    0xFFC7: "Start of Frame 7",  # Differential lossless (sequential)
    0xFFC8: "JPEG Extensions",
    0xFFC9: "Start of Frame 9",  # Extended sequential DCT, Arithmetic coding
    0xFFCA: "Start of Frame 10",  # Progressive DCT, Arithmetic coding
    0xFFCB: "Start of Frame 11",  # Lossless (sequential), Arithmetic coding
    0xFFCC: "Define Arithmetic Coding",
    0xFFCD: "Start of Frame 13",  # Differential sequential DCT, Arithmetic coding
    0xFFCE: "Start of Frame 14",  # Differential progressive DCT, Arithmetic coding
    0xFFCF: "Start of Frame 15",  # Differential lossless(sequential), Arithmetic coding
    0xFFD0: "Restart Marker 0",
    0xFFD1: "Restart Marker 1",
    0xFFD2: "Restart Marker 2",
    0xFFD3: "Restart Marker 3",
    0xFFD4: "Restart Marker 4",
    0xFFD5: "Restart Marker 5",
    0xFFD6: "Restart Marker 6",
    0xFFD7: "Restart Marker 7",
    0xFFD8: "Start of Image",
    0xFFD9: "End of Image",
    0xFFDA: "Start of Scan",
    0xFFDB: "Quantization Table",
    0xFFDC: "Define Number of Lines",
    0xFFDD: "Define Restart Interval",
    0xFFDE: "Define Hierarchical Progression",
    0xFFDF: "Expand Reference Component",
    0xFFE0: "Application Default Header",  # JFIF / JPEG Image, AVI1 - Motion JPEG (MJPG)
    0xFFE1: "Application Segment 1",  # EXIF Metadata, TIFF IFD format, JPEG thumbnail (160 x 120), Adobe XMP
    0xFFE2: "Application Segment 2",  # ICC Color Profile, FlashPix
    0xFFE3: "Application Segment 3",  # JPS Tag for Stereoscopic JPEG Images
    0xFFE4: "Application Segment 4",
    0xFFE5: "Application Segment 5",
    0xFFE6: "Application Segment 6",  # NITF Lossless profile
    0xFFE7: "Application Segment 7",
    0xFFE8: "Application Segment 8",
    0xFFE9: "Application Segment 9",
    0xFFEA: "Application Segment 10",  # ActiveObject (multimedia messages / captions)
    0xFFEB: "Application Segment 11",  # HELIOS JPEG Resources (OPI Postscript)
    0xFFEC: "Application Segment 12",  # Picture Info (older digicams), Photoshop Save for Web: Ducky
    0xFFED: "Application Segment 13",  # Photoshop Save As: IRB, 8BIM, IPTC
    0xFFEE: "Application Segment 14",
    0xFFEF: "Application Segment 15",
    0xFFF0: "JPEG Extension 0",
    0xFFF1: "JPEG Extension 1",
    0xFFF2: "JPEG Extension 2",
    0xFFF3: "JPEG Extension 3",
    0xFFF4: "JPEG Extension 4",
    0xFFF5: "JPEG Extension 5",
    0xFFF6: "JPEG Extension 6",
    0xFFF7: "JPEG Extension 7",  # Lossless JPEG
    0xFFF8: "JPEG Extension 8",  # Lossless JPEG Extension Parameters
    0xFFF9: "JPEG Extension 9",
    0xFFFA: "JPEG Extension 10",
    0xFFFB: "JPEG Extension 11",
    0xFFFC: "JPEG Extension 12",
    0xFFFD: "JPEG Extension 13",
    0xFFFE: "Comment"
}

# IDCT Scaling Factors (Chen-Wang algorithm)
m0 = 2.0 * math.cos(1.0 / 16.0 * 2.0 * math.pi)
m1 = 2.0 * math.cos(2.0 / 16.0 * 2.0 * math.pi)
m3 = 2.0 * math.cos(2.0 / 16.0 * 2.0 * math.pi)
m5 = 2.0 * math.cos(3.0 / 16.0 * 2.0 * math.pi)
m2 = m0 - m5
m4 = m0 + m5

s0 = math.cos(0.0 / 16.0 * math.pi) / math.sqrt(8)
s1 = math.cos(1.0 / 16.0 * math.pi) / 2.0
s2 = math.cos(2.0 / 16.0 * math.pi) / 2.0
s3 = math.cos(3.0 / 16.0 * math.pi) / 2.0
s4 = math.cos(4.0 / 16.0 * math.pi) / 2.0
s5 = math.cos(5.0 / 16.0 * math.pi) / 2.0
s6 = math.cos(6.0 / 16.0 * math.pi) / 2.0
s7 = math.cos(7.0 / 16.0 * math.pi) / 2.0

def GetBytes(type, lst, length):
    """
    Extract and unpack multiple bytes from a byte sequence.

    Args:
        type (str): Format character for struct.unpack ('B' for unsigned char, 'H' for unsigned short, etc.)
        lst (bytes): Byte sequence to extract from
        length (int): Number of bytes to extract

    Returns:
        list: List of unpacked integer values

    Example:
        >>> data = b'\x10\x20\x30\x40'
        >>> GetBytes('B', data, 4)
        [16, 32, 48, 64]
    """

    typeTimes = ''
    for _ in range(length):
        typeTimes += type

    return list(unpack(typeTimes, lst[:length]))

def remove_FF00(data):
    """
    Remove JPEG bit stuffing (0xFF00 sequences) from entropy-coded data.
    JPEG uses 0xFF00 to represent literal 0xFF bytes in the bitstream.

    Args:
        data (bytes): Raw entropy-coded segment data from JPEG

    Returns:
        tuple: (processed_data, bytes_consumed)
            - processed_data (list): Byte list with 0xFF00 unstuffed to 0xFF
            - bytes_consumed (int): Number of bytes processed from input

    Example:
        >>> data = b'\xFF\x00\x12\x34\xFF\xD9'  # 0xFF00 followed by regular bytes, then marker
        >>> clean_data, length = remove_FF00(data)
        >>> clean_data
        [255, 18, 52]  # 0xFF00 -> 0xFF, stops at 0xFFD9 marker
    """

    datapro = []
    i = 0
    while(True):
        b, bnext = unpack('BB', data[i: i + 2])
        if b == 0xFF:
            if bnext != 0:
                break
            datapro.append(data[i])
            i += 2
        else:
            datapro.append(data[i])
            i += 1
    return datapro, i

def decode_number(code, bits):
    """
    Decode a signed integer from JPEG's variable-length encoding.
    JPEG represents AC coefficients using magnitude + sign encoding.

    Args:
        code (int): Bit length of the encoded value (0-11 typical range)
        bits (int): The actual bit pattern to decode

    Returns:
        int: Decoded signed integer value

    Example:
        >>> decode_number(3, 0b101)  # 3 bits, pattern 101 (5 in decimal)
        5
        >>> decode_number(3, 0b010)  # 3 bits, pattern 010 (2 in decimal, negative)
        -5
        >>> decode_number(0, 0)  # Zero coefficient
        0
    """

    length = 2 ** (code - 1)
    if bits >= length:
        return bits
    else:
        return bits - (2 * length - 1)

def clamp(col):
    """
    Clamp color value to valid RGB range [0, 255].

    Args:
        col (float): Color component value (may be out of range)

    Returns:
        int: Clamped integer value between 0 and 255

    Example:
        >>> clamp(300.5)
        255
        >>> clamp(-50.2)
        0
        >>> clamp(128.7)
        128
    """

    return int(min(max(col, 0), 255))

#def colorConversion(Y, Cr, Cb):
#    R = Cr * (2 - 2 * .299) + Y
#    B = Cb * (2 - 2 * .114) + Y
#    G = (Y - .114 * B - .299 * R) / .587
#
#    return (clamp(R + 128), clamp(G + 128), clamp(B + 128))
def colorConversion(Y, Cr, Cb):
    """
    Convert YCbCr color space to RGB using ITU-R BT.601 standard.

    Args:
        Y (float): Luminance component (centered around 0 from IDCT)
        Cr (float): Red chrominance difference (centered around 0)
        Cb (float): Blue chrominance difference (centered around 0)

    Returns:
        tuple: (R, G, B) values as integers in range [0, 255]

    Example:
        >>> colorConversion(0, 0, 0)  # Gray (neutral)
        (128, 128, 128)
        >>> colorConversion(50, 25, -10)  # Reddish bright
        (213, 173, 161)
    """

    # Standard YCbCr to RGB conversion
    # Y, Cb, Cr are centered around 0 (from IDCT)
    R = Y + 1.402 * Cr
    G = Y - 0.344136 * Cb - 0.714136 * Cr
    B = Y + 1.772 * Cb
    
    return (clamp(R + 128), clamp(G + 128), clamp(B + 128))

class IDCT:
    """
    An inverse Discrete Cosine Transformation Class
    """
    def __init__(self):
        """
        Initialize Inverse Discrete Cosine Transform (IDCT) processor.
        Pre-computes IDCT coefficient table for 8x8 block transformation.

        Attributes:
            base (list): 64-element linear array for DCT coefficients
            zigzag (list): 8x8 matrix storing coefficients in zigzag order
            idct_precision (int): Block size (always 8 for JPEG)
            idct_table (list): Pre-computed cosine coefficients for fast IDCT

        Example:
            >>> idct = IDCT()
            >>> len(idct.base)
            64
            >>> len(idct.zigzag)
            8
            >>> len(idct.zigzag[0])
            8
        """

        self.base = [0] * 64
        self.zigzag = [
            [0, 1, 5, 6, 14, 15, 27, 28],
            [2, 4, 7, 13, 16, 26, 29, 42],
            [3, 8, 12, 17, 25, 30, 41, 43],
            [9, 11, 18, 24, 31, 40, 44, 53],
            [10, 19, 23, 32, 39, 45, 52, 54],
            [20, 22, 33, 38, 46, 51, 55, 60],
            [21, 34, 37, 47, 50, 56, 59, 61],
            [35, 36, 48, 49, 57, 58, 62, 63],
        ]
        self.idct_precision = 8
        self.idct_table = [
            [
                (self.NormCoeff(u) * math.cos(((2.0 * x + 1.0) * u * math.pi) / 16.0))
                for x in range(self.idct_precision)
            ]
            for u in range(self.idct_precision)
        ]

    def NormCoeff(self, n):
        """
        Calculate normalization coefficient for DCT basis functions.
        DC component (n=0) requires special scaling factor 1/√2.

        Args:
            n (int): Frequency index (0-7)

        Returns:
            float: Normalization coefficient (1/√2 for n=0, else 1.0)

        Example:
            >>> idct = IDCT()
            >>> idct.NormCoeff(0)
            0.7071067811865476  # 1/√2
            >>> idct.NormCoeff(5)
            1.0
        """

        if n == 0:
            return 1.0 / math.sqrt(2.0)
        else:
            return 1.0

    def rearrange_using_zigzag(self):
        """
        Convert linear DCT coefficient array to 8x8 zigzag-ordered matrix.
        JPEG stores coefficients in zigzag order for efficient run-length encoding.

        Returns:
            list: 8x8 matrix with coefficients rearranged from linear base array

        Side Effects:
            Modifies self.zigzag in-place

        Example:
            >>> idct = IDCT()
            >>> idct.base = list(range(64))  # Linear: 0, 1, 2, ..., 63
            >>> matrix = idct.rearrange_using_zigzag()
            >>> matrix[0][0]  # DC coefficient
            0
            >>> matrix[0][1]  # AC coefficient at zigzag position 1
            1
        """

        for x in range(8):
            for y in range(8):
                self.zigzag[x][y] = self.base[self.zigzag[x][y]]
        return self.zigzag

    def perform_IDCT(self):
        """
        Perform fast Inverse DCT using Chen-Wang algorithm on 8x8 coefficient matrix.
        Transforms frequency domain (DCT) coefficients to spatial domain pixel values.

        Side Effects:
            Updates self.base with spatial domain values (8x8 matrix)

        Algorithm:
            Uses factored Chen-Wang butterfly structure for O(N log N) complexity
            instead of naive O(N²) approach.

        Example:
            >>> idct = IDCT()
            >>> # Set DC coefficient only (flat gray block)
            >>> idct.zigzag = [[100] + [0]*7 for _ in range(8)]
            >>> idct.zigzag[0] = [100] + [0]*7
            >>> idct.perform_IDCT()
            >>> # Result: approximately uniform values near 100/8 = 12.5
        """

        cpzig = copy.deepcopy(self.zigzag)
        for i in range(8):
            g0 = cpzig[0][i] * s0
            g1 = cpzig[4][i] * s4
            g2 = cpzig[2][i] * s2
            g3 = cpzig[6][i] * s6
            g4 = cpzig[5][i] * s5
            g5 = cpzig[1][i] * s1
            g6 = cpzig[7][i] * s7
            g7 = cpzig[3][i] * s3

            f0 = g0
            f1 = g1
            f2 = g2
            f3 = g3
            f4 = g4 - g7
            f5 = g5 + g6
            f6 = g5 - g6
            f7 = g4 + g7

            e0 = f0
            e1 = f1
            e2 = f2 - f3
            e3 = f2 + f3
            e4 = f4
            e5 = f5 - f7
            e6 = f6
            e7 = f5 + f7
            e8 = f4 + f6

            d0 = e0
            d1 = e1
            d2 = e2 * m1
            d3 = e3
            d4 = e4 * m2
            d5 = e5 * m3
            d6 = e6 * m4
            d7 = e7
            d8 = e8 * m5

            c0 = d0 + d1
            c1 = d0 - d1
            c2 = d2 - d3
            c3 = d3
            c4 = d4 + d8
            c5 = d5 + d7
            c6 = d6 - d8
            c7 = d7
            c8 = c5 - c6

            b0 = c0 + c3
            b1 = c1 + c2
            b2 = c1 - c2
            b3 = c0 - c3
            b4 = c4 - c8
            b5 = c8
            b6 = c6 - c7
            b7 = c7

            cpzig[0][i] = b0 + b7
            cpzig[1][i] = b1 + b6
            cpzig[2][i] = b2 + b5
            cpzig[3][i] = b3 + b4
            cpzig[4][i] = b3 - b4
            cpzig[5][i] = b2 - b5
            cpzig[6][i] = b1 - b6
            cpzig[7][i] = b0 - b7

        for i in range(8):
            g0 = cpzig[i][0] * s0
            g1 = cpzig[i][4] * s4
            g2 = cpzig[i][2] * s2
            g3 = cpzig[i][6] * s6
            g4 = cpzig[i][5] * s5
            g5 = cpzig[i][1] * s1
            g6 = cpzig[i][7] * s7
            g7 = cpzig[i][3] * s3

            f0 = g0
            f1 = g1
            f2 = g2
            f3 = g3
            f4 = g4 - g7
            f5 = g5 + g6
            f6 = g5 - g6
            f7 = g4 + g7

            e0 = f0
            e1 = f1
            e2 = f2 - f3
            e3 = f2 + f3
            e4 = f4
            e5 = f5 - f7
            e6 = f6
            e7 = f5 + f7
            e8 = f4 + f6

            d0 = e0
            d1 = e1
            d2 = e2 * m1
            d3 = e3
            d4 = e4 * m2
            d5 = e5 * m3
            d6 = e6 * m4
            d7 = e7
            d8 = e8 * m5

            c0 = d0 + d1
            c1 = d0 - d1
            c2 = d2 - d3
            c3 = d3
            c4 = d4 + d8
            c5 = d5 + d7
            c6 = d6 - d8
            c7 = d7
            c8 = c5 - c6

            b0 = c0 + c3
            b1 = c1 + c2
            b2 = c1 - c2
            b3 = c0 - c3
            b4 = c4 - c8
            b5 = c8
            b6 = c6 - c7
            b7 = c7

            cpzig[i][0] = b0 + b7
            cpzig[i][1] = b1 + b6
            cpzig[i][2] = b2 + b5
            cpzig[i][3] = b3 + b4
            cpzig[i][4] = b3 - b4
            cpzig[i][5] = b2 - b5
            cpzig[i][6] = b1 - b6
            cpzig[i][7] = b0 - b7

        self.base = cpzig

class Stream:
    def __init__(self, data):
        """
        Initialize bitstream reader for entropy-coded JPEG data.

        Args:
            data (list or bytes): Byte sequence to read bits from

        Attributes:
            data: Input byte sequence
            pos (int): Current bit position (0-indexed)

        Example:
            >>> stream = Stream([0b10110011, 0b01001100])
            >>> stream.pos
            0
        """

        self.data = data
        self.pos = 0

    def GetBit(self):
        """
        Read single bit from bitstream and advance position.

        Returns:
            int: Bit value (0 or 1)

        Side Effects:
            Increments self.pos by 1

        Example:
            >>> stream = Stream([0b10110011])  # Binary: 1,0,1,1,0,0,1,1
            >>> stream.GetBit()
            1
            >>> stream.GetBit()
            0
            >>> stream.GetBit()
            1
        """

        bit = self.data[self.pos >> 3]  # equals to /8
        shiftAmount = 7 ^ (self.pos & 0x7)  #0x7 hex = 0b111 binary
        self.pos += 1
        return (bit >> shiftAmount) & 1  # get least significant bit

    def GetBitN(self, nrBits):
        """
        Read multiple bits from bitstream and return as integer.

        Args:
            nrBits (int): Number of bits to read (typically 1-16)

        Returns:
            int: Integer value formed by concatenating bits (MSB first)

        Example:
            >>> stream = Stream([0b10110011, 0b01001100])
            >>> stream.GetBitN(4)  # Read '1011'
            11
            >>> stream.GetBitN(4)  # Read '0011'
            3
            >>> stream.GetBitN(8)  # Read next byte '01001100'
            76
        """

        value = 0
        for _ in range(nrBits):
            value = value * 2 + self.GetBit()
        return value

class HuffmanTable:
    def __init__(self):
        """
        Initialize Huffman decoding tree for JPEG entropy coding.

        Attributes:
            root (list): Binary tree structure for Huffman decoding
            elements (list): Symbol values at tree leaves

        Example:
            >>> huff = HuffmanTable()
            >>> huff.root
            []
            >>> huff.elements
            []
        """

        self.root = []
        self.elements = []

    def bits_from_lengths(self, root, element, pos):
        """
        Recursively insert symbol into Huffman tree at specified bit depth.

        Args:
            root (list): Current tree node (list for internal, int for leaf)
            element (int): Symbol value to insert (e.g., 0x05 for run/size combo)
            pos (int): Bit depth for this symbol (0-15 typical)

        Returns:
            bool: True if insertion successful, False if position occupied

        Example:
            >>> huff = HuffmanTable()
            >>> huff.bits_from_lengths(huff.root, 0x05, 2)  # Insert symbol 5 at depth 2
            True
            >>> # Creates tree: [[[], [5]], []]
        """

        if isinstance(root, list):
            if pos == 0:
                if len(root) < 2:
                    root.append(element)
                    return True
                return False
            for i in [0, 1]:
                if len(root) == i:
                    root.append([])
                if self.bits_from_lengths(root[i], element, pos - 1) == True:
                    return True
        return False

    def get_huffman_bits(self, lengths, elements):
        """
        Build complete Huffman decoding tree from JPEG DHT marker data.

        Args:
            lengths (list): 16-element list of symbol counts per bit length
            elements (list): Flat list of symbols in canonical order

        Side Effects:
            Populates self.root with complete binary tree
            Stores elements in self.elements

        Example:
            >>> huff = HuffmanTable()
            >>> lengths = [0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]  # 2 at len 1, 1 at len 2
            >>> elements = [0x00, 0x01, 0x02]  # Three symbols
            >>> huff.get_huffman_bits(lengths, elements)
            >>> # Builds tree for decoding
        """

        self.elements = elements

        pos = 0
        for i in range(len(lengths)):
            for _ in range(lengths[i]):
                self.bits_from_lengths(self.root, elements[pos], i)
                pos += 1

    def find(self, st):
        """
        Traverse Huffman tree using bitstream until reaching a leaf symbol.

        Args:
            st (Stream): Bitstream positioned at start of Huffman code

        Returns:
            int: Decoded symbol value, or -1 if invalid code

        Example:
            >>> huff = HuffmanTable()
            >>> huff.get_huffman_bits([0, 1, 1, 0, ...], [0x05, 0x03, ...])
            >>> stream = Stream([0b10110000])
            >>> symbol = huff.find(stream)  # Reads bits until leaf found
            >>> symbol
            5  # Decoded symbol
        """

        r = self.root
        while isinstance(r, list):
            r = r[st.GetBit()]
        return r

    def get_code(self, st):
        """
        Decode next Huffman symbol from bitstream, handling special EOB case.

        Args:
            st (Stream): Bitstream positioned at start of symbol

        Returns:
            int: Decoded symbol (0 for EOB, >0 for run/size or size value)

        Example:
            >>> huff = HuffmanTable()
            >>> # ... (build tree for AC coefficients)
            >>> stream = Stream(jpeg_data)
            >>> code = huff.get_code(stream)
            >>> code
            0x35  # Run length 3, size 5 (0011 0101)
        """

        while(True):
            res = self.find(st)
            if res == 0:
                return 0
            elif res != -1:
                return res

class JPEG:
    def __init__(self, image_file, enable_gui=False):
        """
        Initialize JPEG decoder and load image file into memory.

        Args:
            image_file (str): Path to JPEG file
            enable_gui (bool): Enable Tkinter canvas rendering (deprecated, default False)

        Attributes:
            huffman_tables (dict): Huffman tables indexed by table ID
            quant (dict): Quantization tables indexed by table ID
            quant_mapping (list): Component-to-quantization-table mapping
            dct_blocks (list): Decoded DCT coefficient blocks
            pixel_data (list): Spatial domain pixel values (if rendered)

        Example:
            >>> jpeg = JPEG('photo.jpg')
            >>> len(jpeg.img_data) > 0
            True
            >>> jpeg.enable_gui
            False
        """

        self.huffman_tables = {}
        self.quant = {}
        self.quant_mapping = []
        self.dct_blocks = []
        self.pixel_data = []
        self.enable_gui = enable_gui
        self.canvas = None
        with open(image_file, 'rb') as f:
            self.img_data = f.read()

    def build_matrix(self, st, idx, quant, oldDCcoeff):
        """
        Decode one 8x8 MCU block from Huffman bitstream and dequantize coefficients.

        Args:
            st (Stream): Entropy-coded bitstream
            idx (int): Huffman table index (0 for Y, 1 for Cb/Cr)
            quant (list): 64-element quantization table for this component
            oldDCcoeff (int): Previous DC coefficient for differential decoding

        Returns:
            tuple: (idct_obj, new_dc_coeff, dct_block)
                - idct_obj (IDCT): IDCT object with spatial domain result
                - new_dc_coeff (int): Current DC coefficient for next block
                - dct_block (list): 8x8 matrix of dequantized DCT coefficients

        Example:
            >>> jpeg = JPEG('test.jpg')
            >>> stream = Stream(entropy_data)
            >>> idct, dc, dct = jpeg.build_matrix(stream, 0, jpeg.quant[0], 0)
            >>> dct[0][0]  # DC coefficient
            1024
            >>> dct[0][1]  # First AC coefficient
            -15
        """

        i = IDCT()

        code = self.huffman_tables[0 + idx].get_code(st)
        bits = st.GetBitN(code)
        DCcoeff = decode_number(code, bits) + oldDCcoeff

        i.base[0] = DCcoeff * quant[0]
        length = 1
        while length < 64:
            code = self.huffman_tables[16 + idx].get_code(st)
            if code == 0:
                break

            # the first part of the AC quantization table
            # is the number of leading zeroes

            if code > 15:
                length += code >> 4
                code &= 0x0F

            bits = st.GetBitN(code)

            if length < 64:
                coeff = decode_number(code, bits)
                i.base[length] = coeff * quant[length]
                length += 1

        i.rearrange_using_zigzag()

        dct_block = copy.deepcopy(i.zigzag)

        i.perform_IDCT()

        return i, DCcoeff, dct_block


    def draw_matrix_on_canvas(self, x, y, matL, matCr, matCb):
        """
        Render 8x8 MCU block to Tkinter canvas (deprecated, kept for compatibility).

        Args:
            x (int): Block X position in image (in MCU units)
            y (int): Block Y position in image (in MCU units)
            matL (list): 8x8 luminance spatial values
            matCr (list): 8x8 red chrominance spatial values
            matCb (list): 8x8 blue chrominance spatial values

        Side Effects:
            Draws rectangles on self.canvas if enabled

        Note:
            Deprecated - use _save_stego_image() for image reconstruction

        Example:
            >>> jpeg = JPEG('test.jpg', enable_gui=True)
            >>> # ... (during decode, automatically called for each block)
        """

        if self.canvas is None:
            return
        for yy in range(MCU):
            for xx in range(MCU):
                c = "#%02x%02x%02x" % colorConversion(matL[yy][xx], matCr[yy][xx], matCb[yy][xx])
                x1, y1 = (x * MCU + xx) * 2, (y * MCU + yy) * 2
                x2, y2 = (x * MCU + (xx + 1)) * 2, (y * MCU + (yy + 1)) * 2
                self.canvas.create_rectangle(x1, y1, x2, y2, fill=c, outline=c)


    def start_of_scan(self, data, headerLen):
        """
        Decode entropy-coded scan data (SOS marker segment).
        Processes all MCU blocks and stores DCT coefficients.

        Args:
            data (bytes): Raw JPEG data starting at SOS marker
            headerLen (int): Length of SOS header to skip

        Returns:
            int: Total bytes consumed (header + entropy data)

        Side Effects:
            Populates self.dct_blocks with decoded coefficient matrices

        Example:
            >>> jpeg = JPEG('image.jpg')
            >>> # ... (parse headers first)
            >>> bytes_read = jpeg.start_of_scan(data, 12)
            >>> len(jpeg.dct_blocks)
            1200  # Number of 8x8 blocks in image
        """

        data, lenchunk = remove_FF00(data[headerLen:])
        st = Stream(data)
        old_lum_dc_coeff, old_cb_dc_coeff, old_cr_dc_coeff = 0, 0, 0

        for y in range(self.height // 8):
            for x in range(self.width // 8):
                matL, old_lum_dc_coeff, dct_L = self.build_matrix(st, 0, self.quant[self.quant_mapping[0]], old_lum_dc_coeff)
                matCb, old_cb_dc_coeff, dct_Cb = self.build_matrix(st, 1, self.quant[self.quant_mapping[1]], old_cb_dc_coeff)
                matCr, old_cr_dc_coeff, dct_Cr = self.build_matrix(st, 1, self.quant[self.quant_mapping[2]], old_cr_dc_coeff)

                # store DCT blocks
                self.dct_blocks.append({
                    'Y': dct_L,
                    'Cb': dct_Cb,
                    'Cr': dct_Cr,
                    'x': x,
                    'y': y
                })
                
                if self.enable_gui and self.canvas is not None:
                    self.draw_matrix_on_canvas(x, y, matL.base, matCr.base, matCb.base)

        return lenchunk + headerLen

    def BaselineDCT(self, data):
        """
        Parse Start of Frame (SOF0) marker - baseline DCT image structure.

        Args:
            data (bytes): SOF0 marker payload (after marker and length)

        Side Effects:
            Sets self.height, self.width, and self.quant_mapping

        Example:
            >>> jpeg = JPEG('photo.jpg')
            >>> sof_data = b'\x08\x02\x00\x03\x00\x03...'  # Precision, height, width, components
            >>> jpeg.BaselineDCT(sof_data)
            Size 512 x 768
            >>> jpeg.width
            512
            >>> jpeg.height
            768
        """

        header, self.height, self.width, components = unpack('>BHHB', data[0: 6])  # H - unsigned short int
        print('Size %i x %i' % (self.width, self.height))

        for i in range(components):
            id, samp, QtbId = unpack('BBB', data[6 + i * 3: 9 + i * 3])
            self.quant_mapping.append(QtbId)

    def define_quantization_tables(self, data):
        """
        Parse Define Quantization Table (DQT) marker.

        Args:
            data (bytes): DQT marker payload containing table ID and 64 coefficients

        Side Effects:
            Adds quantization table to self.quant dictionary

        Example:
            >>> jpeg = JPEG('test.jpg')
            >>> dqt_data = b'\x00\x10\x0b\x0c...'  # Table 0, then 64 quant values
            >>> jpeg.define_quantization_tables(dqt_data)
            >>> len(jpeg.quant[0])
            64
            >>> jpeg.quant[0][0]  # DC quantization value
            16
        """

        header, = unpack('B', data[0: 1])
        self.quant[header] = GetBytes('B', data[1: 1 + 64], 64)
        data = data[65:]

    def decode_huffman(self, data):
        """
        Parse Define Huffman Table (DHT) marker and build decoding tree.

        Args:
            data (bytes): DHT marker payload (table class/ID + lengths + symbols)

        Side Effects:
            Adds HuffmanTable object to self.huffman_tables

        Table IDs:
            0: DC luminance, 1: DC chrominance
            16 (0x10): AC luminance, 17 (0x11): AC chrominance

        Example:
            >>> jpeg = JPEG('photo.jpg')
            >>> dht_data = b'\x00\x00\x02\x03...'  # DC table 0
            >>> jpeg.decode_huffman(dht_data)
            >>> 0 in jpeg.huffman_tables
            True
        """

        offset = 0
        header, = unpack('B', data[offset: offset + 1])
        offset += 1

        # extract the 16 bytes containing length data
        lengths = GetBytes('B', data[offset: offset + 16], 16)
        offset += 16

        # extract the elements after the initial 16 bytes
        elements = []
        for i in lengths:
            elements += GetBytes('B', data[offset: offset + i], i)
            offset += i

        hf = HuffmanTable()
        hf.get_huffman_bits(lengths, elements)
        self.huffman_tables[header] = hf
        data = data[offset:]


    def decode(self):
        """
        Main JPEG decoding loop - parse all markers and decode image.

        Side Effects:
            Populates self.dct_blocks, self.quant, self.huffman_tables
            Prints marker names during parsing

        Markers Handled:
            SOI (0xFFD8), SOF0 (0xFFC0), DHT (0xFFC4), DQT (0xFFDB),
            SOS (0xFFDA), EOI (0xFFD9), APPn, COM, etc.

        Example:
            >>> jpeg = JPEG('image.jpg')
            >>> jpeg.decode()
            Start of Image
            Application Default Header
            Define Quantization Table
            Start of Frame 0
            Size 640 x 480
            Define Huffman Table
            ...
            End of Image
            >>> len(jpeg.dct_blocks)
            4800  # 640/8 * 480/8 * 1 (Y+Cb+Cr treated as 3 components)
        """

        data = self.img_data
        while(True):
            marker, = unpack('>H', data[0: 2])  # H - unsigned char big-endian
            print(marker_dict.get(marker))
            if marker == 0xFFD8:  # SOI Marker
                data = data[2:]
            elif marker == 0xFFD9:  # EOI Marker
                return
            else:
                lenchunk, = unpack('>H', data[2: 4])
                lenchunk += 2
                chunk = data[4: lenchunk]

                if marker == 0xFFC4:  # DHT
                    self.decode_huffman(chunk)
                elif marker == 0xFFDB :  # DQT
                    self.define_quantization_tables(chunk)
                elif marker == 0xFFC0:  # SOF
                    self.BaselineDCT(chunk)
                elif marker == 0xFFDA:  # SOS
                    lenchunk = self.start_of_scan(data, lenchunk)
                data = data[lenchunk:]
            if len(data) == 0:
                break

class DCTDM:
    def __init__(self, image_file, delta=10):
        """
        Initialize DCTDM steganography engine with quantization step parameter.

        Args:
            image_file (str): Path to cover JPEG image (or None for extraction-only)
            delta (int): Quantization step for difference modulation (default 10)
                - Lower delta (5-10): Better imperceptibility, less robust
                - Higher delta (15-20): More robust, possible artifacts

        Raises:
            ValueError: If delta is negative

        Side Effects:
            Converts image to baseline JPEG if incompatible

        Example:
            >>> dctdm = DCTDM('cover.jpg', delta=10)
            ✓ Image is compatible with decoder
            >>> dctdm.delta
            10
            >>> dctdm = DCTDM(None, delta=15)  # Extraction-only mode
        """

        if delta < 0:
            raise ValueError("Delta must be positive")
        self.delta = delta
        self.image_file = image_file

        if image_file:
            self._ensure_baseline_jpeg()
    
    def _derive_key(self, password, salt=None):
        """
        Derive 256-bit encryption key from password using PBKDF2-HMAC-SHA256.

        Args:
            password (str): User password (any length)
            salt (bytes, optional): 16-byte salt (generates random if None)

        Returns:
            tuple: (key, salt)
                - key (bytes): 32-byte base64-encoded Fernet key
                - salt (bytes): 16-byte salt used for derivation

        Algorithm:
            PBKDF2-HMAC-SHA256 with 100,000 iterations

        Example:
            >>> dctdm = DCTDM('test.jpg')
            >>> key, salt = dctdm._derive_key('SecurePassword123')
            >>> len(key)
            44  # Base64-encoded 32 bytes
            >>> len(salt)
            16
        """

        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    def _encrypt_message(self, message, password):
        """
        Encrypt message using AES-256 via Fernet symmetric encryption.

        Args:
            message (str): Plaintext message to encrypt
            password (str): Encryption password

        Returns:
            bytes: Salt (16 bytes) + encrypted message (variable length)

        Example:
            >>> dctdm = DCTDM('cover.jpg')
            >>> encrypted = dctdm._encrypt_message('Secret data', 'mypassword')
            >>> len(encrypted)
            105  # 16 (salt) + 89 (Fernet ciphertext with MAC)
            >>> encrypted[:16]  # Salt prefix
            b'\\x8a\\x3f...'
        """

        key, salt = self._derive_key(password)
        f = Fernet(key)
        
        # encrypt the message
        encrypted = f.encrypt(message.encode())
        
        # prepend salt (needed for decryption)
        return salt + encrypted
    
    def _decrypt_message(self, encrypted_data, password):
        """
        Decrypt Fernet-encrypted message using password and embedded salt.

        Args:
            encrypted_data (bytes): Salt (16 bytes) + ciphertext
            password (str): Decryption password (must match encryption password)

        Returns:
            str: Decrypted plaintext message

        Raises:
            ValueError: If password is wrong or data is corrupted

        Example:
            >>> dctdm = DCTDM('cover.jpg')
            >>> encrypted = dctdm._encrypt_message('Hello', 'pass123')
            >>> plaintext = dctdm._decrypt_message(encrypted, 'pass123')
            >>> plaintext
            'Hello'
            >>> dctdm._decrypt_message(encrypted, 'wrongpass')
            ValueError: Decryption failed. Wrong password or corrupted data.
        """

        # extract salt (first 16 bytes)
        salt = encrypted_data[:16]
        encrypted_message = encrypted_data[16:]
        
        # derive key using same salt
        key, _ = self._derive_key(password, salt)
        f = Fernet(key)
        
        try:
            decrypted = f.decrypt(encrypted_message)
            return decrypted.decode()
        except Exception as e:
            raise ValueError("Decryption failed. Wrong password or corrupted data.")
    
    def _ensure_baseline_jpeg(self):
        """
        Verify JPEG compatibility or convert to baseline DCT format.
        Handles progressive, optimized, and arithmetic-coded JPEGs.

        Side Effects:
            Creates '*_baseline.jpg' file if conversion needed
            Updates self.image_file to baseline version

        Conversion Settings:
            Quality=100, no optimization, no progressive scan, 4:4:4 subsampling

        Example:
            >>> dctdm = DCTDM('progressive.jpg')
            JPEG format not supported: KeyError: 16
            Converting to Baseline JPEG (this may take a moment)...
            ✓ Converted to: progressive_baseline.jpg
            ✓ Converted image is compatible
        """

        is_compatible = False
        try:
            # try to decode with our decoder
            test_jpeg = JPEG(self.image_file)
            test_jpeg.decode()
            is_compatible = True
            print("✓ Image is compatible with decoder")
        except (ValueError, KeyError, IndexError) as e:
            print(f"JPEG format not supported: {type(e).__name__}: {e}")
            is_compatible = False
        
        if not is_compatible:
            print("Converting to Baseline JPEG (this may take a moment)...")
            
            # convert using PIL with maximum quality
            img = Image.open(self.image_file)
            baseline_file = self.image_file.replace('.jpg', '_baseline.jpg').replace('.jpeg', '_baseline.jpg')
            
            # save with quality=100, no optimization, baseline DCT
            img.save(baseline_file, 'JPEG', 
                    quality=100,         # Maximum quality
                    optimize=False,      # Don't optimize (use standard tables)
                    progressive=False,   # Force baseline DCT
                    subsampling=0)       # 4:4:4 (no chroma subsampling)
            
            print(f"✓ Converted to: {baseline_file}")
            self.image_file = baseline_file
            
            # verify the conversion worked
            try:
                test_jpeg2 = JPEG(self.image_file)
                test_jpeg2.decode()
                print("✓ Converted image is compatible")
            except Exception as e2:
                print(f"✗ Error: Even after conversion, image failed to decode: {e2}")
                raise ValueError("Image cannot be processed. Try a different image or manually convert to baseline JPEG.")
    
    def embed_message(self, secret_message, output_file='stego.jpg', password=None):
        """
        Embed secret message into JPEG using DCT Difference Modulation.

        Args:
            secret_message (str): Message to hide (any length, capacity permitting)
            output_file (str): Output filename (saved to 'Output Images/' directory)
            password (str, optional): Encryption password (None for no encryption)

        Returns:
            str: Full path to generated stego JPEG file

        Side Effects:
            Creates stego JPEG and .meta metadata file
            Prints embedding statistics and verification

        Algorithm:
            1. Decode JPEG to get DCT coefficients
            2. Encrypt message if password provided (AES-256)
            3. Embed 2 bits per coefficient pair using difference modulation
            4. Encode modified coefficients back to JPEG

        Example:
            >>> dctdm = DCTDM('photo.jpg', delta=10)
            >>> stego_path = dctdm.embed_message('Hidden text', 'output.jpg', 'secret')
            Encrypting message...
            Embedded ENCRYPTED 11 chars → 128 chars encrypted (1040 bits)
            Used 65 blocks to embed message
            ✓ Encoded JPEG with 4800 blocks
            >>> stego_path
            'Output Images/output.jpg'
        """

        output_dir = 'Output Images'
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"Created directory: {output_dir}")
        
        output_path = os.path.join(output_dir, output_file)

        # decode JPEG and get DCT blocks
        jpeg = JPEG(self.image_file)
        jpeg.decode()

        # encrypt message if password provided
        if password:
            print("Encrypting message...")
            encrypted_data = self._encrypt_message(secret_message, password)
            # convert bytes to base64 string for embedding
            message_to_embed = base64.b64encode(encrypted_data).decode('ascii')
            print(f"   Encrypted size: {len(encrypted_data)} bytes → {len(message_to_embed)} chars (base64)")
        else:
            message_to_embed = secret_message

        quant_Y = jpeg.quant[jpeg.quant_mapping[0]]
        
        # convert message to binary
        binary_message = ''.join(format(ord(char), '08b') for char in message_to_embed)
        msg_length = len(message_to_embed)
        binary_message = format(msg_length, '016b') + binary_message
        
        if password:
            print(f"Embedding ENCRYPTED {len(secret_message)} chars → {msg_length} chars encrypted ({len(binary_message)} bits)")
        else:
            print(f"Embedding {msg_length} characters ({len(binary_message)} bits)")
        
        # embed in Y (luminance) channel DCT blocks
        bit_index = 0
        blocks_used = 0
        
        for block_data in jpeg.dct_blocks:
            if bit_index >= len(binary_message):
                break
            
            block = block_data['Y']  # work with luminance channel
            
            # embed in rows 1-7 (skip DC coefficient in row 0)
            for row in range(1, 8):
                if bit_index + 1 >= len(binary_message):
                    break
                
                # process pairs of coefficients
                for j in range(0, 7, 2):
                    if bit_index + 1 >= len(binary_message):
                        break
                    
                    bit1 = int(binary_message[bit_index])
                    bit2 = int(binary_message[bit_index + 1])
                    
                    # get the quantization table indices for these positions
                    idx1 = row * 8 + j
                    idx2 = row * 8 + (j + 1)

                    # the DCT coefficients are DEQUANTIZED (coeff * quant_table)
                    # convert to quantized values first
                    ac1_dequant = float(block[row][j])
                    ac2_dequant = float(block[row][j + 1])
                    
                    # quantize to get the integer values
                    ac1_quant = round(ac1_dequant / quant_Y[idx1])
                    ac2_quant = round(ac2_dequant / quant_Y[idx2])

                    D_original = ac1_quant - ac2_quant
                    
                    # calculate epsilon values based on absolute difference
                    abs_D = abs(D_original)
                    
                    # round to nearest multiple of delta (not down!)
                    # this ensures we don't always get epsilon1=0 for small values
                    k = int(abs_D / self.delta)  # nearest multiple
                    epsilon1 = k * self.delta + self.delta / 4
                    epsilon2 = k * self.delta + 3 * self.delta / 4
                    
                    # embed bits according to the 4 cases
                    if bit1 == 0 and bit2 == 0:
                        new_diff = epsilon1
                    elif bit1 == 0 and bit2 == 1:
                        new_diff = epsilon2
                    elif bit1 == 1 and bit2 == 0:
                        new_diff = -epsilon2
                    else:  # bit1 == 1 and bit2 == 1
                        new_diff = -epsilon1
                    
                    # update QUANTIZED coefficients
                    avg_quant = (ac1_quant + ac2_quant) / 2
                    new_ac1_quant = round(avg_quant + new_diff / 2)
                    new_ac2_quant = round(avg_quant - new_diff / 2)
                    
                    # convert back to DEQUANTIZED values for storage
                    block[row][j] = new_ac1_quant * quant_Y[idx1]
                    block[row][j + 1] = new_ac2_quant * quant_Y[idx2]
                    
                    # debug first few embeddings
                    if bit_index < 32:
                        print(f"DEBUG Embed[{bit_index}]: bits={bit1}{bit2}, " +
                            f"D_orig={D_original:.2f} (quant), " +
                            f"new_diff={new_diff:.2f}, " +
                            f"ac1: {ac1_quant}->{new_ac1_quant}, ac2: {ac2_quant}->{new_ac2_quant}")
                    
                    bit_index += 2
            
            blocks_used += 1
        
        print(f"Used {blocks_used} blocks to embed message")
        
        # use custom JPEG encoder to preserve exact DCT coefficients
        print("Encoding JPEG with embedded message...")
        encoder = JPEGEncoder(jpeg)
        encoder.encode(output_path)

        # save metadata about encryption to a separate file
        metadata_path = output_path.replace('.jpg', '.meta')
        with open(metadata_path, 'wb') as f:
            pickle.dump({'encrypted': password is not None}, f)

        if password:
            print(f"Message encrypted and embedded successfully!")
            print(f"Password required for extraction!")
        else:
            print(f"Message embedded successfully (no encryption)")
        
        print(f"Stego JPEG saved: {output_path}")
        print(f"Metadata saved: {metadata_path}")
        
        return output_path

    def extract_message(self, stego_file, password=None):
        """
        Extract hidden message from stego JPEG using DCTDM algorithm.

        Args:
            stego_file (str): Path to stego JPEG file
            password (str, optional): Decryption password (required if encrypted)

        Returns:
            str: Extracted plaintext message, or error string if failed

        Raises:
            ValueError: If password required but not provided, or decryption fails

        Algorithm:
            1. Decode stego JPEG to DCT coefficients
            2. Extract 2 bits per coefficient pair by analyzing differences
            3. Reconstruct binary message from bits
            4. Decrypt if password provided

        Example:
            >>> dctdm = DCTDM(None, delta=10)  # Extraction mode
            >>> message = dctdm.extract_message('Output Images/stego.jpg', 'secret')
            Extracting from JPEG: Output Images/stego.jpg
            This message is encrypted
            Decrypting message...
            ✓ Message decrypted successfully
            >>> message
            'Hidden text'
        """

        print(f"Extracting from JPEG: {stego_file}")
        
        # check for metadata file
        metadata_path = stego_file.replace('.jpg', '.meta')
        is_encrypted = False

        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, 'rb') as f:
                    metadata = pickle.load(f)
                is_encrypted = metadata.get('encrypted', False)
                
                if is_encrypted:
                    print("This message is encrypted")
                    if not password:
                        raise ValueError("Password required for extraction!")
            except Exception as e:
                print(f"Warning: Could not read metadata: {e}")

        # decode the stego JPEG
        jpeg = JPEG(stego_file)
        jpeg.decode()

        quant_Y = jpeg.quant[jpeg.quant_mapping[0]]
        
        extracted_bits = []
        bit_count = 0
        
        for block_data in jpeg.dct_blocks:
            block = block_data['Y']
            
            for row in range(1, 8):
                for j in range(0, 7, 2):
                    if j + 1 >= 8:  # make sure we don't go out of bounds
                        break
                        
                    # get quantization indices
                    idx1 = row * 8 + j
                    idx2 = row * 8 + (j + 1)
                    
                    # convert dequantized to quantized
                    ac1_dequant = float(block[row][j])
                    ac2_dequant = float(block[row][j + 1])
                    
                    ac1_quant = round(ac1_dequant / quant_Y[idx1])
                    ac2_quant = round(ac2_dequant / quant_Y[idx2])
                    
                    # work with QUANTIZED difference
                    D = ac1_quant - ac2_quant
                    abs_D = abs(D)

                    # find which quantization bin this falls into
                    # the boundary between epsilon1 and epsilon2 is at k*delta + delta/2    
                    k = int(abs_D / self.delta)
                    boundary = k * self.delta + self.delta / 2
                    
                    # the value is closer to epsilon2 if dist2 < dist1
                    is_epsilon2 = abs_D >= boundary
                    
                    # extract bits based on sign and which epsilon
                    if D >= 0:
                        if is_epsilon2:
                            extracted_bits.extend([0, 1])  # positive, epsilon2
                        else:
                            extracted_bits.extend([0, 0])  # positive, epsilon1
                    else:
                        if is_epsilon2:
                            extracted_bits.extend([1, 0])  # negative, epsilon2
                        else:
                            extracted_bits.extend([1, 1])  # negative, epsilon1
                    
                    # debug first few extractions
                    if bit_count < 10:
                        print(f"DEBUG Extract: D={D:.2f}, abs_D={abs_D:.2f}, k={k}, " +
                            f"boundary={boundary:.2f}, is_eps2={is_epsilon2}, bits={extracted_bits[-2:]}")
                    bit_count += 1
                    
                    # check if we have the complete message
                    if len(extracted_bits) >= 16:
                        msg_length = int(''.join(map(str, extracted_bits[:16])), 2)
                        if msg_length > 0 and msg_length < 10000:  # sanity check
                            total_bits_needed = 16 + (msg_length * 8)
                            if len(extracted_bits) >= total_bits_needed:
                                print(f"DEBUG: Extracted {len(extracted_bits)} bits total")
                                break
                
                if len(extracted_bits) >= 16:
                    msg_length = int(''.join(map(str, extracted_bits[:16])), 2)
                    if msg_length > 0 and msg_length < 10000:
                        total_bits_needed = 16 + (msg_length * 8)
                        if len(extracted_bits) >= total_bits_needed:
                            break
            
            if len(extracted_bits) >= 16:
                msg_length = int(''.join(map(str, extracted_bits[:16])), 2)
                if msg_length > 0 and msg_length < 10000:
                    total_bits_needed = 16 + (msg_length * 8)
                    if len(extracted_bits) >= total_bits_needed:
                        break
        
        # decode the message
        if len(extracted_bits) < 16:
            print("Error: Not enough bits extracted")
            return ""
        
        print(f"DEBUG: First 16 bits: {''.join(map(str, extracted_bits[:16]))}")
        msg_length = int(''.join(map(str, extracted_bits[:16])), 2)
        print(f"DEBUG: Message length decoded: {msg_length}")
        
        if msg_length == 0 or msg_length > 10000:  # sanity check
            print(f"Error: Invalid message length: {msg_length}")
            return ""
        
        message_bits = extracted_bits[16:16 + (msg_length * 8)]
        print(f"DEBUG: Extracting {len(message_bits)} message bits")
        
        message = ''
        for i in range(0, len(message_bits), 8):
            if i + 8 <= len(message_bits):
                byte = message_bits[i:i+8]
                char_code = int(''.join(map(str, byte)), 2)
                message += chr(char_code)
        
        # decrypt if encrypted
        if is_encrypted and password:
            print("Decrypting message...")
            try:
                # decode from base64
                encrypted_data = base64.b64decode(message)
                message = self._decrypt_message(encrypted_data, password)
                print("✓ Message decrypted successfully")
            except Exception as e:
                raise ValueError(f"Decryption failed: {e}")
        elif is_encrypted and not password:
            return "[ENCRYPTED - PASSWORD REQUIRED]"
        
        return message
    
    def _save_stego_image(self, jpeg, output_file):
        """
        Reconstruct spatial domain image from modified DCT coefficients.
        (Note: Deprecated - JPEGEncoder preserves DCT directly)

        Args:
            jpeg (JPEG): JPEG object with modified dct_blocks
            output_file (str): Output image path

        Side Effects:
            Saves reconstructed image as JPEG (quality=100, 4:4:4)

        Example:
            >>> dctdm = DCTDM('cover.jpg')
            >>> jpeg = JPEG('cover.jpg')
            >>> jpeg.decode()
            >>> # ... modify jpeg.dct_blocks ...
            >>> dctdm._save_stego_image(jpeg, 'reconstructed.jpg')
            Saved stego image: reconstructed.jpg
        """

        # create numpy array for the image
        img_array = np.zeros((jpeg.height, jpeg.width, 3), dtype=np.uint8)
        
        # reconstruct image from DCT blocks
        for block_data in jpeg.dct_blocks:
            x = block_data['x']
            y = block_data['y']
            
            # apply IDCT to each channel using the existing IDCT class
            Y_spatial = self._idct_block(block_data['Y'])
            Cr_spatial = self._idct_block(block_data['Cr'])
            Cb_spatial = self._idct_block(block_data['Cb'])
            
            # convert YCrCb to RGB and place in image array
            for yy in range(8):
                for xx in range(8):
                    pixel_y = y * 8 + yy
                    pixel_x = x * 8 + xx
                    
                    if pixel_y < jpeg.height and pixel_x < jpeg.width:
                        Y_val = Y_spatial[yy][xx]
                        Cr_val = Cr_spatial[yy][xx]
                        Cb_val = Cb_spatial[yy][xx]
                        
                        # YCbCr to RGB conversion
                        R = Y_val + 1.402 * Cr_val
                        G = Y_val - 0.344136 * Cb_val - 0.714136 * Cr_val
                        B = Y_val + 1.772 * Cb_val
                        
                        # clamp and store
                        img_array[pixel_y][pixel_x][0] = clamp(R + 128)
                        img_array[pixel_y][pixel_x][1] = clamp(G + 128)
                        img_array[pixel_y][pixel_x][2] = clamp(B + 128)
        
        # save using PIL with highest quality JPEG to minimize re-compression artifacts
        img = Image.fromarray(img_array, 'RGB')
        img.save(output_file, 'JPEG', quality=100, subsampling=0)
        print(f"Saved stego image: {output_file}")
    
    def _idct_block(self, dct_coeffs):
        """
        Apply Inverse DCT to 8x8 coefficient block for image reconstruction.

        Args:
            dct_coeffs (list): 8x8 matrix of DCT coefficients (zigzag order)

        Returns:
            list: 8x8 matrix of spatial domain pixel values (centered around 0)

        Example:
            >>> dctdm = DCTDM('test.jpg')
            >>> dct_block = [[120.5] + [0]*7 for _ in range(8)]  # DC-only block
            >>> spatial = dctdm._idct_block(dct_block)
            >>> spatial[0][0]  # Approximately 120.5/8 = 15.06
            15.234
        """

        idct = IDCT()
        
        # the DCT coefficients are already in zigzag order
        idct.zigzag = copy.deepcopy(dct_coeffs)
        
        # perform IDCT
        idct.perform_IDCT()
        
        # return the spatial domain values
        return idct.base


class JPEGThread(threading.Thread):
    def __init__(self, jpeg_instance):
        """
        Initialize background thread for JPEG decoding (prevents GUI blocking).

        Args:
            jpeg_instance (JPEG): JPEG decoder instance to run in thread

        Example:
            >>> jpeg = JPEG('large_photo.jpg', enable_gui=True)
            >>> thread = JPEGThread(jpeg)
            >>> thread.start()
            >>> # GUI remains responsive while decoding
        """

        threading.Thread.__init__(self)
        self.jpeg_instance = jpeg_instance

    def run(self):
        """
        Execute JPEG decode() in background thread.

        Side Effects:
            Calls self.jpeg_instance.decode()

        Example:
            >>> jpeg = JPEG('photo.jpg')
            >>> thread = JPEGThread(jpeg)
            >>> thread.start()
            >>> thread.join()  # Wait for completion
            >>> len(jpeg.dct_blocks) > 0
            True
        """
        
        self.jpeg_instance.decode()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--stego':
        print("=" * 60)
        print("DCTDM Steganography - Direct Execution")
        print("=" * 60)
        print()
        
        image_file = input("Enter input image path (default: Images/profile2.jpg): ").strip()
        if not image_file:
            image_file = 'Images/profile2.jpg'
        
        secret_message = input("Enter secret message to embed: ").strip()
        if not secret_message:
            secret_message = "This is a secret message!"
            print(f"Using default message: {secret_message}")

        use_encryption = input("Encrypt message? (y/n, default: n): ").strip().lower()
        password = None
        if use_encryption == 'y':
            password = input("Enter encryption password: ").strip()
            if not password:
                print("Warning: Empty password! Message will not be encrypted.")
                password = None

        delta_input = input("Enter delta value (default: 10): ").strip()
        delta = int(delta_input) if delta_input else 10
        
        output_file = input("Enter output filename (default: stego_output.jpg): ").strip()
        if not output_file:
            output_file = 'stego_output.jpg'
        
        print("\n" + "=" * 60)
        dctdm = DCTDM(image_file, delta=delta)
        stego_file = dctdm.embed_message(secret_message, output_file, password=password)
        
        print("\n" + "=" * 60)
        print("Verifying embedded message...")
        print("=" * 60)
        extracted = dctdm.extract_message(stego_file, password=password)
        
        print(f"\nOriginal message:  '{secret_message}'")
        print(f"Extracted message: '{extracted}'")
        print(f"Match: {secret_message == extracted}")
        
        if secret_message == extracted:
            print("\n✓ Message successfully embedded and verified!")
            print(f"\nFiles saved:")
            print(f"  - Stego JPEG: {stego_file}")
            if password:
                print(f"  - Metadata: {stego_file.replace('.jpg', '.meta')}")
                print(f"\nMessage is encrypted. Password required for extraction.")
        else:
            print("\n✗ Message verification failed!")
    
    else:
        print("=" * 60)
        print("DCTDM - GUI Mode (View Decoded JPEG)")
        print("=" * 60)
        print()
        
        print("Decoding JPEG using DCTDM...")
        dctdm = DCTDM('Images/profile2.jpg', delta=10)
        
        jpeg = JPEG('Images/profile2.jpg', enable_gui=False)
        jpeg.decode()
        
        temp_output = 'Output Images/decoded_view.jpg'
        os.makedirs('Output Images', exist_ok=True)
        
        print(f"Saving decoded image to: {temp_output}")
        dctdm._save_stego_image(jpeg, temp_output)
        
        print("Displaying decoded image...")
        img = Image.open(temp_output)
        img.show()
        
        print("\nImage displayed successfully!")
        print(f"Saved to: {temp_output}")
        print("Close the image window to exit.")