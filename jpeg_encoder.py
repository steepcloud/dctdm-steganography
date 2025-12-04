import struct
import copy

class JPEGEncoder:
    """
    Complete JPEG Encoder for steganography
    Preserves exact DCT coefficients without requantization
    """
    
    def __init__(self, original_jpeg):
        """Initialize encoder with data from decoded JPEG"""
        self.width = original_jpeg.width
        self.height = original_jpeg.height
        self.quant = copy.deepcopy(original_jpeg.quant)
        self.quant_mapping = copy.deepcopy(original_jpeg.quant_mapping)
        self.huffman_tables = copy.deepcopy(original_jpeg.huffman_tables)
        self.dct_blocks = original_jpeg.dct_blocks
        
        # Build reverse Huffman lookup tables
        self.huffman_code_tables = {}
        for table_id, huff_table in self.huffman_tables.items():
            self.huffman_code_tables[table_id] = self._build_huffman_code_table(huff_table)
    
    def _build_huffman_code_table(self, huffman_table):
        """Build reverse lookup: symbol -> (code, code_length)"""
        code_table = {}
        
        def traverse(node, code=0, length=0):
            if isinstance(node, list):
                # Internal node - traverse both children
                if len(node) > 0:
                    traverse(node[0], (code << 1) | 0, length + 1)
                if len(node) > 1:
                    traverse(node[1], (code << 1) | 1, length + 1)
            else:
                # Leaf node - store code for this symbol
                code_table[node] = (code, length)
        
        traverse(huffman_table.root)
        return code_table
    
    def _extract_huffman_data(self, huffman_table):
        """Extract lengths and symbols from Huffman table for DHT marker"""
        # Reconstruct the canonical Huffman table data
        symbols_by_length = {}
        
        def collect_symbols(node, length=0):
            if isinstance(node, list):
                if len(node) > 0:
                    collect_symbols(node[0], length + 1)
                if len(node) > 1:
                    collect_symbols(node[1], length + 1)
            else:
                # Leaf node - store symbol at this bit length
                if length not in symbols_by_length:
                    symbols_by_length[length] = []
                symbols_by_length[length].append(node)
        
        collect_symbols(huffman_table.root)
        
        # Build lengths array (16 bytes)
        lengths = []
        symbols = []
        for i in range(1, 17):  # Bit lengths 1-16
            if i in symbols_by_length:
                lengths.append(len(symbols_by_length[i]))
                symbols.extend(sorted(symbols_by_length[i]))
            else:
                lengths.append(0)
        
        return lengths, symbols
    
    def _write_dht_marker(self, jpeg_data):
        """Write Define Huffman Table markers"""
        # DC table 0 (luminance)
        if 0 in self.huffman_tables:
            lengths, symbols = self._extract_huffman_data(self.huffman_tables[0])
            jpeg_data.extend(struct.pack('>H', 0xFFC4))  # DHT marker
            length = 2 + 1 + 16 + len(symbols)
            jpeg_data.extend(struct.pack('>H', length))
            jpeg_data.append(0x00)  # Table class (0=DC) and ID (0)
            jpeg_data.extend(struct.pack('16B', *lengths))
            jpeg_data.extend(struct.pack(f'{len(symbols)}B', *symbols))
        
        # AC table 0 (luminance)
        if 16 in self.huffman_tables:
            lengths, symbols = self._extract_huffman_data(self.huffman_tables[16])
            jpeg_data.extend(struct.pack('>H', 0xFFC4))
            length = 2 + 1 + 16 + len(symbols)
            jpeg_data.extend(struct.pack('>H', length))
            jpeg_data.append(0x10)  # Table class (1=AC) and ID (0)
            jpeg_data.extend(struct.pack('16B', *lengths))
            jpeg_data.extend(struct.pack(f'{len(symbols)}B', *symbols))
        
        # DC table 1 (chrominance)
        if 1 in self.huffman_tables:
            lengths, symbols = self._extract_huffman_data(self.huffman_tables[1])
            jpeg_data.extend(struct.pack('>H', 0xFFC4))
            length = 2 + 1 + 16 + len(symbols)
            jpeg_data.extend(struct.pack('>H', length))
            jpeg_data.append(0x01)  # Table class (0=DC) and ID (1)
            jpeg_data.extend(struct.pack('16B', *lengths))
            jpeg_data.extend(struct.pack(f'{len(symbols)}B', *symbols))
        
        # AC table 1 (chrominance)
        if 17 in self.huffman_tables:
            lengths, symbols = self._extract_huffman_data(self.huffman_tables[17])
            jpeg_data.extend(struct.pack('>H', 0xFFC4))
            length = 2 + 1 + 16 + len(symbols)
            jpeg_data.extend(struct.pack('>H', length))
            jpeg_data.append(0x11)  # Table class (1=AC) and ID (1)
            jpeg_data.extend(struct.pack('16B', *lengths))
            jpeg_data.extend(struct.pack(f'{len(symbols)}B', *symbols))
    
    def _encode_number(self, value):
        """Encode a signed number into (size, bits) for JPEG"""
        if value == 0:
            return 0, 0
        
        abs_val = abs(value)
        # Number of bits needed to represent absolute value
        size = abs_val.bit_length()
        
        if value > 0:
            # Positive: use value as-is
            bits = value
        else:
            # Negative: use one's complement representation
            # For negative numbers, the representation is (2^size - 1) + value
            bits = (1 << size) - 1 + value
        
        return size, bits
    
    def _write_bits(self, bit_buffer, value, num_bits):
        """Append bits to buffer"""
        for i in range(num_bits - 1, -1, -1):
            bit = (value >> i) & 1
            bit_buffer.append(bit)
    
    def _bits_to_bytes(self, bit_buffer):
        """Convert bit buffer to bytes with JPEG bit stuffing"""
        byte_data = bytearray()
        byte_val = 0
        bit_count = 0
        
        for bit in bit_buffer:
            byte_val = (byte_val << 1) | bit
            bit_count += 1
            
            if bit_count == 8:
                byte_data.append(byte_val)
                # JPEG bit stuffing: insert 0x00 after 0xFF
                if byte_val == 0xFF:
                    byte_data.append(0x00)
                byte_val = 0
                bit_count = 0
        
        # Flush remaining bits, padded with 1s
        if bit_count > 0:
            byte_val <<= (8 - bit_count)
            byte_val |= (1 << (8 - bit_count)) - 1  # Pad with 1s
            byte_data.append(byte_val)
            if byte_val == 0xFF:
                byte_data.append(0x00)
        
        return bytes(byte_data)
    
    def _zigzag_to_linear(self, zigzag_block):
        """Convert 8x8 zigzag block to linear 64-element array"""
        zigzag_order = [
            0, 1, 5, 6, 14, 15, 27, 28,
            2, 4, 7, 13, 16, 26, 29, 42,
            3, 8, 12, 17, 25, 30, 41, 43,
            9, 11, 18, 24, 31, 40, 44, 53,
            10, 19, 23, 32, 39, 45, 52, 54,
            20, 22, 33, 38, 46, 51, 55, 60,
            21, 34, 37, 47, 50, 56, 59, 61,
            35, 36, 48, 49, 57, 58, 62, 63
        ]
        
        linear = [0] * 64
        for row in range(8):
            for col in range(8):
                idx = row * 8 + col
                linear[zigzag_order[idx]] = zigzag_block[row][col]
        
        return linear
    
    def _encode_block(self, dct_block, quant_table, dc_table_id, ac_table_id, prev_dc):
        """Encode a single 8x8 DCT block"""
        bit_buffer = []
        
        # Convert zigzag 2D array to linear array
        linear_dct = self._zigzag_to_linear(dct_block)
        
        # Quantize DCT coefficients
        quantized = [0] * 64
        for i in range(64):
            # Round to nearest integer (proper rounding)
            quantized[i] = round(linear_dct[i] / quant_table[i])
        
        # Encode DC coefficient (differential encoding)
        dc_diff = quantized[0] - prev_dc
        dc_size, dc_bits = self._encode_number(dc_diff)
        
        # Get Huffman code for DC size
        dc_code_table = self.huffman_code_tables[dc_table_id]
        if dc_size in dc_code_table:
            dc_code, dc_code_len = dc_code_table[dc_size]
            self._write_bits(bit_buffer, dc_code, dc_code_len)
            # Write the actual DC value bits
            if dc_size > 0:
                self._write_bits(bit_buffer, dc_bits, dc_size)
        else:
            # Fallback: write zero
            if 0 in dc_code_table:
                dc_code, dc_code_len = dc_code_table[0]
                self._write_bits(bit_buffer, dc_code, dc_code_len)
        
        # Encode AC coefficients in zigzag order
        ac_code_table = self.huffman_code_tables[ac_table_id]
        
        # Find last non-zero coefficient
        last_nonzero = 63
        while last_nonzero > 0 and quantized[last_nonzero] == 0:
            last_nonzero -= 1
        
        i = 1  # Start after DC
        while i <= last_nonzero:
            # Count zeros before next non-zero coefficient
            zero_run = 0
            while i <= last_nonzero and quantized[i] == 0:
                zero_run += 1
                i += 1
            
            if i > last_nonzero:
                break
            
            # Handle runs of 16+ zeros using ZRL (0xF0)
            while zero_run >= 16:
                if 0xF0 in ac_code_table:
                    zrl_code, zrl_len = ac_code_table[0xF0]
                    self._write_bits(bit_buffer, zrl_code, zrl_len)
                zero_run -= 16
            
            # Encode the AC coefficient
            ac_val = quantized[i]
            ac_size, ac_bits = self._encode_number(ac_val)
            
            # Combine run length and size: RRRRSSSS
            rs_symbol = (zero_run << 4) | ac_size
            
            if rs_symbol in ac_code_table:
                ac_code, ac_code_len = ac_code_table[rs_symbol]
                self._write_bits(bit_buffer, ac_code, ac_code_len)
                # Write the actual AC value bits
                if ac_size > 0:
                    self._write_bits(bit_buffer, ac_bits, ac_size)
            
            i += 1
        
        # End of block (EOB) if we finished before position 63
        if last_nonzero < 63:
            if 0 in ac_code_table:
                eob_code, eob_len = ac_code_table[0]
                self._write_bits(bit_buffer, eob_code, eob_len)
        
        return bit_buffer, quantized[0]
    
    def encode(self, output_path):
        """Encode complete JPEG file"""
        jpeg_data = bytearray()
        
        # SOI (Start of Image)
        jpeg_data.extend(struct.pack('>H', 0xFFD8))
        
        # APP0 (JFIF header)
        jpeg_data.extend(struct.pack('>H', 0xFFE0))
        jfif_header = bytearray()
        jfif_header.extend(b'JFIF\x00')  # Identifier
        jfif_header.extend(struct.pack('>BB', 1, 1))  # Version 1.1
        jfif_header.append(0)  # Density units (0 = no units)
        jfif_header.extend(struct.pack('>HH', 1, 1))  # X and Y density
        jfif_header.extend(struct.pack('>BB', 0, 0))  # Thumbnail size
        jpeg_data.extend(struct.pack('>H', len(jfif_header) + 2))
        jpeg_data.extend(jfif_header)
        
        # DQT (Define Quantization Table)
        for table_id in sorted(self.quant.keys()):
            jpeg_data.extend(struct.pack('>H', 0xFFDB))
            jpeg_data.extend(struct.pack('>H', 67))  # Length: 2 + 1 + 64
            jpeg_data.append(table_id)  # Precision (0) + Table ID
            jpeg_data.extend(struct.pack('64B', *self.quant[table_id]))
        
        # SOF0 (Start of Frame - Baseline DCT)
        jpeg_data.extend(struct.pack('>H', 0xFFC0))
        jpeg_data.extend(struct.pack('>H', 17))  # Length
        jpeg_data.append(8)  # Precision (8 bits)
        jpeg_data.extend(struct.pack('>HH', self.height, self.width))
        jpeg_data.append(3)  # Number of components (Y, Cb, Cr)
        
        # Component specifications
        # Component 1: Y (luminance)
        jpeg_data.append(1)  # Component ID
        jpeg_data.append(0x11)  # Sampling factors: 1x1
        jpeg_data.append(self.quant_mapping[0])  # Quantization table ID
        
        # Component 2: Cb (chrominance)
        jpeg_data.append(2)
        jpeg_data.append(0x11)
        jpeg_data.append(self.quant_mapping[1])
        
        # Component 3: Cr (chrominance)
        jpeg_data.append(3)
        jpeg_data.append(0x11)
        jpeg_data.append(self.quant_mapping[2])
        
        # DHT (Define Huffman Tables)
        self._write_dht_marker(jpeg_data)
        
        # SOS (Start of Scan)
        jpeg_data.extend(struct.pack('>H', 0xFFDA))
        jpeg_data.extend(struct.pack('>H', 12))  # Length
        jpeg_data.append(3)  # Number of components
        
        # Scan component selectors
        jpeg_data.extend(struct.pack('>BB', 1, 0x00))  # Y: DC table 0, AC table 0
        jpeg_data.extend(struct.pack('>BB', 2, 0x11))  # Cb: DC table 1, AC table 1
        jpeg_data.extend(struct.pack('>BB', 3, 0x11))  # Cr: DC table 1, AC table 1
        
        # Spectral selection
        jpeg_data.extend(struct.pack('>BBB', 0, 63, 0))  # Start, End, Approximation
        
        # Encode scan data (MCU blocks)
        scan_bits = []
        prev_dc_y = 0
        prev_dc_cb = 0
        prev_dc_cr = 0
        
        # Sort blocks by position for proper encoding order
        sorted_blocks = sorted(self.dct_blocks, key=lambda b: (b['y'], b['x']))
        
        for block_data in sorted_blocks:
            # Encode Y block
            y_bits, prev_dc_y = self._encode_block(
                block_data['Y'],
                self.quant[self.quant_mapping[0]],
                0, 16,  # DC table 0, AC table 16
                prev_dc_y
            )
            scan_bits.extend(y_bits)
            
            # Encode Cb block
            cb_bits, prev_dc_cb = self._encode_block(
                block_data['Cb'],
                self.quant[self.quant_mapping[1]],
                1, 17,  # DC table 1, AC table 17
                prev_dc_cb
            )
            scan_bits.extend(cb_bits)
            
            # Encode Cr block
            cr_bits, prev_dc_cr = self._encode_block(
                block_data['Cr'],
                self.quant[self.quant_mapping[2]],
                1, 17,  # DC table 1, AC table 17
                prev_dc_cr
            )
            scan_bits.extend(cr_bits)
        
        # Convert bits to bytes
        scan_bytes = self._bits_to_bytes(scan_bits)
        jpeg_data.extend(scan_bytes)
        
        # EOI (End of Image)
        jpeg_data.extend(struct.pack('>H', 0xFFD9))
        
        # Write to file
        with open(output_path, 'wb') as f:
            f.write(jpeg_data)
        
        print(f"✓ Encoded JPEG with {len(sorted_blocks)} blocks")
        print(f"✓ File size: {len(jpeg_data)} bytes")