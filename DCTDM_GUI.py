import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                             QTextEdit, QFileDialog, QSpinBox, QTabWidget,
                             QGroupBox, QMessageBox, QProgressBar)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont
from DCTDM import DCTDM

class WorkerThread(QThread):
    """Background thread for embedding/extraction to keep UI responsive"""
    finished = pyqtSignal(bool, str)
    progress = pyqtSignal(str)
    
    def __init__(self, operation, **kwargs):
        super().__init__()
        self.operation = operation
        self.kwargs = kwargs
    
    def run(self):
        try:
            if self.operation == 'embed':
                self.embed_message()
            elif self.operation == 'extract':
                self.extract_message()
        except Exception as e:
            self.finished.emit(False, str(e))
    
    def embed_message(self):
        self.progress.emit("Decoding JPEG image...")
        dctdm = DCTDM(self.kwargs['input_file'], delta=self.kwargs['delta'])
        
        self.progress.emit("Embedding message...")
        password = self.kwargs.get('password') if self.kwargs.get('password') else None

        stego_file = dctdm.embed_message(
            self.kwargs['message'], 
            self.kwargs['output_file'],
            password=password
        )
        
        self.progress.emit("Verifying embedded message...")
        extracted = dctdm.extract_message(stego_file, password=password)
        
        if extracted == self.kwargs['message']:
            msg = f"Message embedded successfully!\n\nStego JPEG: {stego_file}"
            if password:
                msg += "\nMessage is encrypted"
            self.finished.emit(True, msg)
        else:
            self.finished.emit(False, "Verification failed!")
    
    def extract_message(self):
        self.progress.emit("Loading JPEG...")
        dctdm = DCTDM(image_file=None, delta=self.kwargs['delta'])
        
        self.progress.emit("Extracting hidden message...")
        password = self.kwargs.get('password') if self.kwargs.get('password') else None
        
        try:
            extracted = dctdm.extract_message(self.kwargs['stego_file'], password=password)
            
            if extracted:
                self.finished.emit(True, extracted)
            else:
                self.finished.emit(False, "No message found")
        except ValueError as e:
            self.finished.emit(False, str(e))

class DCTDMApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steganography Tool - DCTDM (DCT Difference Modulation)")
        self.setGeometry(100, 100, 950, 750)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
            QLineEdit, QTextEdit, QSpinBox {
                padding: 5px;
                border: 2px solid #ddd;
                border-radius: 3px;
            }
            QLineEdit:focus, QTextEdit:focus, QSpinBox:focus {
                border: 2px solid #4CAF50;
            }
        """)
        
        self.worker = None
        self.init_ui()
    
    def init_ui(self):
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Title
        title = QLabel("Steganography Tool")
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        title.setFont(title_font)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title)
        
        subtitle = QLabel("Hide and Reveal Encrypted Text Inside Images")
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_font.setItalic(True)
        subtitle.setFont(subtitle_font)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #666;")
        main_layout.addWidget(subtitle)
        
        # Tab widget
        tabs = QTabWidget()
        main_layout.addWidget(tabs)
        
        # Embed tab
        embed_tab = self.create_embed_tab()
        tabs.addTab(embed_tab, "Hide Message")
        
        # Extract tab
        extract_tab = self.create_extract_tab()
        tabs.addTab(extract_tab, "Reveal Message")
        
        # Analysis tab
        analysis_tab = self.create_analysis_tab()
        tabs.addTab(analysis_tab, "Analyze Detection Limits")
        
        # About tab
        about_tab = self.create_about_tab()
        tabs.addTab(about_tab, "About DCTDM")
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(True)
        main_layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.status_label)
    
    def create_embed_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Input image group
        input_group = QGroupBox("Input Image")
        input_layout = QHBoxLayout()
        input_group.setLayout(input_layout)
        
        self.embed_input_edit = QLineEdit()
        self.embed_input_edit.setPlaceholderText("Select input JPEG image...")
        input_layout.addWidget(self.embed_input_edit)
        
        browse_input_btn = QPushButton("Browse...")
        browse_input_btn.clicked.connect(self.browse_input_image)
        input_layout.addWidget(browse_input_btn)
        
        layout.addWidget(input_group)
        
        # Secret message group
        message_group = QGroupBox("Secret Message to Hide")
        message_layout = QVBoxLayout()
        message_group.setLayout(message_layout)
        
        self.message_text = QTextEdit()
        self.message_text.setPlaceholderText("Enter your secret message here...")
        self.message_text.setMaximumHeight(150)
        message_layout.addWidget(self.message_text)
        
        # Character counter
        self.char_count_label = QLabel("Characters: 0 | Bits: 0")
        self.char_count_label.setStyleSheet("color: #666;")
        self.message_text.textChanged.connect(self.update_char_count)
        message_layout.addWidget(self.char_count_label)
        
        layout.addWidget(message_group)

        # Encryption group
        encryption_group = QGroupBox("Encryption (Optional)")
        encryption_layout = QVBoxLayout()
        encryption_group.setLayout(encryption_layout)
        
        password_layout = QHBoxLayout()
        password_label = QLabel("Password (optional):")
        self.embed_password_edit = QLineEdit()
        self.embed_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.embed_password_edit.setPlaceholderText("Leave empty for no encryption")
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.embed_password_edit)
        layout.addLayout(password_layout)

        # Password info
        pwd_info = QLabel("Tip: Use a strong password with letters, numbers, and symbols")
        pwd_info.setStyleSheet("color: #666; font-size: 10px;")
        encryption_layout.addWidget(pwd_info)

        layout.addWidget(encryption_group)
        
        # Settings group
        settings_group = QGroupBox("Steganography Settings")
        settings_layout = QVBoxLayout()
        settings_group.setLayout(settings_layout)
        
        delta_layout = QHBoxLayout()
        delta_label = QLabel("Delta (δ) - Quantization Step:")
        delta_layout.addWidget(delta_label)
        
        self.embed_delta_spin = QSpinBox()
        self.embed_delta_spin.setRange(1, 50)
        self.embed_delta_spin.setValue(10)
        self.embed_delta_spin.setToolTip("Controls imperceptibility vs robustness trade-off\n\nδ = 5-10: High quality, less robust\nδ = 10-15: Balanced (recommended)\nδ = 15-20: More robust, may show artifacts")
        delta_layout.addWidget(self.embed_delta_spin)
        
        delta_layout.addStretch()
        settings_layout.addLayout(delta_layout)
        
        # Info label
        info_label = QLabel("Lower delta = better image quality | Higher delta = more resistant to detection")
        info_label.setStyleSheet("color: #666; font-size: 10px;")
        info_label.setWordWrap(True)
        settings_layout.addWidget(info_label)
        
        layout.addWidget(settings_group)
        
        # Output group
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        output_group.setLayout(output_layout)
        
        output_file_layout = QHBoxLayout()
        self.output_filename_edit = QLineEdit("stego_output.jpg")
        self.output_filename_edit.setPlaceholderText("Output filename...")
        output_file_layout.addWidget(QLabel("Filename:"))
        output_file_layout.addWidget(self.output_filename_edit)
        output_layout.addLayout(output_file_layout)

        
        output_dir_layout = QHBoxLayout()
        self.output_dir_edit = QLineEdit("Output Images")
        output_dir_layout.addWidget(QLabel("Directory:"))
        output_dir_layout.addWidget(self.output_dir_edit)
        
        browse_output_btn = QPushButton("Browse...")
        browse_output_btn.clicked.connect(self.browse_output_dir)
        output_dir_layout.addWidget(browse_output_btn)
        
        output_layout.addLayout(output_dir_layout)
        
        layout.addWidget(output_group)
        
        # Embed button
        self.embed_btn = QPushButton("Hide Message in Image")
        self.embed_btn.setMinimumHeight(50)
        self.embed_btn.clicked.connect(self.embed_message)
        layout.addWidget(self.embed_btn)
        
        layout.addStretch()
        
        return widget
    
    def create_extract_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Input method selection
        method_group = QGroupBox("Stego Image Input")
        method_layout = QVBoxLayout()
        method_group.setLayout(method_layout)
        
        # JPEG file method
        jpeg_layout = QHBoxLayout()
        self.extract_jpeg_edit = QLineEdit()
        self.extract_jpeg_edit.setPlaceholderText("Select stego JPEG file...")
        jpeg_layout.addWidget(QLabel("JPEG File:"))
        jpeg_layout.addWidget(self.extract_jpeg_edit)
        
        browse_jpeg_btn = QPushButton("Browse...")
        browse_jpeg_btn.clicked.connect(self.browse_stego_jpeg)
        jpeg_layout.addWidget(browse_jpeg_btn)
        
        method_layout.addLayout(jpeg_layout)
        
        layout.addWidget(method_group)
        
        # Decryption group
        decryption_group = QGroupBox("Decryption")
        decryption_layout = QVBoxLayout()
        decryption_group.setLayout(decryption_layout)
        
        password_layout = QHBoxLayout()
        password_label = QLabel("Password (if encrypted):")
        self.extract_password_edit = QLineEdit()
        self.extract_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.extract_password_edit.setPlaceholderText("Leave empty if not encrypted")
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.extract_password_edit)
        decryption_layout.addLayout(password_layout)

        # Password info
        pwd_info = QLabel("If message is encrypted, you MUST provide the correct password")
        pwd_info.setStyleSheet("color: #ff6600; font-size: 10px;")
        decryption_layout.addWidget(pwd_info)
        
        layout.addWidget(decryption_group)

        # Settings group
        settings_group = QGroupBox("Extraction Settings")
        settings_layout = QVBoxLayout()
        settings_group.setLayout(settings_layout)

        delta_layout = QHBoxLayout()
        delta_label = QLabel("Delta (δ):")
        delta_layout.addWidget(delta_label)
        
        self.extract_delta_spin = QSpinBox()
        self.extract_delta_spin.setRange(1, 50)
        self.extract_delta_spin.setValue(10)
        self.extract_delta_spin.setToolTip("Must match the delta used during embedding")
        delta_layout.addWidget(self.extract_delta_spin)
        
        delta_layout.addStretch()
        settings_layout.addLayout(delta_layout)
        
        warning_label = QLabel("Delta must match the value used when hiding the message")
        warning_label.setStyleSheet("color: #ff6600; font-size: 10px;")
        settings_layout.addWidget(warning_label)
        
        layout.addWidget(settings_group)
        
        # Extract button
        self.extract_btn = QPushButton("Reveal Hidden Message")
        self.extract_btn.setMinimumHeight(50)
        self.extract_btn.clicked.connect(self.extract_message)
        layout.addWidget(self.extract_btn)
        
        # Extracted message display
        result_group = QGroupBox("Revealed Secret Message")
        result_layout = QVBoxLayout()
        result_group.setLayout(result_layout)
        
        self.extracted_text = QTextEdit()
        self.extracted_text.setReadOnly(True)
        self.extracted_text.setPlaceholderText("Hidden message will appear here after extraction...")
        result_layout.addWidget(self.extracted_text)
        
        # Copy and save buttons
        button_layout = QHBoxLayout()
        
        copy_btn = QPushButton("Copy to Clipboard")
        copy_btn.clicked.connect(self.copy_extracted_message)
        button_layout.addWidget(copy_btn)
        
        save_btn = QPushButton("Save to File")
        save_btn.clicked.connect(self.save_extracted_message)
        button_layout.addWidget(save_btn)
        
        result_layout.addLayout(button_layout)
        
        layout.addWidget(result_group)
        
        layout.addStretch()
        
        return widget
    
    def create_analysis_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        # Analysis info
        info_group = QGroupBox("Detection Limits Analysis")
        info_layout = QVBoxLayout()
        info_group.setLayout(info_layout)
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setMaximumHeight(200)
        info_text.setHtml("""
        <h3>Understanding Detection Limits</h3>
        <p>DCTDM modulates <b>differences between adjacent DCT coefficients</b> to hide data. 
        The delta (δ) parameter controls how detectable the changes are:</p>
        <ul>
            <li><b>Imperceptibility:</b> Changes are invisible to human eyes across all delta values</li>
            <li><b>Statistical Detection:</b> Lower delta = harder to detect by steganalysis tools</li>
            <li><b>Robustness:</b> Higher delta = survives JPEG recompression better</li>
        </ul>
        """)
        info_layout.addWidget(info_text)
        
        layout.addWidget(info_group)
        
        # Comparison group
        compare_group = QGroupBox("Compare Original vs Stego Image")
        compare_layout = QVBoxLayout()
        compare_group.setLayout(compare_layout)
        
        # File selections
        orig_layout = QHBoxLayout()
        self.analysis_orig_edit = QLineEdit()
        self.analysis_orig_edit.setPlaceholderText("Select original image...")
        orig_layout.addWidget(QLabel("Original:"))
        orig_layout.addWidget(self.analysis_orig_edit)
        browse_orig_btn = QPushButton("Browse...")
        browse_orig_btn.clicked.connect(self.browse_analysis_original)
        orig_layout.addWidget(browse_orig_btn)
        compare_layout.addLayout(orig_layout)
        
        stego_layout = QHBoxLayout()
        self.analysis_stego_edit = QLineEdit()
        self.analysis_stego_edit.setPlaceholderText("Select stego image...")
        stego_layout.addWidget(QLabel("Stego:"))
        stego_layout.addWidget(self.analysis_stego_edit)
        browse_stego_btn = QPushButton("Browse...")
        browse_stego_btn.clicked.connect(self.browse_analysis_stego)
        stego_layout.addWidget(browse_stego_btn)
        compare_layout.addLayout(stego_layout)
        
        # Analyze button
        analyze_btn = QPushButton("Analyze Differences")
        analyze_btn.setMinimumHeight(40)
        analyze_btn.clicked.connect(self.analyze_images)
        compare_layout.addWidget(analyze_btn)
        
        layout.addWidget(compare_group)
        
        # Results group
        results_group = QGroupBox("Analysis Results")
        results_layout = QVBoxLayout()
        results_group.setLayout(results_layout)
        
        self.analysis_results = QTextEdit()
        self.analysis_results.setReadOnly(True)
        self.analysis_results.setPlaceholderText("Analysis results will appear here...")
        results_layout.addWidget(self.analysis_results)
        
        layout.addWidget(results_group)
        
        layout.addStretch()
        
        return widget
    
    def create_about_tab(self):
        widget = QWidget()
        layout = QVBoxLayout()
        widget.setLayout(layout)
        
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <h2>DCTDM Steganography Tool with AES Encryption</h2>
        
        <h3>What is DCTDM?</h3>
        <p><b>DCT Difference Modulation (DCTDM)</b> is an advanced steganography technique that hides 
        secret messages within JPEG images by modulating the <b>differences between adjacent DCT 
        (Discrete Cosine Transform) coefficients</b>.</p>
        
        <p><i>Reference: Bhattacharyya, S., Khan, A., & Sanyal, G. (2014). "DCT Difference Modulation 
        (DCTDM) Image Steganography." International Journal of Information & Network Security (IJINS), 
        Vol. 3, No. 1, pp. 40-63.</i></p>
        
        <h3>Encryption Features</h3>
        <ul>
            <li><b>AES-256 Encryption:</b> Military-grade encryption via Fernet (symmetric)</li>
            <li><b>PBKDF2 Key Derivation:</b> 100,000 iterations with SHA-256</li>
            <li><b>Random Salt:</b> Unique salt per message prevents rainbow table attacks</li>
            <li><b>Optional:</b> Can embed with or without encryption</li>
        </ul>
                           
        <h3>How DCTDM Works</h3>
        <ol>
            <li><b>Encryption (if password provided):</b> Message → AES-256 → Base64</li>
            <li><b>DCT Transform:</b> Image is converted to frequency domain using Discrete Cosine Transform</li>
            <li><b>Embedding:</b> Modify coefficient differences to encode bits</li>
            <li><b>Coefficient Pairs:</b> Adjacent AC coefficients are selected as embedding locations</li>
            <li><b>Difference Modulation:</b> The difference D = AC1 - AC2 is modified to encode 2 bits:
                <ul>
                    <li>bits = 00 → D = +ε₁</li>
                    <li>bits = 01 → D = +ε₂</li>
                    <li>bits = 10 → D = -ε₂</li>
                    <li>bits = 11 → D = -ε₁</li>
                </ul>
            </li>
            <li><b>Extraction:</b> Secret message is recovered by analyzing coefficient differences</li>
            <li><b>JPEG Encoding:</b> Save with preserved DCT coefficients</li>
        </ol>
        
        <h3>Key Advantages</h3>
        <ul>
            <li>✓ <b>High Imperceptibility:</b> Changes are in DCT domain, invisible to human eyes</li>
            <li>✓ <b>Robustness:</b> Resistant to JPEG recompression and noise</li>
            <li>✓ <b>Capacity:</b> 2 bits per coefficient pair = high embedding capacity</li>
            <li>✓ <b>Security:</b> Difficult to detect with statistical steganalysis</li>
        </ul>
        
        <h3>Security Layers</h3>
        <table border="1" cellpadding="5" style="border-collapse: collapse;">
            <tr style="background-color: #e0e0e0;">
                <th>Layer</th>
                <th>Protection</th>
            </tr>
            <tr>
                <td>Steganography</td>
                <td>Hides existence of secret message</td>
            </tr>
            <tr>
                <td>AES-256 Encryption</td>
                <td>Protects message content even if detected</td>
            </tr>
            <tr>
                <td>PBKDF2 Key Derivation</td>
                <td>Prevents brute-force password attacks</td>
            </tr>
            <tr>
                <td>Random Salt</td>
                <td>Each encryption is unique</td>
            </tr>
        </table>
        
        <h3>Delta (δ) Parameter</h3>
        <p>The quantization step that controls the embedding strength:</p>
        <ul>
            <li><b>ε₁ = k×δ + δ/4</b> (closer to quantization boundary)</li>
            <li><b>ε₂ = k×δ + 3×δ/4</b> (farther from boundary)</li>
            <li><b>boundary = k×δ + δ/2</b></li>
        </ul>
        
        <table border="1" cellpadding="5" style="border-collapse: collapse;">
            <tr style="background-color: #e0e0e0;">
                <th>Delta Range</th>
                <th>Image Quality</th>
                <th>Robustness</th>
                <th>Use Case</th>
            </tr>
            <tr>
                <td>δ = 5-10</td>
                <td>Excellent</td>
                <td>Moderate</td>
                <td>High-quality images, minimal processing</td>
            </tr>
            <tr>
                <td>δ = 10-15</td>
                <td>Very Good</td>
                <td>Good</td>
                <td><b>Recommended balance</b></td>
            </tr>
            <tr>
                <td>δ = 15-20</td>
                <td>Good</td>
                <td>Excellent</td>
                <td>Resistant to compression/attacks</td>
            </tr>
            <tr>
                <td>δ > 20</td>
                <td>Fair</td>
                <td>Maximum</td>
                <td>Maximum security, may show artifacts</td>
            </tr>
        </table>
        
        <h3>Project Capabilities</h3>
        <ul>
            <li>✓ <b>Hide:</b> Embed secret text messages (with optional encryption) into JPEG images</li>
            <li>✓ <b>Reveal:</b> Extract hidden messages (with optional decryption) from stego images</li>
            <li>✓ <b>Analyze:</b> Compare original vs stego images to measure detection limits</li>
            <li>✓ <b>Verify:</b> Automatic message verification during embedding</li>
        </ul>
        
        <h3>Technical Details</h3>
        <ul>
            <li><b>Transform Domain:</b> DCT (Discrete Cosine Transform)</li>
            <li><b>Block Size:</b> 8×8 MCU (Minimum Coded Unit)</li>
            <li><b>Embedding Rate:</b> 2 bits per coefficient pair</li>
            <li><b>Color Space:</b> YCbCr (works with JPEG standard)</li>
            <li><b>Format:</b> JPEG (lossy compression compatible)</li>
        </ul>
        
        <h3>Usage Tips</h3>
        <ul>
            <li>🔹 Always use the <b>same delta value</b> for embedding and extraction</li>
            <li>🔹 The stego image appears <b>visually identical</b> to the original</li>
            <li>🔹 <b>Files:</b> Keep both .jpg and .meta files together</li>
            <li>🔹 Longer messages require more DCT coefficient pairs</li>
            <li>🔹 Test with different delta values to find your optimal balance</li>
            <li>🔹 <b>Security:</b> Encrypted message is useless without password</li>
        </ul>
        
        <p><i>Developed with PyQt6, NumPy, Python and Python Cryptography<br>
        Based on academic research in image steganography</i></p>
        """)
        layout.addWidget(about_text)
        
        return widget
    
    # Slot functions
    def browse_input_image(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Input Image", "", "JPEG Images (*.jpg *.jpeg)"
        )
        if filename:
            self.embed_input_edit.setText(filename)
    
    def browse_output_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if directory:
            self.output_dir_edit.setText(directory)
    
    def browse_stego_jpeg(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Stego JPEG", "", "JPEG Images (*.jpg *.jpeg)"
        )
        if filename:
            self.extract_jpeg_edit.setText(filename)
    
    def browse_analysis_original(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Original Image", "", "JPEG Images (*.jpg *.jpeg)"
        )
        if filename:
            self.analysis_orig_edit.setText(filename)
    
    def browse_analysis_stego(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Stego Image", "", "JPEG Images (*.jpg *.jpeg)"
        )
        if filename:
            self.analysis_stego_edit.setText(filename)
    
    def update_char_count(self):
        count = len(self.message_text.toPlainText())
        bits = count * 8 + 16  # 8 bits per char + 16 bits for length
        self.char_count_label.setText(f"Characters: {count} | Bits: {bits} (2 bits per coefficient pair)")
    
    def embed_message(self):
        # Validate inputs
        if not self.embed_input_edit.text():
            QMessageBox.warning(self, "Missing Input", "Please select an input image.")
            return
        
        if not self.message_text.toPlainText():
            QMessageBox.warning(self, "Missing Message", "Please enter a secret message.")
            return
        
        if not self.output_filename_edit.text():
            QMessageBox.warning(self, "Missing Output", "Please specify an output filename.")
            return
        
        # Disable buttons
        self.embed_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        
        # Create output directory if needed
        output_dir = self.output_dir_edit.text()
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Start worker thread
        self.worker = WorkerThread(
            'embed',
            input_file=self.embed_input_edit.text(),
            message=self.message_text.toPlainText(),
            delta=self.embed_delta_spin.value(),
            output_file=self.output_filename_edit.text(),
            password=self.embed_password_edit.text() if self.embed_password_edit.text() else None
        )
        self.worker.progress.connect(self.update_status)
        self.worker.finished.connect(self.embed_finished)
        self.worker.start()
    
    def embed_finished(self, success, message):
        self.progress_bar.setVisible(False)
        self.embed_btn.setEnabled(True)
        
        if success:
            QMessageBox.information(self, "Success - Message Hidden!", message)
            self.status_label.setText("✓ Secret message successfully hidden in image!")
        else:
            QMessageBox.critical(self, "Error", message)
            self.status_label.setText("✗ Embedding failed!")
    
    def extract_message(self):
        # Validate inputs
        if not self.extract_jpeg_edit.text():
            QMessageBox.warning(self, "Missing Input", "Please select a stego JPEG file.")
            return
        
        # Disable buttons
        self.extract_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        
        # Start worker thread
        self.worker = WorkerThread(
            'extract',
            stego_file=self.extract_jpeg_edit.text(),
            delta=self.extract_delta_spin.value(),
            password=self.extract_password_edit.text() if self.extract_password_edit.text() else None
        )
        self.worker.progress.connect(self.update_status)
        self.worker.finished.connect(self.extract_finished)
        self.worker.start()
    
    def extract_finished(self, success, message):
        self.progress_bar.setVisible(False)
        self.extract_btn.setEnabled(True)
        
        if success:
            self.extracted_text.setPlainText(message)
            self.status_label.setText("✓ Secret message successfully revealed!")
            QMessageBox.information(self, "Success - Message Revealed!", 
                                   f"Hidden message extracted successfully!\n\nLength: {len(message)} characters")
        else:
            QMessageBox.critical(self, "Error", message)
            self.status_label.setText("✗ Extraction failed!")
    
    def update_status(self, message):
        self.status_label.setText(message)
    
    def copy_extracted_message(self):
        text = self.extracted_text.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            QMessageBox.information(self, "Copied", "Secret message copied to clipboard!")
    
    def save_extracted_message(self):
        text = self.extracted_text.toPlainText()
        if not text:
            QMessageBox.warning(self, "No Message", "No message to save.")
            return
        
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Secret Message", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(text)
            QMessageBox.information(self, "Saved", f"Secret message saved to:\n{filename}")
    
    def analyze_images(self):
        if not self.analysis_orig_edit.text() or not self.analysis_stego_edit.text():
            QMessageBox.warning(self, "Missing Images", "Please select both original and stego images.")
            return
        
        try:
            from PIL import Image
            import numpy as np
            
            # Load images
            orig = Image.open(self.analysis_orig_edit.text())
            stego = Image.open(self.analysis_stego_edit.text())
            
            orig_array = np.array(orig)
            stego_array = np.array(stego)
            
            # Calculate metrics
            diff = np.abs(orig_array.astype(int) - stego_array.astype(int))
            
            # MSE (Mean Squared Error)
            mse = np.mean(diff ** 2)
            
            # PSNR (Peak Signal-to-Noise Ratio)
            if mse == 0:
                psnr = float('inf')
            else:
                psnr = 10 * np.log10((255 ** 2) / mse)
            
            # Per-channel differences
            r_diff = diff[:,:,0].mean()
            g_diff = diff[:,:,1].mean()
            b_diff = diff[:,:,2].mean()
            
            # Max difference
            max_diff = diff.max()
            
            # Results
            results = f"""<h3>Image Comparison Analysis</h3>
            
<table border="1" cellpadding="8" style="border-collapse: collapse;">
    <tr style="background-color: #e0e0e0;">
        <th>Metric</th>
        <th>Value</th>
        <th>Interpretation</th>
    </tr>
    <tr>
        <td><b>PSNR (dB)</b></td>
        <td>{psnr:.2f}</td>
        <td>{'Excellent (> 40 dB)' if psnr > 40 else 'Good (30-40 dB)' if psnr > 30 else 'Detectable'}</td>
    </tr>
    <tr>
        <td><b>MSE</b></td>
        <td>{mse:.4f}</td>
        <td>{'Imperceptible' if mse < 1 else 'Very Low' if mse < 5 else 'Low'}</td>
    </tr>
    <tr>
        <td><b>Avg Pixel Diff</b></td>
        <td>R: {r_diff:.2f}, G: {g_diff:.2f}, B: {b_diff:.2f}</td>
        <td>{'Undetectable by eye' if max(r_diff, g_diff, b_diff) < 3 else 'Barely visible'}</td>
    </tr>
    <tr>
        <td><b>Max Pixel Diff</b></td>
        <td>{max_diff}</td>
        <td>{'Excellent' if max_diff < 10 else 'Good' if max_diff < 20 else 'Moderate'}</td>
    </tr>
</table>

<h4>Detection Limit Analysis:</h4>
<ul>
    <li><b>Visual Detection:</b> {'✗ Impossible - Changes are imperceptible' if psnr > 40 else '⚠️ Very Difficult' if psnr > 30 else '✓ Possible with careful inspection'}</li>
    <li><b>Statistical Detection:</b> {'✗ Very Difficult - Low statistical signature' if mse < 1 else '⚠️ Difficult - Moderate signature' if mse < 5 else '✓ Possible with advanced tools'}</li>
    <li><b>Histogram Analysis:</b> {'✗ Undetectable - Minimal distribution change' if max_diff < 10 else '⚠️ Difficult to detect' if max_diff < 20 else '✓ May show patterns'}</li>
</ul>

<p><b>Conclusion:</b> {'Excellent steganography - virtually undetectable!' if psnr > 40 and mse < 1 else '✓ Good steganography - difficult to detect' if psnr > 30 else '⚠️ Moderate - detectable with advanced analysis'}</p>
"""
            
            self.analysis_results.setHtml(results)
            self.status_label.setText("✓ Analysis complete!")
            
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Failed to analyze images:\n{str(e)}")

def main():
    app = QApplication(sys.argv)
    window = DCTDMApp()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()