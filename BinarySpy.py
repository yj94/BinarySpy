import tkinter as tk
from tkinter import filedialog, messagebox
import pefile
import os
import capstone

def va_to_rva(pe, va):
    image_base = pe.OPTIONAL_HEADER.ImageBase
    return va - image_base

def rva_to_offset(pe, rva):
    for section in pe.sections:
        if section.VirtualAddress <= rva < section.VirtualAddress + section.SizeOfRawData:
            return rva - section.VirtualAddress + section.PointerToRawData
    return None

def replace_text_section(pe_file_path, text_bin_path, va):
    pe = pefile.PE(pe_file_path)
    rva = va_to_rva(pe, va)
    file_offset = rva_to_offset(pe, rva)
    if file_offset is None:
        messagebox.showerror("错误", "无法找到对应的文件偏移，RVA 可能不在任何节区中。")
        return
    with open(text_bin_path, 'rb') as f:
        text_data = f.read()
    with open(pe_file_path, 'r+b') as f:
        f.seek(file_offset)
        f.write(text_data)
    messagebox.showinfo("成功", ".text节区已成功覆盖在PE文件中。")

def extract_text_section(pe_path, output_path):
    pe = pefile.PE(pe_path)
    if pe is None:
        messagebox.showerror("错误", "PE文件加载失败。")
        return
    for section in pe.sections:
        if b'.text' in section.Name:
            with open(output_path, 'wb') as f:
                f.write(section.get_data())
            messagebox.showinfo("成功", ".text节区已提取并保存。")
            return
    messagebox.showerror("错误", "没有找到.text节区")

def browse_file(entry, title, filetypes):
    file_path = filedialog.askopenfilename(title=title, filetypes=filetypes)
    if file_path:
        entry.delete(0, tk.END)
        entry.insert(0, file_path)

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def check_file_readable(file_path):
    return os.path.isfile(file_path) and os.access(file_path, os.R_OK)

def execute():
    modify_pe_file_path = modify_pe_file_entry.get()
    va_input = va_entry.get()
    text_or_pe_path = text_bin_path_entry.get()

    if not modify_pe_file_path or not text_or_pe_path:
        messagebox.showerror("错误", "输入不能为空。")
        return

    if not modify_pe_file_path.lower().endswith('.exe'):
        messagebox.showerror("错误", "待修改的PE文件必须是.exe格式。")
        return

    if not va_input:
        messagebox.showinfo("VA为空", "未检测到VA输入,启动自动化patch")
        va_input = find_main_function(modify_pe_file_path)
        va_input = hex(va_input)
        messagebox.showinfo("成功", f"获取到可能patch func va:{va_input}")
    
    if not is_hex(va_input):
        messagebox.showerror("错误", "VA输入必须是一个有效的十六进制数。")
        return

    va = int(va_input, 16)

    if text_or_pe_path.lower().endswith('.exe'):
        if not check_file_readable(text_or_pe_path):
            messagebox.showerror("错误", "PE文件不可读或不存在。")
            return
        text_bin_path = text_or_pe_path + ".text"
        extract_text_section(text_or_pe_path, text_bin_path)
    elif text_or_pe_path.lower().endswith('.text'):
        if not check_file_readable(text_or_pe_path):
            messagebox.showerror("错误", ".text文件不可读或不存在。")
            return
        text_bin_path = text_or_pe_path
    else:
        messagebox.showerror("错误", "提供的文件必须是PE文件或.text文件。")
        return
    
    replace_text_section(modify_pe_file_path, text_bin_path, va)

# 自动patch代码段
def find_main_function(pe_path):
    pe = pefile.PE(pe_path)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_point_va = entry_point_rva + pe.OPTIONAL_HEADER.ImageBase
    code_size = 0x100
    code_rva = entry_point_rva - 0x10
    code_va = code_rva + pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_memory_mapped_image()[code_rva:code_rva + code_size]
    code_asm = list(md.disasm(code, code_va))

    call_jmp_count = 0
    crt_addr = None
    for insn in code_asm:
        if insn.mnemonic == 'jmp':
            call_jmp_count += 1
            if call_jmp_count == 1:
                crt_addr = int(insn.op_str, 16)
                print(f'call jmp function VA: {insn.address:#x}\r\nOP_str: {insn.op_str}')
    return find_by_crt(pe_path, crt_addr)

def find_by_crt(pe_path, crt_addr):
    pe = pefile.PE(pe_path)
    crt_addr_rva = va_to_rva(pe, crt_addr)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    code_size = 0x300
    code_rva = crt_addr_rva - 0x10
    code_va = code_rva + pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_memory_mapped_image()[code_rva:code_rva + code_size]
    code_asm = list(md.disasm(code, code_va))

    crt_r8_addr = None
    crt_r8_addr_count = 0
    for insn in code_asm:
        if insn.mnemonic == 'mov' and 'r8' in insn.op_str and insn.op_str.find('r8') == 0:
            crt_r8_addr_count += 1
            if crt_r8_addr_count == 1:
                crt_r8_addr = insn.address
                print(f'CRT\'s mov r8 instruction VA: {crt_r8_addr:#x}\r\nOP_str: {insn.op_str}')
    return find_by_r8(pe_path, crt_r8_addr)

def find_by_r8(pe_path, crt_r8_addr):
    pe = pefile.PE(pe_path)
    crt_r8_addr_rva = va_to_rva(pe, crt_r8_addr)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    code_size = 0x50
    code_rva = crt_r8_addr_rva
    code_va = code_rva + pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_memory_mapped_image()[code_rva:code_rva + code_size]
    code_asm = list(md.disasm(code, code_va))

    main_addr = None
    main_addr_count = 0
    for insn in code_asm:
        if insn.mnemonic == 'call' and is_hex(insn.op_str):
            main_addr_count += 1
            if main_addr_count == 1:
                main_addr = int(insn.op_str, 16)
                print(f'main instruction VA: {insn.address:#x}\r\nOP_str: {insn.op_str}')
    return find_by_main(pe_path, main_addr)

def find_by_main(pe_path, main_addr):
    pe = pefile.PE(pe_path)
    crt_main_addr_rva = va_to_rva(pe, main_addr)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    code_size = 0x200
    code_rva = crt_main_addr_rva
    code_va = code_rva + pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_memory_mapped_image()[code_rva:code_rva + code_size]
    code_asm = list(md.disasm(code, code_va))

    patch_addr = None
    for insn in code_asm:
        if insn.mnemonic == 'call' and is_hex(insn.op_str):
            patch_addr = int(insn.op_str, 16)
            print("may patch:" + str(hex(patch_addr)))
            if filter_by_func_ret(pe_path, patch_addr):
                print(f'patch func instruction VA: {insn.address:#x}\r\nOP_str: {insn.op_str}')
                return patch_addr

def filter_by_func_ret(pe_path, patch_addr):
    pe = pefile.PE(pe_path)
    patch_addr_rva = va_to_rva(pe, patch_addr)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    code_size = 0x4000
    code_rva = patch_addr_rva
    code_va = code_rva + pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_memory_mapped_image()[code_rva:code_rva + code_size]
    code_asm = list(md.disasm(code, code_va))

    patch_retn_addr = None
    patch_addr_count = 0
    for insn in code_asm:
        if insn.mnemonic == 'ret':
            patch_addr_count += 1
            if patch_addr_count == 1:
                patch_retn_addr = insn.address
                print(f'patch func retn VA: {insn.address:#x}\r\nOP_str: {insn.op_str}')
    print(patch_retn_addr - patch_addr)
    return patch_retn_addr - patch_addr > 0x60

# 创建主窗口
root = tk.Tk()
root.title("BinarySpy")

# 创建界面元素
modify_pe_file_label = tk.Label(root, text="待修改的PE文件路径:")
modify_pe_file_label.pack()
modify_pe_file_entry = tk.Entry(root, width=50)
modify_pe_file_entry.pack()
modify_pe_file_button = tk.Button(root, text="浏览", command=lambda: browse_file(modify_pe_file_entry, "选择待修改的PE文件", [("PE文件", "*.exe")]))
modify_pe_file_button.pack()

va_label = tk.Label(root, text="要修改PE文件的VA (十六进制):")
va_label.pack()
va_entry = tk.Entry(root)
va_entry.pack()

text_or_pe_label = tk.Label(root, text="待覆盖的.text文件路径或待提取.text段的PE文件路径:")
text_or_pe_label.pack()
text_bin_path_entry = tk.Entry(root, width=50)
text_bin_path_entry.pack()
text_bin_path_button = tk.Button(root, text="浏览", command=lambda: browse_file(text_bin_path_entry, "选择待覆盖的.text文件或待提取的PE文件", [("所有文件", "*.*")]))
text_bin_path_button.pack()

execute_button = tk.Button(root, text="执行", command=execute)
execute_button.pack()

# 运行主循环
root.mainloop()
