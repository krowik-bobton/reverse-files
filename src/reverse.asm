section .data
  ; System call constants :
  SYS_OPEN equ 2                ; file open
  SYS_EXIT equ 60               ; exit program
  SYS_FSTAT equ 5               ; get file status
  SYS_MMAP   equ 9              ; map file to memory
  SYS_MUNMAP equ 11             ; unmap memory-mapped file
  SYS_MSYNC  equ 26             ; synchronize changes in mapped memory to file
  SYS_CLOSE  equ 3              ; close file

  ; parameters for sys_mmap :
  PROT_READ  equ 1              ; permission to read
  PROT_WRITE equ 2              ; permission to write
  MAP_SHARED equ 1              ; shared mapping (changes visible in file)

  ; parameter for sys_open :
  O_RDWR equ 2                  ; open for reading and writing

  ; bit masks for file types (from sys_stat structure) :
  S_IFMT    equ 0o170000        ; mask for file type
  S_IFREG   equ 0o100000        ; value indicating that the file is of regular type
                                ; meaning it can be reversed

  ; Constants for memory sizes :
  PAGE_SIZE equ 4096            ; standard page size (4KB)
  CHUNK_SIZE equ 0x100000       ; size of the mapped chunks (1MB)

global _start

section .text
    ; Local variables (kept on stack):
    %define ptr_block_left          rbp - 8   ; pointer to the start of the left block
    %define ptr_block_right         rbp - 16  ; pointer to the start of the right block (as above)

    %define ptr_block_right_orig    rbp - 24  ; original pointer to right block
                                              ; (returned by sys_mmap)
    %define ptr_block_left_orig     rbp - 32  ; original pointer to left block
                                              ; (returned by sys_mmap)

    %define size_block_left         rbp - 40  ; size of the left mapping
    %define size_block_right        rbp - 48  ; size of the right mapping
    %define stat_buffer             rbp - 192 ; buffer for the stat structure returned by fstat (144 bytes)

_start:
    push rbp
    mov rbp, rsp
    sub rsp, 192          ; reserve space for local variables, 144 for stat_buffer
                          ; and 48 for pointers and block sizes

.open_file:
    ; Parameters passed to the program are on the stack starting at rsp (rbp stores its initial value).
    mov rcx, [rbp + 8]    ; Load into rcx the number of passed parameters
    cmp rcx, 2            ; Check if there are only two parameters
                          ; Where the first one will be the name of this program
                          ; And the second is the name of the file to reverse.
    jne .exit_error     ; If there aren't two parameters, error.

    ; in [rbp + 24] the name of the file to reverse is stored. We open it:
    mov rax, SYS_OPEN     ; rax = info about using sys_open
    mov rdi, [rbp + 24]   ; rdi = name of the given file.
    mov rsi, O_RDWR       ; rsi = info about permissions (reading and writing)
    mov rdx, 0            ; rdx = mode (0, meaning irrelevant)
    syscall               ; call sys_open with the above parameters.

    ; if sys_open ended with failure then rax has a negative value
    cmp rax, 0
    jl .exit_error   ; if rax < 0 then end execution (we don't close the file because it didn't open)

    ; if sys_open succeeded, then in rax is the file descriptor, by which
    ; we refer to the opened file.
    mov r12, rax                  ; in r12 we store the file descriptor

; After opening the file, we check if it's a "regular" file (possible to reverse)
; and if so, whether it has a number of bytes greater than or equal to 2. If so then
; we proceed to reversing the file.
.check_file_properties:
    ; gather statistics about the file using sys_fstat:
    mov rax, SYS_FSTAT
    mov rdi, r12                  ; rdi = file descriptor (kept in r12)
    lea rsi, [stat_buffer]        ; rsi = pointer to buffer for the result struct
    syscall

    ; check if successful:
    cmp rax, 0
    jl .cleanup_exit              ; if unsuccessful then close file and end


    ; Check if this file is of regular type
    mov eax, [stat_buffer + 24]   ; here the file type is stored
    and eax, S_IFMT               ; isolate the file type
    cmp eax, S_IFREG              ; check if regular
    jne .cleanup_exit             ; if not then close file and end

    ; Since we're here the file is regular. If it has < 2 bytes we don't reverse it.
    ; file size is stored at position 48 in the returned structure
    mov r13, [stat_buffer + 48]   ; save file size to r13
    cmp r13, 2
    jb .success_exit              ; if it has less than 2 bytes, success.

.init_pointers:
    ; initialization of pointers to the start and end of the file
    mov r14, 0                    ; start = r14 = 0 (first byte)
    mov r15, r13                  ; end = r15 = file size
    dec r15                       ; r15 = end = file size - 1 (start of the last byte)

    ; Count the number of bytes between start and end (inclusively)
    mov rax, r15                  ; rax = end
    sub rax, r14                  ; rax = end - start
    inc rax                       ; rax = end - start + 1
                                  ; that's how many bytes are between start and end (inclusively)

    ; check if we can map LEFT (1MB) and RIGHT(1MB), so that
    ; the parts don't overlap :
    mov rdi, CHUNK_SIZE
    shl rdi, 1                    ; rdi = CHUNK_SIZE * 2
    cmp rax, rdi
    jb .reverse_small_part        ; if smaller, then we must jump to reversing
                                  ; a small file (a part of the file, having less than 2MB)

; Since we're here we must reverse 1MB from the front and back until we get
; a middle part smaller than 2MB.
.main_loop:
    ; for sys_mmap, the given file offset must be a multiple of PAGE_SIZE
    ; we must calculate the appropriate values that we'll pass to sys_mmap and
    ; remember the index offsets relative to those from which we want to start
    ; reversing. The following example illustrates this (on a smaller scale):
    ; we want to map bytes from the one at position nr 5 to the one at position
    ; number 5000 (we are indexing from 0). So the file offset we'll pass to sys_mmap
    ; will be 0, because this is the rounding of 5 down to a multiple of
    ; page_size. So we'll map 0 to 5000 bytes of the file, but
    ; we want to use only the mapping from 5 to 5000, so
    ; we must remember:

    ; [ptr_block_left] -> start of mapped block + shift
    ;                   (in the example the shift equals 5).
    ; [ptr_block_left_orig] -> address of the start of the mapped block
    ;                   (value of rax after successful execution of sys_mmap)
    ; [size_block_left] -> length of the mapped block (from 0 to 5000).
    ; analogously for right blocks.

    ; compute left offset and shift
    mov rax, r14                      ; rax = start
    xor rdx, rdx                      ; rdx = 0, clearing
    mov rcx, PAGE_SIZE                ; rcx = divisor = PAGE_SIZE
    div rcx                           ; rax = start / PAGE_SIZE (floor)
    mul rcx                           ; rax = (start / PAGE_SIZE) * PAGE_SIZE
    ; now, rax contains file offset that we pass to sys_mmap
    mov r9, rax                       ; r9 = file offset
    mov rbx, r14
    sub rbx, r9                       ; rbx = start - file offset = shift

    ; mapping the LEFT block
    mov rax, SYS_MMAP
    mov rdi, 0                        ; addr = NULL (default)
    mov rsi, CHUNK_SIZE
    add rsi, rbx                      ; mapping length = CHUNK_SIZE + shift
    mov rdx,  PROT_READ | PROT_WRITE  ; both reading and writing
    mov r10, MAP_SHARED               ; shared mapping (changes visible in file)
    mov r8, r12                       ; r8 = r12 = file descriptor
    ; r9 already holds the file offset
    syscall

    ; in case of success, mmap returns (to rax) a pointer to the mapped area
    ; negative rax is an error.
    cmp rax, 0
    jl .cleanup_exit                  ; if rax < 0 then error

    ; if success, then we remember the needed data
    mov [ptr_block_left_orig], rax
    add rax, rbx                      ; add shift
    mov [ptr_block_left], rax
    ; rsi holds CHUNK_SIZE + rbx (as we passed when calling sys_mmap)
    mov [size_block_left], rsi


    ; mapping the RIGHT block
    ; we must calculate the start of the right block in the file.
    ; it will be: end - CHUNK_SIZE + 1
    mov r11, r15                      ; r11 = end
    sub r11, CHUNK_SIZE               ; r11 = end - CHUNK_SIZE
    inc r11                           ; r11 = end - CHUNK_SIZE + 1
    ;we must align it down to PAGE_SIZE
    mov rax, r11
    xor rdx, rdx
    mov rcx, PAGE_SIZE
    div rcx                           ; rax = r11 / page_size (floor)
    mul rcx                           ; rax = (r11 / PAGE_SIZE) * PAGE_SIZE
    mov r9, rax                       ; in r9 we now have the aligned offset

    ; Calculate how many bytes "too early" the offset is (calculate the shift)
    mov rbx, r11                      ; r11 = original offset in the file
    sub rbx, r9                       ; r9 = rounded down offset.
    ; now rbx holds the shift

    ; map the right block :
    mov rax, SYS_MMAP
    mov rdi, 0
    mov rsi, rbx
    add rsi, CHUNK_SIZE               ; rsi = CHUNK_SIZE + shift (mapping length)
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8, r12                       ; r8 = r12 = file descriptor
    ; r9 already has the offset
    syscall

    ; If it succeeded, then rax holds the address to the mapped memory,
    ; if it didn't succeed then rax is negative.
    cmp rax, 0
    jl .cleanup_exit                  ; rax < 0, end program

    mov [ptr_block_right_orig], rax   ; save original pointer
    mov rsi, rbx
    add rsi, CHUNK_SIZE               ; rsi = shift + CHUNK_SIZE
    mov [size_block_right], rsi       ; save mapping length

    add rax, rbx                      ; shift the mapping address by the shift
    mov [ptr_block_right], rax        ; save address


    ; At this moment we have mapped left and right blocks, each with length
    ; 1MB (due to rounding, their length may be greater). We must
    ; swap corresponding bytes of the left and right block in a loop.
    ; loop index i is kept in rcx.
    xor rcx, rcx           ; i = 0

.swap_blocks_loop:
    cmp rcx, CHUNK_SIZE
    jge .after_swapping               ; if i>=CHUNK_SIZE, end of loop

    ; Calculate the places that will be swapped
    ; p = ptr_block_left + i
    ; q = ptr_block_right + CHUNK_SIZE - i - 1
    mov rsi, [ptr_block_left]
    add rsi, rcx                      ; rsi = p = ptr_block_left + i

    mov rax, CHUNK_SIZE
    sub rax, rcx
    dec rax                           ; rax = CHUNK_SIZE - i - 1
    mov rdi, [ptr_block_right]
    add rdi, rax                      ; rdi = q = ptr_block_right + CHUNK_SIZE - i - 1

    ; swap the bytes
    mov al, [rsi]                     ; al is the last byte of eax
    mov ah, [rdi]                     ; ah is the second-to-last byte of eax
    mov [rsi], ah
    mov [rdi], al

    inc rcx
    jmp .swap_blocks_loop

.after_swapping:
    ; after swapping blocks, we must do sys_msync for each mapping, to
    ; be sure that the changes were applied
    ; We must also remove the mapping using sys_munmap

    ; sys_msync for the left block
    mov rax, SYS_MSYNC
    mov rdi, [ptr_block_left_orig]          ; starting address of mapping
    mov rsi, [size_block_left]              ; mapping length
    mov rdx, 0                              ; no special flags
    syscall
    cmp rax, 0
    jl .cleanup_exit                        ; rax < 0, end with error.


    ; sys_msync for the RIGHT block
    mov rax, SYS_MSYNC
    mov rdi, [ptr_block_right_orig]         ; starting address of mapping
    mov rsi, [size_block_right]             ; mapping length
    mov rdx, 0                              ; no special flags
    syscall

    ; if failure, end with error
    cmp rax, 0
    jl .cleanup_exit

    ; free the mapping for the LEFT block using sys_munmap
    mov rax, SYS_MUNMAP
    mov rdi, [ptr_block_left_orig]          ; starting address of mapping
    mov rsi, [size_block_left]              ; mapping length
    syscall

    ; when failure, end with error
    cmp rax, 0
    jl .cleanup_exit

    ; free the mapping for the RIGHT block using sys_munmap
    mov rax, SYS_MUNMAP
    mov rdi, [ptr_block_right_orig]
    mov rsi, [size_block_right]
    syscall

    ; in case of failure, end with error
    cmp rax, 0
    jl .cleanup_exit

.main_loop_continue:
    ; we must update start and end
    add r14, CHUNK_SIZE                    ; start += CHUNK_SIZE
    sub r15, CHUNK_SIZE                    ; end -= CHUNK_SIZE

    ; count how many unreversed bytes are between start and end (inclusively)
    mov rax, r15
    sub rax, r14
    inc rax                                ; rax = end - start + 1

    ; check if there is >= (2 * CHUNK_SIZE) of bytes left to reverse
    mov rsi, CHUNK_SIZE
    shl rsi, 1
    cmp rax, rsi
    jge .main_loop                         ; if so, then next iteration of the loop

; If we're here, then potentially there's a small (< 2MB) unreversed
; part of the file in the middle.

.reverse_small_part:
    ; count how many bytes of the unreversed part there are
    mov rax, r15
    sub rax, r14
    inc rax                                ; rax = r15 - r14 + 1
    ; rax now has the size of the part that remains to be reversed

    ; when the number of middle bytes is less than or equal to 1, do nothing.
    cmp rax, 1
    jle .success_exit ;

    mov rbx, rax      ; rbx, now has the size of the part that remains to be reversed

    ; We must map the remaining area, but first just like before,
    ; we round the file offset to a multiple of page_size
    mov rax, r14                           ; rax = start
    xor rdx, rdx                           ; rdx = 0
    mov rcx, PAGE_SIZE                     ; rcx = PAGE_SIZE
    div rcx                                ; rax = start / PAGE_SIZE (floor)
    mul rcx                                ; rax *= PAGE_SIZE
    mov r9, rax                            ; r9 holds the aligned offset

    mov rsi, r14
    sub rsi, r9       ; rsi = start - aligned offset = shift

    ; mapping length = shift + length
    mov rax, rsi      ; rax = shift
    add rax, rbx      ; rax = shift + length

    mov [size_block_left], rax            ; save block size

    ; map the block (we are treating it as the left block)
    mov rax, SYS_MMAP
    mov rdi, 0
    mov rsi, [size_block_left]            ; total length
    mov rdx, PROT_READ | PROT_WRITE
    mov r10, MAP_SHARED
    mov r8, r12                           ; r12 contains the file descriptor
    ; r9 already holds the aligned offset
    syscall

    ; in case of failure we exit with code 1
    cmp rax, 0
    jl .cleanup_exit

    ; if mapping succeeded then rax = mapping address
    ; just like in the main loop we save the mapping address
    mov [ptr_block_left_orig], rax
    add rax, r14                          ; rax += start
    sub rax, r9                           ; rax -= aligned offset
    mov [ptr_block_left], rax             ; user address

    ; reverse the block bytes in a loop.
    mov rdx, rbx                          ; rdx = rbx = size of the area being reversed
    shr rdx, 1                            ; rdx = area size / 2
    xor rcx, rcx                          ; i = 0, we iterate with this

.reverse_center_loop:
    cmp rcx, rdx                          ; if( i >= length / 2) end of loop
    jge .after_center_reverse

    ; swap bytes p and q :
    ; p = [ptr_block_left] + i
    ; q = [ptr_block_left] + area length - i - 1

    ; calculate p
    mov rsi, [ptr_block_left]             ;p = [ptr_block_left]
    add rsi, rcx                          ; rsi = p = [ptr_block_left] + i

    ; calculate q
    mov rax, rbx                          ; rax = area length
    sub rax, rcx                          ; rax = area length - i
    dec rax                               ; rax = area length - i - 1
    mov rdi, [ptr_block_left]             ; rdi = [ptr_block_left]
    add rdi, rax                          ; rdi = q = [ptr_block_left] + rax

    ; swap bytes
    mov al, [rsi]
    mov ah, [rdi]
    mov [rsi], ah
    mov [rdi], al

    ; i++
    inc rcx
    jmp .reverse_center_loop

.after_center_reverse:
    ; we must synchronize the changes using sys_msync
    mov rax, SYS_MSYNC
    mov rdi, [ptr_block_left_orig]         ; mapping address
    mov rsi, [size_block_left]             ; mapping length
    mov rdx, 0                             ; no special flags
    syscall

    cmp rax, 0
    jl .cleanup_exit                       ; if it didn't succeed, exit with 1

    ; remove the middle mapping
    mov rax, SYS_MUNMAP
mov rdi, [ptr_block_left_orig]             ; mapping address
    mov rsi, [size_block_left]             ; mapping length
    syscall

    cmp rax, 0
    jl .cleanup_exit                       ; if error, then exit

; we have different program termination scenarios:
; 1) file opened, everything successful, we have to close the file and
; end program with signal 0
.success_exit:

    ; close the file
    mov rax, SYS_CLOSE
    mov rdi, r12                           ; file descriptor
    syscall
    cmp rax, 0                             ; if it didn't succeed then error.
    jl .exit_error

    mov rax, SYS_EXIT
    xor rdi, rdi                           ; rdi = 0 (exit code)

    mov rsp, rbp
    pop rbp

    syscall

; 2) file opened, but something went wrong in the meantime
.cleanup_exit:
    ; close file
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall
; proceed below to end program with signal 1

; 3) if error was detected before / during file opening or during closing
.exit_error:
    ; exit with signal 1 (error)
    mov rax, SYS_EXIT
    mov rdi, 1

    mov rsp, rbp
    pop rbp

    syscall