# File Reverser (x86-64 Assembly)

Low-level Assembly program for reversing file contents with
low RAM usage. Designed for educational purposes.

## Key features
* **Low resource usage:** Despite possibly huge size of the provided file, program uses constant RAM (~2MB for mapped memory blocks).
* **Linux syscalls:** Directly invokes Linux system calls: `sys_mmap`, `sys_msync`, `sys_fstat`.

## Applied strategy
1. **Large Files (Unprocessed part ≥ 2MB):**
   * The program maps the first 1MB and the last 1MB of the remaining part using `sys_mmap`.
   * It performs a byte-for-byte swap between these two mapped regions.
   * This process continues iteratively.

2. **Small Files / Remaining Center (< 2MB):**
   * The remaining middle section (or the entire small file) is mapped into memory at once.
   * A standard single-pointer loop reverses this final segment.

3. **Error Handling:**
   * Any system call failure results in an immediate termination.
   * If provided file isn't reversible (e.g. directory), program signals an error.
   * The program exits with a status code of `1` to signal an error.

## How to use
1. Make executable file `reverse` using provided Makefile by typing following line in the terminal:
   ```bash
   make
   ```
2. Execute the program with the target path as an argument. 
   ```bash
   ./reverse <path_to_file>
   ```
**Note:** if number of paths to files is 0 or more than 1, program exits with a status code of `1` (error)
3. If you want to delete files added by Makefile, simply type:
  ```bash
  make clean
  ```

## Future Optimizations
1. The current version iteratively swaps single bytes. Performance could be improved by swapping entire 64-bit registers (after reversing them with `bswap`).
