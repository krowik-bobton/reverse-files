all:
	nasm -f elf64 src/reverse.asm -o reverse.o
	ld -o reverse reverse.o

clean:
	rm -f reverse reverse.o