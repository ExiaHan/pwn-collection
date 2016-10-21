LCTF pwn400


encrypt输出可以造成堆地址泄露

decrypt后会释放对象

comment填充进行UAF，根据泄露的堆地址伪造虚表

跳转到可栈溢出的地址，然后ROP拿到shell

