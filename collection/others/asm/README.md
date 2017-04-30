本题实现了一个汇编器，输入为汇编代码，输出为自定义的二进制文件。

要pwn的程序是该二进制文件的解释器。

漏洞位置在push和pop指令的处理上。

关键点：

* 通过lea指令可以泄漏全局变量地址，从而过PIE。
* 通过修改sp指针，利用push可以写大于堆地址的内存（即栈），利用pop可以读小于堆地址的内存（即bss段）
* bss段有全局变量保存了栈地址，利用pop读取后，再利用push向栈中写入ROP链
* 程序开启了PIC，调用plt函数时需要恢复ebx寄存器
* ROP链：pop_ebx_ret, ebx, dlsym@plt, pop2ret, 0, "system", call eax, "/bin/sh"