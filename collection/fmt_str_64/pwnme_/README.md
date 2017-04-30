Show处有明显的fsb漏洞。

通过泄露rbp可以得到栈地址。泄露puts@got可以得到libc基址，发现和kali 2.0中自带libc一样，可以直接计算出system地址。

不过RELOC full打开，所以不能覆写got。
这里通过rbp算出返回地址的值，使用%hn写入低位，可以控制RIP到一个栈溢出的位置，但发现RDX此时的值太大了，以至于read总会返回-1。


最终找到00400B38，将RIP截持到这儿，而读入的buf指针是栈中的值，可好可以用password控制，将这个原本指向堆的指针也指向栈，可以读入0x12c字节。形成栈溢出。

由于栈地址已知，可以直接将/bin/sh串布置在栈里，libc前面已经泄露了基址，直接pop rdi后call system可以起shell了。

（edit中存在整数溢出后memcpy栈溢出，利用比上述要简单一些）
