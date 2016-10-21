XNUCA pwn450

程序在0x400E76处设置了一个可以进行栈溢出的函数，需要将EIP控到该函数即可。

本题开启了Full RELRO，不能修改got，那么就考虑从伪造虚表入手。

不过程序会在全局数据区保存虚表的值，并在使用的时候检查，因此在修改虚表的同时要同时修改数据区对应的值。

关键漏洞点有两个，对应两种利用方法：

（1） public chat处malloc后读入存在堆溢出， 利用方法（test.py）

首先在name中伪选两个fastbin可用的堆块（块1指向块2）和虚表备用。

choose side 5次会一起释放一次。

得到free chunk后即可用public chat的溢出修改fd，指向name中的伪造块。

再choose side两次即可将这个object申请到name中的伪造块上去。

此时用options的rename修改object虚表。

public chat会申请到name中的第二个伪造块，可以修改数据区的虚表指针与前面相同过掉检查。

伪造的虚表指向栈溢出函数，接下来正常栈溢出ROP即可。

（2）public chat 保存malloc返回值的指针未初始化，输入无效长度时会跳过malloc直接free栈中的指针。可以利用house of spirit （test2.py）

首先在name中伪选两个fastbin可用的堆块（块1指向块2）和虚表备用。

在buy weapon函数中可以覆盖栈中的数据为块1的指针。

然后public chat时输出一个无效的size，即可将块1free到fast bin链表中。

choose side后则可将块1分配给object。

此时用options的rename修改object虚表。

public chat会申请到name中的第二个伪造块，可以修改数据区的虚表指针与前面相同过掉检查。

伪造的虚表指向栈溢出函数，接下来正常栈溢出ROP即可。
