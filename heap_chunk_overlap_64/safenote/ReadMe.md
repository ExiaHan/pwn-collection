xnuca pwn500

程序中实现了自己一套堆保护机制。

包括如下：

* 堆指针异或随机数后存储，防止unlink利用
* malloc时检查读入长度，避免溢出
* free时将下块的pre_size修改为无效值，在下块free时恢复该pre_size以便正常的块合并


利用思路：

利用free恢复pre_size的机制造成chunk overlap

具体利用如下：

1. 申请0x400(块0)，0x100(块1)
2. 删除块0，此时块1中pre_size被修改为无效值，并将真正长度保存在块中。
3. 申请0x100(块0)，0x100(块2)，0x100(块3)
4. 释放块0，释放块1，此时0x400被恢复到块1的pre_size处，因此将与前面0x400大小的块进行合并。
5. 申请0x500(块0)，此时块0完全覆盖块2，块3
6. 申请0x100(块1)，0x100(块4)，0x100(块5)
7. 修改块0内容避免\0截断，后打印块内容，可打印出块2保存的av->unsortedbin值，对应可算出main_arena值（64位为-88处）。（main_arena 是__malloc_hook 下紧挨着的变量，IDA中x可以看到大量lea指令在引用）。
8. 修改块0从而恢复块2内容，free块2
9. 修改块0覆盖块2 bk为global_max_fast - 0x10，申请0x100(块2)，形成unsorted bin attack，将global_max_fast覆盖为较大整数（实际是unsortedbin地址），使接下来的分配均使用fastbin。（global_max_fast在malloc_set_state()赋值，可根据引用确定其数据区地址）
10. 释放块3，释放块2，此时块2的fd指向块3
11. 修改块0避免\0截断，打印块内容，泄露块2中fd值，从而得到堆地址。
12. 修改块覆盖块2的为bss段的值，bss段中会保存堆大小，故容易找到含有0x100可用来伪造fastbin堆块的地址。申请0x100(块2)，0x100(块3)。形成fastbin attack，此时块3指向bss区域
13. 修改块3避免\0截断，打印块内容，泄露出bss段的数据，得到堆指针异或后的值，和之前泄露的堆地址结合计算，得到异或key的值。
14. 修改块3覆盖块5的指针，为free@got
15. 修改块5为system值，free -> system
16. 修改块0将块2的数据修改为/bin/sh
17. 释放块2，调用system(/bin/sh)得到shell