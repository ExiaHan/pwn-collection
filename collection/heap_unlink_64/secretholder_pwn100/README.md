hitcon pwn100

程序只能固定申请huge, big, small三种类型的块。

huge会以mmap形式分析，但free后再申请会使用topchunk。

因此可以如下触发double free:

1. 申请small,big
2. 释放small,big
3. 申请huge并伪造堆块
4. 第二次释放 big 造成unlink，使huge指针指向bss段，修改指针达到任意读写，同时可覆盖所有edit flag值，使三个指针均可以renew

进一步拿到shell：

1. 将free@got修改为puts@plt，将big指针修改为puts@got， free big从而得到puts的libc地址
2. 将free@got修改为system, free huge起shell（huge先填充为/bin/sh）