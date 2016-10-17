UAF，同时开了PIE

输入姓名的时候使用20个A，
show的时候会返回姓名后面的值，其中第一个是堆地址，第二个是show函数地址，可以用来过PIE。

买weapon后不断attack，weapon可用数为0时会free掉，指针没有清0，因此存在UAF。
comment函数刚好可以用来申请新堆块，覆盖原来weapon的攻击函数，可以控EIP。

这里直接将EIP控到0x0A14这个位置，会直接发生栈溢出，构造ROP链即可。
开了PIE后直接调plt函数会出现错误，因为PIE需要EBX寄存校正。
ROP链中不能用plt函数，只能用二进制文件中普通函数（感觉应该有能直接用plt函数的姿势，比如怎么设置一个ebx什么的。。）
weapon的攻击函数可以puts，读用0x0B62 这个函数。
