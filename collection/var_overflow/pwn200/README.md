LCTF pwn200

give me money后可覆盖指针变量产生任意写。

利用：

1. 将free@got写为任意写函数的地址，然后选2，跳回函数，从而形成无限任意写
2. 将bss段写为shellcode，然后选2
3. 将free@got写为shellcode地址，然后选2 跳到shellcode处

（输入名字处可泄漏栈地址，直接向栈中写入shellcode然后利用任意写改返回地址更简单）