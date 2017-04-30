## GMIC CTF 2017 线下赛

* `snprintf` 格式化串漏洞。
* 循环下标越界形成栈溢出

### recur.py

1. 将`printf@got`覆盖成`leave ret`
2. 利用9次base64写入fmt串和溢出的ROP，由于snprintf的原因，ROP不能包含0x00
3. 第一段ROP： `puts(read@got)`, 返回到main。此时得到libc基址，可以调用任意libc函数了。但直接调用system(/bin/sh)会失败，因为snprintf第9次造成的溢出会覆盖环境变量。需要使用execve(/bin/sh, 0, 0)。
4. 第二段ROP： `gets(bss), pop ebp, leave ret`。向bss段写入第三段ROP，同时`stack pivot`到bss段上去。gets不会产生0x00截段，可以用来execve了
5. 第三段ROP：直接execve(/bin/sh, 0, 0)


### recur2.py

只利用格式化串。

1. 利用格式化串将`strlen@got`覆盖成`printf`， `strspn@got`覆盖成`main`，这样调用`is_b64string(input)`时会直接`printf(input)`并返回到`main`，形成`read -> printf -> main -> fflush -> read ...`的循环。
2. 之后变成通用的栈可控的格式化串。
3. `printf(%p, read@got)`得到libc基址
4. 再将`strlen@got`覆盖成`system`，输入/bin/sh时执行strlen(/bin/sh)得到shell