
使用64位通用gadget置rdx为8

泄漏地址，bss写入/bin/sh串，重写write@got为system，最后调用write@plt（即system)

