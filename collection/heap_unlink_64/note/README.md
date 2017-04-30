程序自带socket通信，为了方便调试patch了一下。

漏洞有多处：

1. new note 存在off-by-one写null
2. edit note 未检查指针合法性
3. delete note free后指针未置NULL

因此有多种利用方式：

1. 直接编辑free块的内容，伪造堆块。free后块触发unlink。 
2. 正常编辑伪造堆块，并利用off-by-one修改后块的INUSE标志位，free后块，触发unlink。
3. 申请2小块free掉，申请大块，内容伪造2个小块，double free第2小块，触发unlink。

unlink后有任意读写，即可泄露libc并修改free地址为system。
