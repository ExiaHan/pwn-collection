
写入feedback时未验证长度（只采用\n截断）导致堆溢出。  
同时free时author指针未置0，可以double free。

### 只使用堆溢出

申请块A  
申请块B  
溢出A，在A中伪造块头（fk,bk)      溢出到B中置A中伪造块为空闲。   
free B，导致A中伪造块unlink。全局数据区任意读写。

读atoi@got值， 写入system。


### 只使用double free
申请块A   
申请块B  
释放块A  
释放块B 
申请块C大小等于A+B  
在C中伪造块头(fk,bk)  ，在原B块位置设置伪造块空闲，再次free B。   
产生伪造块unlink，达到任意读写。    

读atoi@got值， 写入system。