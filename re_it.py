# coding:utf-8

import angr
import simuvex

# This shows how to use angr to solve crackme.

# 新建project 
p = angr.Project("./test", load_options={"auto_load_libs":False})    # 禁用加载库会比较快

# p.loader是加截binary相关的接口
# 如读某些字节
''.join(p.loader.memory.read_bytes(addr, size))
# 反编译
p.arch.capstone.disasm(insn_bytes, addr)

################################################################
# 生成state或者path。

# entry点
s = p.factory.entry_state()  

# 在某个固定地址开始进行符号执行。 禁用LAZY_SOLVES可以避免生成太多无关路径
s = p.factory.blank_state(addr=0x400780, remove_options={simuvex.o.LAZY_SOLVES})   

# path可以用于设置argv, envp值，path默认从entry_state生成
argv1 = angr.claripy.BVS("argv1",100*8, ) # bit-vector
s = p.factory.path(args=["./crackme1",argv1], env={"HOME": "/home/angr"})

################################################################
# 修改state（内存或者寄存器）
s.mem[0x6030a0:] = s.se.BVS("c", 32) # bit-vector. name='c', size=32 (in bit)
s.memory.store(addr , state.se.BVS("name", 8*32))
s.memory.store(addr , struct.pack("<I", int_value))

s.regs.rdi = 0x6030a0                # BV64 0x6030a0
s.regs.rdi._model_concrete.value     # 获取具体值

# 压栈
s.stack_push(256)              # buffer size: 256
s.stack_push(s.regs.esp + 20)      # buffer: space on previous stack frame
s.stack_push(exec_sink)   # return address: terminate execution

################################################################
# hook 
def strtol(state):
	# We return an unconstrained number here
	global unconstrained_number
	unconstrained_number = state.se.BVS('strtol', 64)
	# Store it to rax
	state.regs.rax = unconstrained_number

# length是hook后跳过多少字节，可设置为0，表示继续执行原来的指令（不替换）
p.hook(0x4004a7, strtol, length=5)

def patch_scanf(state):
		print(state.regs.rsi)
		state.mem[state.regs.rsi:] = state.se.BVS('c', 8)

# 可以由IDA看到
scanf_offsets = (0x4d, 0x85, 0xbd, 0xf5, 0x12d, 0x165, 0x19d, 0x1d5, 0x20d, 0x245, 0x27d, 0x2b5, 0x2ed)

init = p.factory.blank_state(addr=main)
# Patch 掉 main中的所有scanf
for offst in scanf_offsets:
	p.hook(main + offst, func=patch_scanf, length=5)

# 直接使用函数摘要替换某些函数，比如对于静态编译的文件，使用函数摘要可以加块速度
p.hook(0x2398, simuvex.SimProcedures['libc.so.6']['malloc'])
p.hook(0x4018B0, simuvex.SimProcedures['libc.so.6']['__libc_start_main'])
p.hook(0x422690, simuvex.SimProcedures['libc.so.6']['memcpy'])
p.hook(0x408F10, simuvex.SimProcedures['libc.so.6']['puts'])

################################################################
# 生成path_group， 线程数主要对Z3有用。
pg = p.factory.path_group(s, threads=4)  

# 符号执行.  find表示找到的路径，avoid表示避开的路径，参数境均可以为list
pg.explore(find=0x4020DF, avoid=0x4020FE)

def correct(path):
	try:
		return 'Password OK' in path.state.posix.dumps(1)
	except:
		return False
def wrong(path):
	try:
		return 'Password Incorrect' in path.state.posix.dumps(1)
	except:
		return False
# find和avoid也可以是自定义回调函数，参数为path
pg.explore(find=correct, avoid=wrong)

# 也可以一层一层explore， 每次只保存found，把avoid去掉。
pg.explore(find=0x4016A3).unstash(from_stash='found', to_stash='active')
pg.explore(find=0x4016B7, avoid=[0x4017D6, 0x401699, 0x40167D]).unstash(from_stash='found', to_stash='active')
pg.explore(find=0x4017CF, avoid=[0x4017D6, 0x401699, 0x40167D]).unstash(from_stash='found', to_stash='active')
pg.explore(find=0x401825, avoid=[0x401811])

################################################################
# 呼出ipython 方便调试用
import IPython; IPython.embed()

################################################################
# 处理结果状态
found_state = pg.found[0].state

found_state.se.any_str(found_state.memory.load(0x6030a0, 32)) # 输出内存
found_state.posix.dumps(0) # dump stdin
found_state.posix.dumps(1) # dump stdout


# 完整示例
import angr
import simuvex


def common_test(filename, find, avoid):
	p = angr.Project(filename, load_options={"auto_load_libs": False})
	s = p.factory.entry_state(remove_options={simuvex.o.LAZY_SOLVES})

	pg = p.factory.path_group(s)
	pg.explore(find=find, avoid=avoid) 
	print pg.found[0].state.posix.dumps(0) # stdin   

def common_test2(filename, find, avoid):
	p = angr.Project(filename, load_options={"auto_load_libs": False})
	s = p.factory.entry_state(remove_options={simuvex.o.LAZY_SOLVES})

	argv1 = angr.claripy.BVS("argv1",100*8, ) # bit-vector
	s = p.factory.entry_state(args=[filename,argv1], remove_options={simuvex.o.LAZY_SOLVES})

	pg = p.factory.path_group(s)
	pg.explore(find=find, avoid=avoid) 
	print pg.found[0].state.se.any_str(argv1) 

def sample2():

	b = angr.Project("very_success", load_options={"auto_load_libs":False})
	s = b.factory.blank_state(addr=0x401084, remove_options={simuvex.o.LAZY_SOLVES})
	
	# 添加处理栈上的参数
	s.mem[s.regs.esp+12:] = s.se.BVV(40, s.arch.bits)
	s.mem[s.regs.esp+8:].dword = 0x402159
	s.mem[s.regs.esp+4:].dword = 0x4010e4
	s.mem[s.regs.esp:].dword = 0x401064

	# 将input设置为一个符号值
	s.mem[0x402159:] = s.se.BVS("ans", 8*40)
	
	# explore
	pg = b.factory.path_group(s, immutable=False)
	pg.explore(find=0x40106b, avoid=0x401072)

	# 输出结果
	found_state = pg.found[0].state
	return found_state.se.any_str(found_state.memory.load(0x402159, 40))

if __name__ == '__main__':
	common_test2('./a.out', 0x00400560 , 0x0040056C)