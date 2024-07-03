'''
- `sl(x)`: 发送一行数据。
- `sd(x)`: 发送数据。
- `sa(x, y)`: 发送数据直到遇到特定字符串。
- `sla(x, y)`: 发送一行数据直到遇到特定字符串.

- `rc(x)`: 接收指定长度的数据。
- `rl()`: 接收一行数据。
- `ru(x)`: 接收直到遇到特定字符串。

- `ita()`: 进入交互模式。
- `slc()`: 使用shellcraft生成shellcode并发送。
- `uu64(x)`: 将输入转换为64位无符号整数。
- `uu32(x)`: 将输入转换为32位无符号整数。
- `print_hex(bin_code)`: 打印二进制数据的十六进制表示形式。
- `gdba(x='')`: 如果未指定参数 'n',则附加GDB调试器。
- `getProcess()`: 根据参数返回远程连接或本地进程。

'''
from pwn import *

def getProcess(ip,port,name):
    global p
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
        p = remote(ip, port)
        return p
    else:
        p = process(name)
        return p

sl = lambda x: p.sendline(x)
sd = lambda x: p.send(x)
sa = lambda x, y: p.sendafter(x, y)
sla = lambda x, y: p.sendlineafter(x, y)
rc = lambda x: p.recv(x)
rl = lambda: p.recvline()
ru = lambda x: p.recvuntil(x)
ita = lambda: p.interactive()
slc = lambda: asm(shellcraft.sh())
uu64 = lambda x: u64(x.ljust(8, b'\0'))
uu32 = lambda x: u32(x.ljust(4, b'\0'))


def print_hex(bin_code):
    # 转换为十六进制字符串，并在每个字节之间添加空格
    hex_string_with_spaces = ' '.join(f'{byte:02x}' for byte in bin_code)
    print(hex_string_with_spaces)


def gdba(x=''):
    # 如果运行参数后面加了'n' 则不gdb
    if len(sys.argv) > 1:
        if sys.argv[1] == 'n':
            return
    if type(p) == pwnlib.tubes.remote.remote:
        return
    elif type(p) == pwnlib.tubes.process.process:
        gdb.attach(p, x)
        # print('',proc.pidof(p)[0])
        # gdb.attach(proc.pidof(p)[0])
        pause()

def log(message_int):
    success(hex(message_int))
