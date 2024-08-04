from pwn import *
context.log_level   ='debug'
context.arch        ='amd64'
'''
Libc Lib:
    https://libc.rip/
'''
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
import sys
DEBUG = False if len(sys.argv) > 1 else True
if DEBUG:
    p=process('./challenge',env={"LD_PRELOAD":"../libc.so.6"})
else:
    p = remote("0.0.0.0",31337)
ru 		= lambda a: 	p.readuntil(a)
r 		= lambda n:		p.read(n)
sla 	= lambda a,b: 	p.sendlineafter(a,b)
sa 		= lambda a,b: 	p.sendafter(a,b)
sl		= lambda a: 	p.sendline(a)
s 		= lambda a: 	p.send(a)
def num(x):
    return str(x).encode()
def cmd(c):
    sla("",num(c))
def leak(a,x=0,mute=0):
    ru(a)
    if x: # when to stop
        leaked = int(ru(x)[:-1],16)
    else:
        leaked = u64(p.read(6)+b'\0\0')
    if mute!=0:
        warn(hex(leaked))
    return leaked
def debug(script):
    if DEBUG:
        gdb.attach(p,script)

debug('bof ')
# libc = ELF("../libc.so.6")

# libc.address = base
# rop     = ROP(libc)
# rdi     = rop.find_gadget(['pop rdi','ret'])[0]
# ret     = rdi+1
# sh_str  = libc.search(b"/bin/sh\0").__next__()
# system  = libc.sym['system']
# chain   = [rdi,sh_str,system]



# sl("./submitter 1")
p.interactive()
