import Options, Utils, sys
from os import unlink, symlink, popen
from os.path import exists, islink

srcdir = '.'
blddir = 'build'
VERSION = '0.0.1'

def set_options(ctx):
    ctx.tool_options('compiler_cxx')

def configure(ctx):
    ctx.check_tool('compiler_cxx')
    ctx.check_tool('node_addon')

def build(ctx):
    if sys.platform.startswith("sunos"):
        platc = 'ife-dlpi.cc'
    elif sys.platform.startswith("darwin"):
        platc = 'ife-bpf.cc'
    elif sys.platform.startswith("freebsd"):
        platc = 'ife-bpf.cc'
    elif sys.platform.startswith("linux"):
        platc = 'ife-sockpacket.cc'
        
    t = ctx.new_task_gen('cxx', 'shlib', 'node_addon')
    t.target = 'IFEBinding'
    t.source = ['IFE.cc', 'ife-icmp-support.cc', platc]
