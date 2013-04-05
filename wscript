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
    t = ctx.new_task_gen('cxx', 'shlib', 'node_addon')
    t.target = 'IFEBinding'
    t.source = ['IFE.cc', 'ife-icmp-support.cc']

    if sys.platform.startswith("sunos"):
        t.source.extend(['ife-dlpi.cc', 'arpcache-dlpi.cc'])
    elif sys.platform.startswith("darwin") or sys.platform.startswith("freebsd"):
        t.source.extend(['ife-bpf.cc', 'arpcache-ctlnet.cc'])
    elif sys.platform.startswith("linux"):
        t.source.extend(['ife-sockpacket.cc', 'arpcache-proc.cc'])
    elif sys.platform.startswith("windows"):
        t.source.extend(['ife-win32.cc', 'arpcache-none.cc'])
