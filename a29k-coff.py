# an example of a file loader in Python
# The scripting loader must define at least two functions: accept_file and load_file
# other optional functions are: save_file, move_segm, ...
#
# see also loader.hpp

import idaapi
from idc import *
import struct
import string
from collections import namedtuple

fmt_a29k_coff_big="AMD 29K coff (big-endian)"
fmt_a29k_coff_little="AMD 29K coff (little-endian)"

class Unpacker:
    fmt_filehdr = "HHlllHH"
    tup_filehdr = namedtuple('filehdr', 'magic nscns timdat symptr nsyms opthdr flags')

    fmt_sectionhdr = "8sLLLLLLHHL"
    tup_sectionhdr = namedtuple('sectionhdr', 'name paddr vaddr size scnptr relptr lnnoptr nreloc nlnno flags')

    fmt_reloc = "LLH"
    tup_reloc = namedtuple('reloc', 'vaddr symndx type')

    fmt_lineno = "LH"
    tup_lineno = namedtuple('lineno', 'addr lnno')

    fmt_sysent_name = "8sLhHBB"
    tup_sysent_name = namedtuple('sysent_name', 'name value scnum type sclass numaux')

    fmt_sysent_off = "LLLhHBB"
    tup_sysent_off = namedtuple('sysend_off', 'zeroes offset value scnum type sclass numaux')
    
    fmt_prefix = None

    def __init__(self, prefix):
        self.fmt_prefix = prefix
        
    def get_filehdr(self, fi):
        return self.perform(self.fmt_filehdr, self.tup_filehdr, fi)

    def get_sectionhdr(self, fi):
        return self.perform(self.fmt_sectionhdr, self.tup_sectionhdr, fi)

    def get_reloc(self, fi):
        return self.perform(self.fmt_reloc, self.tup_reloc, fi)

    def get_lineno(self, fi):
        return self.perform(self.fmt_lineno, self.tup_lineno, fi)

    def get_sysent(self, fi, strpos):
        pos = fi.tell()
        off = self.perform(self.fmt_sysent_off, self.tup_sysent_off, fi)
        fi.seek(pos)
        name = self.perform(self.fmt_sysent_name, self.tup_sysent_name, fi)
        if off.zeroes == 0: 
            #print(off)
            pos = fi.tell()
            fi.seek(strpos + off.offset)
            n = fi.getz(1024)
            fi.seek(pos)
            return name._replace(name = n)
        return name
    
    def get_string(self, fi):
        fi.seek(o, idaapi.SEEK_CUR)
        return fi.getz(1024)
        

    def perform(self, fmt, tup, fi):
        data = fi.read(struct.calcsize(self.fmt_prefix+fmt))
        record = struct.unpack(self.fmt_prefix + fmt, data)
        ntup = tup._make(record)
        return ntup
        
# -----------------------------------------------------------------------

magics = [0x017A]

# -----------------------------------------------------------------------
def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing 
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # we support only one format per file
    if n > 0:
        return 0

    li.seek(0)
    magic = li.read(2)
    if struct.unpack('>h',magic)[0] in magics:
        idaapi.set_processor_type("A29K", SETPROC_ALL)
        return { 'format': fmt_a29k_coff_big, 'options': 1 }
    if struct.unpack('<h',magic)[0] in magics:
        idaapi.set_processor_type("A29K", SETPROC_ALL)
        return { 'format': fmt_a29k_coff_little, 'options': 1 }
    
    # unrecognized format
    return 0

def readToSegment(li, src, size, target, name):
        li.seek(src)
        data = li.read(size)
        idaapi.mem2base(data, target)
        AddSeg(target,target + size,0,1,idaapi.saRelWord, idaapi.scPub)
        RenameSeg(target, name)

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    fmt_prefix = None
    if format == fmt_a29k_coff_big:
        fmt_prefix = '>'
    else:
        fmt_prefix = '<'
        
    li.seek(0, idaapi.SEEK_END)
    size = li.tell()
    
    li.seek(0, idaapi.SEEK_SET)
    P = Unpacker(fmt_prefix)

    head = P.get_filehdr(li)
    #print(head)
    
    # skip optional header
    li.seek(head.opthdr, idaapi.SEEK_CUR)


    sectionstart = li.tell()
    # process sections
    sections = []
    for i in range(0,head.nscns):
        shdr = P.get_sectionhdr(li)
        sections.append(shdr)
    sectionend = li.tell()

    # loading sections
    for s in sections:
        #print(s)
        if(s.size == 0):
            continue
        readToSegment(li, s.scnptr, s.size, s.paddr, s.name)

    # processing symbols
    li.seek(head.symptr)
    symbolstart = head.symptr
    strstart = li.tell() + 18 * head.nsyms
    
    symbols = []
    i = 0
    while i < head.nsyms:
        sym = P.get_sysent(li,strstart)
        symbols.append(sym)
        i = i + 1 
        
        if(sym.sclass == 2 and sym.type == 0):
            if(sym.scnum in [13,14]):
                MakeName(sym.value, sym.name)
                MakeCode(sym.value)
                MakeFunction(sym.value)
                AddEntryPoint(sym.value, sym.value, sym.name, 1)
            elif(sym.scnum in [2,6,7]):
                MakeName(sym.value, sym.name)
                MakeCode(sym.value)
                MakeFunction(sym.value)
            elif(sym.scnum == 3):
                MakeName(sym.value, sym.name)
                MakeStr(sym.value, BADADDR)
            elif(sym.scnum == 8):
                MakeName(sym.value, sym.name)
                MakeDword(sym.value)
            elif(sym.scnum == 15):
                MakeName(sym.value, sym.name)
                MakeWord(sym.value)
            elif(sym.scnum in [11,12,16,14]):
                pass
            elif sym.scnum == -1:
                pass
            else:
                MakeName(sym.value, sym.name)

    # dumping COFF header
    readToSegment(li, 0, sectionstart, 0xFF000000, "COFF_HEAD")
    readToSegment(li, sectionstart, sectionend - sectionstart ,  0xFF100000, "COFF_SECTIONS")
    readToSegment(li, symbolstart, strstart - symbolstart, 0xFF200000, "COFF_SYMBOLS")
    readToSegment(li, strstart, size - strstart, 0xFF300000, "COFF_STRINGS")

    return 1

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    Warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0




