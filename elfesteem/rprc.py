# RPRC syntax: firmware format used by rpmsg

# The main source of information on this format is
#  https://github.com/ohadbc/sysbios-rpmsg
# A tool that reads the content of a RPRC .bin file is
#  https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/rprcfmt.h
#  https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/readrprc.c
# But the last version of this tool (tagged "new ABI") does not correspond
# to the RPRC files downloadable at http://goo.gl/4dndeg
# For example, the size of resources is 76 bytes, while in the new ABI it
# is 96 bytes. All examples of output of 'readrprc' that are found in this
# repository and in the following links have 76-bytes long resources.
#  https://github.com/radare/radare2/issues/1602
#  http://omappedia.org/wiki/RPMsg_BIOS_Sources
#  http://www.omappedia.com/wiki/RPMsg_Tesla
#  http://omappedia.org/wiki/Debugging_RPMsg#Readrprc_Utility
#  http://omappedia.org/wiki/RPMsg_BIOS_Sources#SYS.2FBIOS_RPMsg_Customizations
#  http://omappedia.org/wiki/Design_Overview_-_RPMsg#Firmware_Image_Format
# Currently, we don't know if there is a flag that tells when the "new ABI"
# is used, e.g. a value of 'version' greater than 2 in the header.

import struct
from elfesteem.cstruct import CBase, CStruct, data_null
from elfesteem.strpatchwork import StrPatchwork

class CData(object):
    def __new__(self, f):
        class CDataInstance(CBase):
            def _initialize(self, f=f):
                self._size = f(self.parent)
            def unpack(self, c, o):
                self.data = c[o:o+self._size]
            def pack(self):
                return self.data
            def __str__(self):
                return self.data.decode('latin1')
        return CDataInstance

# Section types
FW_RESOURCE    = 0
FW_TEXT        = 1
FW_DATA        = 2

# Resource types (old ABI)
RSC_CARVEOUT    = 0
RSC_DEVMEM      = 1
RSC_DEVICE      = 2
RSC_IRQ         = 3
RSC_TRACE       = 4
RSC_BOOTADDR    = 5
RSC_VRING       = 6

# Resource types (new ABI)
RSC_CARVEOUT    = 0
RSC_DEVMEM      = 1
RSC_TRACE       = 2
RSC_VRING       = 3
RSC_VIRTIO_HDR  = 4
RSC_VIRTIO_CFG  = 5

class RPRChdr(CStruct):
    _fields = [ ("magic","4s"), 
                ("version","u32"),
                ("header_len","u32"),
                ("data",CData(lambda _:_.header_len))]
    magic_txt = property(lambda _:_.magic.decode('latin1'))
    def _initialize(self):
        CStruct._initialize(self)
        # Change default values
        self.magic      = 'RPRC'.encode('latin1')
        self.version    = 2
        self.header_len = 1012
        self.data.data  = data_null * self.header_len
        self._size     += self.header_len
    def display(self):
        rep = []
        rep.append('magic number %(magic_txt)s' % self)
        rep.append('header version %(version)d' % self)
        rep.append('header size %(header_len)d' % self)
        rep.append('header data')
        rep.append(str(self.data))
        return '\n'.join(rep)

# NB: the following definition is taken from
# https://github.com/ohadbc/sysbios-rpmsg/blob/master/src/utils/rprcfmt.h
# It does not correspond to the RPRC files we have
class RPRCresourceNewABI(CStruct):
    _fields = [ ("type","u32"),
                ("id","u32"),
                ("da","u64"),   # Device Address
                ("pa","u64"),   # Physical Address
                ("len","u32"),
                ("flags","u32"),
                ("reserved","16s"),
                ("name","48s"),
                ]

class RPRCresource(CStruct):
    _fields = [ ("type","u32"),
                ("da","u64"),   # Device Address
                ("pa","u64"),   # Physical Address
                ("len","u32"),
                ("flags","u32"),
                ("name","48s"),
                ]
    name_txt = property(lambda _:_.name.strip(data_null).decode('latin1'))
    def display(self):
        return 'resource %(type)d, da: %(da)#010x, pa: %(pa)#010x, len: %(len)#010x, name: %(name_txt)s' % self

class RPRCsection(CStruct):
    _fields = [ ("type","u32"),
                ("da","u64"),   # Device Address
                ("len","u32"),
                ("data",CData(lambda _:_.len))]
    def unpack(self, c, o):
        CStruct.unpack(self, c, o)
        if self.type == FW_RESOURCE:
            self.res_len = RPRCresource(parent=self).bytelen
            if self.data.bytelen % self.res_len != 0:
                raise ValueError('Section data length %#x not multiple of %#x' % (self.data.bytelen, self.res_len))
            of = 0
            self.res = []
            while of + self.res_len <= self.data.bytelen:
                r = RPRCresource(parent=self, content=self.data.data, start=of)
                self.res.append(r)
                of += self.res_len
    def display(self):
        rep = []
        rep.append('section %(type)d, address: %(da)#010x, size: %(len)#010x' % self)
        if self.type == FW_RESOURCE:
            rep.append('resource table: %d' % self.res_len)
            for r in self.res:
                rep.append(r.display())
        return '\n'.join(rep)

class RPRC(object):
    sex = '<'
    wsize = 32
    def __init__(self, data = None, **kargs):
        self.sections = []
        if data is not None:
            self.content = StrPatchwork(data)
            self.parse_content()
            return
        # Create a RPRC file with no section
        self.hdr = RPRChdr(parent=self)
    def parse_content(self):
        self.hdr = RPRChdr(parent=self, content=self.content)
        if self.hdr.magic_txt != 'RPRC':
            raise ValueError("Not an RPRC")
        of = self.hdr.bytelen
        while of < len(self.content):
            s = RPRCsection(parent=self, content=self.content, start=of)
            self.sections.append(s)
            of += s.bytelen
    def pack(self):
        c = StrPatchwork()
        c[0] = self.hdr.pack()
        of = self.hdr.bytelen
        for s in self.sections:
            c[of] = s.pack()
            of += s.bytelen
        return c.pack()
    def display(self):
        # Same output as 'readrprc'
        rep = [self.hdr.display()] + [s.display() for s in self.sections]
        return '\n'.join(rep)

if __name__ == "__main__":
    import sys, code
    if len(sys.argv) > 2:
        for f in sys.argv[1:]:
            print('File: %s'%f)
            e = RPRC(open(f, 'rb').read())
            print (e.display())
        sys.exit(0)
    if len(sys.argv) == 2:
        e = RPRC(open(sys.argv[1], 'rb').read())
    code.interact('Interactive Python Console', None, locals())
