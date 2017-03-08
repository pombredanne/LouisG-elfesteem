#! /usr/bin/env python

import os
__dir__ = os.path.dirname(__file__)

try:
    import hashlib
except ImportError:
    # Python 2.4 does not have hashlib
    # but 'md5' is deprecated since python2.5
    import md5 as oldpy_md5
    class hashlib(object):
        def md5(self, data):
            return oldpy_md5.new(data)
        md5 = classmethod(md5)

def run_test():
    ko = []
    def assertion(target, value, message):
        if target != value: ko.append(message)
    import struct
    assertion('f71dbe52628a3f83a77ab494817525c6',
              hashlib.md5(struct.pack('BBBB',116,111,116,111)).hexdigest(),
              'MD5')
    from elfesteem.rprc import RPRC
    e = RPRC()
    d = e.pack()
    assertion('865001a37fa24754bd17012e85d2bfff',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty RPRC')
    d = RPRC(d).pack()
    assertion('865001a37fa24754bd17012e85d2bfff',
              hashlib.md5(d).hexdigest(),
              'Creation of a standard empty RPRC; fix point')
    rprc_m3 = open(__dir__+'/binary_input/ducati-m3_p768.bin', 'rb').read()
    assertion('d31c5887b98b37f949da3570b8688983',
              hashlib.md5(rprc_m3).hexdigest(),
              'Reading ducati-m3_p768.bin')
    e = RPRC(rprc_m3)
    d = e.pack()
    assertion('d31c5887b98b37f949da3570b8688983',
              hashlib.md5(d).hexdigest(),
              'Packing after reading ducati-m3_p768.bin')
    # Packed file is identical :-)
    d = e.display().encode('latin1')
    assertion('c691ff75fffede7701086f6b3c981b3b',
              hashlib.md5(d).hexdigest(),
              'Display RPRC file content')
    return ko

if __name__ == "__main__":
    ko = run_test()
    if ko:
        for k in ko:
            print('Non-regression failure for %r'%k)
    else:
        print('OK')

