import rzpipe
import re
import os
from keystone import *

def patch(so, ks, file_name):
    with open(file_name) as f:
        pattern = r"patch: \[([0-9a-fA-F]+)\] (.+)"
        for line in f.readlines():
            if (len(line.strip()) != 0):
                match = re.match(pattern, line)
                encoding, count = ks.asm(match.group(2), int(match.group(1), 16))
                data = ' '.join(["%02x" % b for b in encoding])
                so.cmd(f'wx "{data}" @ 0x{match.group(1)}')

def main():
    so = rzpipe.open('./patch_ins_lib52pojie.so', flags=['-w'])
    ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    directory = './patch_ins'
    for file_name in os.listdir(directory):
        patch(so, ks, os.path.join(directory, file_name))
        print(f'{file_name} is patch done !!!')

    # so.cmd('wa "b.lt 0x1cad4" @ 0x1cbe8')
    # so.cmd('wa "b 117884" @ 0x1cdbc')
    so.quit()

if __name__ == '__main__':
    main()
