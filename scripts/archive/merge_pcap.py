import os
from glob import glob
from os.path import join
from multiprocessing import Process

#pcap_root = '/data/juma/data/ids18/PCAPs/Thursday-15-02-2018/pcap'
pcap_root = '/mnt/disk3/net_intrusion/ids18/traffic/Thursday-01-03-2018/editcap'
outfile = '/mnt/disk3/net_intrusion/ids18/traffic/Thursday-01-03-2018-editca.pcap'


os.chdir(pcap_root)

fns = ['"{}"'.format(i) for i in glob(join('*'))]
fns = sorted(fns)
print(fns[:2])
print(pcap_root)
cmd  = 'mergecap -w {} {} -F pcap'.format(outfile,' '.join(fns))
#cmd  = 'joincap -v -w={} {} '.format(outfile,' '.join(fns))

os.system(cmd)
