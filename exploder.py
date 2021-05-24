#!/usr/bin/env python3

from netaddr import *

for cloud in ['public', 'china', 'gov']:
    ipranges = IPSet()
    with open('azure-%s.txt' % cloud, 'r') as reader:
        for line in reader.readlines():
            ipranges.add(line)
    with open('azure-%s-ips.txt' % cloud, 'w') as writer:
        for ip in ipranges:
            writer.write(str(ip)+'\n')
