#!/usr/bin/env python

# Analyze ping by Keith Buck.
# MIT licensed.

import argparse
import re

parser = argparse.ArgumentParser(description="Analyze a ping file for missed probes.")
parser.add_argument("file", nargs="+", type=argparse.FileType('r'), help="file to search")
parser.add_argument("-g", "--gap-size", type=int, default=2, help="minimum gap count in probes")
args = parser.parse_args()

PROBE_REGEX = re.compile(ur'^\d+ bytes from [a-f0-9\.]+: icmp_seq=(?P<seq>\d+) ttl=\d+ time=(?P<time>\d+\.\d+) ms$')

for file in args.file:
	print file.name + ":"
	last_seq = -1
	for line in file:
		m = PROBE_REGEX.match(line)
		if m:
			seq = int(m.group('seq'))
			diff = seq - last_seq
			if diff > args.gap_size:
				print "Gap of {diff} probes at seq={seq}.".format(diff=diff, seq=seq)
			last_seq = seq
	print
