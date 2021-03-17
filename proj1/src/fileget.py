#!/usr/bin/env python3.8

import sys
import argparse
import re
import socket

BUFFER_SIZE = 4096

# define command line arguments
aparser = argparse.ArgumentParser(description="Distributed Filesystem Client.")
aparser.add_argument(
    "--nameserver", "-n",
    required = True,
    help="IP address & port of name server")
aparser.add_argument(
    "--fileinfo", "-f",
    required = True,
    help="SURL of file to be downloaded; Protocol in URL is always fsp")

# get CL arguments
args = aparser.parse_args()
ns_ip, ns_port = args.nameserver.split(":")
ns_port = int(ns_port)
protocol, fs_name, filename = re.split("://|/", args.fileinfo, maxsplit=2)

# check CL args
if protocol != "fsp":
    sys.exit("ERROR: Invalid protocol \"%s\"" %protocol)

# get IP & port of file server
nserver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
nserver.sendto(b"WHEREIS " + str.encode(fs_name), (ns_ip, ns_port))
data, _ = nserver.recvfrom(ns_port)
nserver.close()
status, fs_ip, fs_port = re.split(" |:", data.decode("utf-8"))
fs_port = int(fs_port)
if status != "OK":
    sys.exit("ERROR: Failed to find server \"%s\"" % fs_name)

# find file & get its size
fserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fserver.connect((fs_ip, fs_port))
fserver.send(b"GET %s FSP/1.0\r\nHostname: %s\r\nAgent: xbartk07\r\n\r\n" % (filename.encode(), fs_name.encode()))
data = fserver.recv(BUFFER_SIZE).decode("utf-8")
# get contents of file
N = int(re.search("Length:(.+?)\n", data).group(1))
fserver.send(b"GET %s FSP/1.0\r\nHostname: %s\r\nAgent: xbartk07\r\n\r\n" % (filename.encode(), fs_name.encode()))
data = fserver.recv(N).decode("utf-8")
fserver.close()

print(data, end="")
