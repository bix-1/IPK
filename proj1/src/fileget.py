#!/usr/bin/env python3.8

import sys
import argparse
import re
import socket


def recvall(sock):
    buf_size = 4096
    # receive first packet
    data = sock.recv(buf_size)
    # split to: [Status, Length, FileContents]
    tmp = re.split(b"Length:\s*|\r\n\r\n", data)
    if b"Not Found" in tmp[0]:
        sys.exit("ERROR: File not found")
    received = [tmp[2]]
    remaining = int(tmp[1].decode("utf-8")) - len(received)

    while remaining > 0:
        data = sock.recv(min(remaining, buf_size))
        received.append(data)
        remaining -= len(data)

    return b"".join(received)


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

# print(args.fileinfo)
# sys.exit()

# check CL args
if protocol != "fsp":
    sys.exit("ERROR: Invalid protocol \"%s\"" %protocol)

"""_____get IP & port of file server_____"""
# send request to name server using UDP
nserver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
nserver.sendto(b"WHEREIS " + str.encode(fs_name), (ns_ip, ns_port))
# receive reply
data, _ = nserver.recvfrom(ns_port)
nserver.close()
# parse reply
status, fs_ip, fs_port = re.split(" |:", data.decode("utf-8"))
fs_port = int(fs_port)
if status != "OK":
    sys.exit("ERROR: Failed to find server \"%s\"" % fs_name)

"""_____get file from file server_____"""
# send request to file server using TCP
fserver = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
fserver.connect((fs_ip, fs_port))
fserver.send(b"GET %s FSP/1.0\r\nHostname: %s\r\nAgent: xbartk07\r\n\r\n" % (filename.encode(), fs_name.encode()))
# receive all packets
contents = recvall(fserver)
fserver.close()

# output contents to file
file = open(filename, "wb")
file.write(contents + b"\n")
file.close()
