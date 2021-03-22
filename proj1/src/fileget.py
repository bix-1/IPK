#!/usr/bin/env python3.8

import socket
import re                       # regex
from sys import exit as Exit    # error exits
import argparse                 # handling CL args
from os.path import dirname     # handling output files
from pathlib import Path        # handling output files


def recvall(sock):
    """Returns complete message of reply from server as string
    """
    buf_size = 4096
    # receive first packet
    data = sock.recv(buf_size)
    # split to: [Status, Length, FileContents]
    tmp = re.split(b"Length:\s*|\r\n\r\n", data)
    if b"Not Found" in tmp[0]:
        Exit("ERROR: File not found")
    if len(tmp) < 2:    # header + empty message
        tmp.append(b"")
    received = [tmp[2]]
    remaining = int(tmp[1].decode()) - len(tmp[2])

    while remaining > 0:
        data = sock.recv(min(remaining, buf_size))
        received.append(data)
        remaining -= len(data)

    return b"".join(received)


def get(address, servername, filename):
    """Copies specified file from given server
    """
    # connect
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fserver:
        try:
            fserver.connect(address)
            fserver.send(b"GET %s FSP/1.0\r\nHostname: %s\r\nAgent: xbartk07\r\n\r\n" % (filename.encode(), servername.encode()))
            fserver.settimeout(2)
            # get contents
            contents = recvall(fserver)
        except socket.timeout:
            fserver.close()
            Exit("Failed to reach nameserver")

    # output contents to file
    file = open(filename, "wb")
    file.write(contents)
    file.close()


def get_all(address, servername):
    """Copies filesystem of files & non-empty dirs of specified server
    """
    # connect
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fserver:
        try:
            fserver.connect(address)
            # get index file
            fserver.send(b"GET %s FSP/1.0\r\nHostname: %s\r\nAgent: xbartk07\r\n\r\n" % ("index".encode(), servername.encode()))
            fserver.settimeout(2)
            # get file list
            files = [x for x in recvall(fserver).decode().split("\r\n") if x != ""]
        except socket.timeout:
            fserver.close()
            Exit("Failed to reach nameserver")

    for file in files:
        # create path for file
        Path(dirname(file)).mkdir(parents=True, exist_ok=True)
        # get file
        get(address, servername, file)


def get_args():
    """Returns parsed CL arguments
    """
    # define CL arguments
    aparser = argparse.ArgumentParser(description="Distributed Filesystem Client.")
    aparser.add_argument(
        "--nameserver", "-n",
        required = True,
        help="IP address & port of name server")
    aparser.add_argument(
        "--fileinfo", "-f",
        required = True,
        help="SURL of file to be downloaded; Protocol in URL is always fsp")

    return aparser.parse_args()


def main():
    """_____get nameserver & file(s) options_____"""
    args = get_args()
    ns_ip, ns_port = args.nameserver.split(":")
    ns_port = int(ns_port)
    protocol, fs_name, filename = re.split("://|/", args.fileinfo, maxsplit=2)
    # check protocol
    if protocol != "fsp":
        Exit("ERROR: Invalid protocol \"%s\" -- must be \"fsp\"" %protocol)


    """_____get IP address & port of file server_____"""
    # send request to nameserver using UDP
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as nserver:
        try:
            nserver.sendto(b"WHEREIS " + str.encode(fs_name), (ns_ip, ns_port))
            nserver.settimeout(2)
            data, _ = nserver.recvfrom(ns_port)
        except socket.timeout:
            nserver.close()
            Exit("Failed to reach nameserver")
    # parse reply
    status, fs_ip, fs_port = re.split(" |:", data.decode())
    if status != "OK":
        Exit("ERROR: Failed to find server \"%s\"" % fs_name)
    fs_port = int(fs_port)


    """_____get file(s) from file server_____"""
    if filename == "*":
        get_all((fs_ip, fs_port), fs_name)
    else:
        get((fs_ip, fs_port), fs_name, filename)


if __name__ == "__main__":
    main()
