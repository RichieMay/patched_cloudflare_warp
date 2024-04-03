#!/usr/bin/env python3

import os
import argparse
from ipaddress import IPv4Address

def get_func_section(file_path: str, func_name_regex: str) -> tuple:
    command = str.format('readelf -Ws {} | grep -P "{}"', file_path, func_name_regex)
    output_stream = os.popen(command)
    if not output_stream:
        return None

    func_address_info = output_stream.read()
    if not func_address_info:
        return None

    keywords = func_address_info.split()
    if not keywords or len(keywords) != 8:
        return None

    begin = int(keywords[1], 16)
    end = begin + int(keywords[2])      
    return tuple((begin, end))

def modify_bind_ip_address(file_path: str, new_ipv4_addr: str) -> bool:
    start_hex = b'\x49'
    follow_hex = b"\xC1\xE4\x20\x49\x81\xCC"
    ipv4_bytes = IPv4Address(new_ipv4_addr).packed

    begin, end = get_func_section(file_path, "FUNC.+WarpConnection\d+start_inner\d+")
    with open(file_path, "rb+") as f:
        f.seek(begin, os.SEEK_SET)

        while begin < end:
            begin += len(start_hex)
            char = f.read(len(start_hex))
            if not char:
                break

            if char != start_hex:
                continue

            begin += len(follow_hex)
            if f.read(len(follow_hex)) == follow_hex:
                f.write(ipv4_bytes)
                return True

        return False

def get_cmdline_args():
    parser = argparse.ArgumentParser(description='parameters to patch')
    parser.add_argument('-p', '--path', type=str, default='/bin/warp-svc', help='the path of warp-svc')
    parser.add_argument('-s', '--server', type=str, required=True, help='the ipv4 address of server')
    return parser.parse_args()

if __name__ == '__main__':
    args = get_cmdline_args()
    print("Good, Patch OK!" if modify_bind_ip_address(args.path, args.server) else "Sorry, Patch Failed!")
