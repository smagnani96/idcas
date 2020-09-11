# IDCAS - Intrusion Detection and Counter Attack System

IDCAS is an Intrusion Detection and Counter Attack System born as a research project for my Computer System Security exam.

As the name says, this tool aims to detect an attack and try to replicate it to all the other victims you specify. Despite being a research project, it turned out to be really usefull and usable during the CTF Attack-Defense, famous competitions where a lot of cybersecurity teams from all the world can take part.

In fact, the tool can be used to analyze a specific service you have to protect (a particular ip addres accessible from the machine you are going to run the software), looking for incoming attack and replicate them to all the other CTF participants, without even knowing the real attack. 

I created a video tutorial to explain both the architecture and how the system works, making a simple example using a dumb web application which you can find under the [vuln\_app](./vuln_app) folder.

https://drive.google.com/file/d/1VqbHxWJGEvL9F5-FZHDehtl-ve8maXK4/view?usp=sharing

## Requirements

* bcc;
* pyroute2;
* urllib3;
* email;
* zlib;
* ctypes.

Concerning eBPF, the only requirement is at least 130Kb for the session map in the DataPlane.
In the ControlPlane (python script) you can adjust the cleaner thread timer to clear the map as you like. Pay attention that in that dictionary there are at least the 130Kb coming from the DataPlane plus the list of all the HTTP messages intercepted, so the size could reach also 20Mb.

## Architecture

IDCAS's architecture may seem complex, but actually it is quite simple. There are two eBPF functions defined in [ebpf_filter.c](./ebpf_filter.c) that will be inserted in your Linux system and they will handle incoming (INGRESS) and outgoing (EGRESS) packets.

Concerning the Ingress part, every packet that contains an HTTP request (eg. Get, Post,...) and it is designated to a specific service (if specified) will be recorded, and that session (srcIp, dstIp, srcPort, dstPort) will be monitored.

At this point, the Egress program will record all HTTP response packets belonging to an already tracked session, to make sure not to waste time and mix packets.

When these program records a packet, the ControlPlane contained in [idcas.py](./idcas.py) will be called to perform many checks and reassemble the HTTP requests/responses. Every time an HTTP response has been correctly reassembled and decompressed, the script looks for a pattern to be contained in the HTTP body, and this is usuallly the flag an attacker has taken from us. At this point, if the pattern is contained in the response body, the script will start forwarding the same attack received to all the VICTIMS_IP, which are the other participants, and wait for a response. If the response contains the pattern, then we have successfully obtained with "no effort" a flag, otherwise something went wrong (they patched the service / there was an error decompressing the request / ...).

Every request is performed using a separated Thread. Moreover, every tot seconds a cleaner Thread is called to delete from the local dictionary in the ControlPlane all the old entries. 

## Usage

```bash
usage: idcas.py [-h] [-m MODE] [-S] [-H] [-s SERVICE] interface pattern

positional arguments:
  interface             indicates the interface to attach programs
  pattern               the pattern to search for in the http body

optional arguments:
  -h, --help            show this help message and exit
  -m MODE, --mode MODE  set the mode (XDP or CLS) (default: CLS)
  -S, --skb             use the skb mode if XDP (default: False)
  -H, --hardware        use the hardware offload mode if XDP (default: False)
  -s SERVICE, --service SERVICE
                        the ip of the service to protect if any (default: None)
```

I strongly suggest not to change the *MODE* since XDP does not support Egress program, so this tool won't work at all, but I decided to let this mode only for future improvements.

You must specify the network interface you want to attach the programs to and the pattern, which in case of CTF Attack-Defense is the flag format (eg. `myFlg{.*}`).

Finally, I would strongly suggest to specify the service ip thanks to the *-s* switch. This way the eBPF program will look only for packets belonging to session with that specific IP, avoiding to add useless overhead to the capture.

## Possible extensions

* Check better if it is possible to attach the probe directly to the service (to intercept HTTPS before encryption)
* Improve thread safety/logging
* Consider the usage of libpcap to compile dynamic filters (not so useful in ctf, once you have the IP/port in the program you are done)
* ... 