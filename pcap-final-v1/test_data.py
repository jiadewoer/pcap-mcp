"""Tiny synthetic protocol traffic, solely for offline checks; never pilot data."""
import struct

def pcap(protocol, bodies, port):
    result=bytearray(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1))
    for i,body in enumerate(bodies):
        if protocol==17:transport=struct.pack('!HHHH',53000,port,8+len(body),0)+body
        else:transport=struct.pack('!HHIIBBHHH',54000,port,1,1,0x50,0x18,8192,0,0)+body
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(transport),i,0,64,protocol,0,b'\xc0\x00\x02\x01',b'\xc6\x33\x64\x01')
        packet=b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x00'+ip+transport
        result.extend(struct.pack('<IIII',1700000000+i,0,len(packet),len(packet)));result.extend(packet)
    return bytes(result)

def samples():
    question=b'\x07example\x03com\x00\x00\x01\x00\x01'
    query=struct.pack('!HHHHHH',1,0x0100,1,0,0,0)+question
    nx=struct.pack('!HHHHHH',1,0x8183,1,0,0,0)+question
    # Complete ServerHello in a TLS record; no claim this establishes a full real connection.
    hello=b'\x03\x03'+b'\x11'*32+b'\x00\xc0\x2f\x00'
    handshake=b'\x02'+len(hello).to_bytes(3,'big')+hello
    tls=b'\x16\x03\x03'+len(handshake).to_bytes(2,'big')+handshake
    return {'ws-http.pcap':pcap(6,[b'GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Offline-Check\r\n\r\n'],80),
            'dns.cap':pcap(17,[query,nx],53),'http2-16-ssl.pcapng':pcap(6,[tls],443)}
