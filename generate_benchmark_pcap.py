#!/usr/bin/env python3
"""
Generate a large PCAP file for DPI benchmarking.
Creates ~10,000+ packets with diverse traffic patterns.
"""

import struct
import random

class PCAPWriter:
    def __init__(self, filename):
        self.file = open(filename, 'wb')
        self.write_global_header()
        self.timestamp = 1700000000
        self.pkt_count = 0

    def write_global_header(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
        self.file.write(header)

    def write_packet(self, data):
        ts_sec = self.timestamp + self.pkt_count // 100
        ts_usec = random.randint(0, 999999)
        self.pkt_count += 1
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, len(data), len(data))
        self.file.write(pkt_header)
        self.file.write(data)

    def close(self):
        self.file.close()

def eth(src='00:11:22:33:44:55', dst='aa:bb:cc:dd:ee:ff', etype=0x0800):
    return bytes.fromhex(dst.replace(':','')) + bytes.fromhex(src.replace(':','')) + struct.pack('>H', etype)

def ip_hdr(src, dst, proto, payload_len):
    h = struct.pack('>BBHHHBBH', 0x45, 0, 20+payload_len, random.randint(1,65535), 0x4000, 64, proto, 0)
    h += bytes(int(x) for x in src.split('.'))
    h += bytes(int(x) for x in dst.split('.'))
    return h

def tcp_hdr(sp, dp, seq, ack, flags):
    return struct.pack('>HHIIBBHHH', sp, dp, seq, ack, 0x50, flags, 65535, 0, 0)

def udp_hdr(sp, dp, plen):
    return struct.pack('>HHHH', sp, dp, 8+plen, 0)

def tls_hello(sni):
    sni_b = sni.encode()
    sni_entry = struct.pack('>BH', 0, len(sni_b)) + sni_b
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('>HH', 0, len(sni_list)) + sni_list
    sv = struct.pack('>HHB', 0x002b, 3, 2) + struct.pack('>H', 0x0304)
    exts = sni_ext + sv
    body = struct.pack('>H', 0x0303) + bytes(random.randint(0,255) for _ in range(32))
    body += struct.pack('B', 0) + struct.pack('>H', 4) + struct.pack('>HH', 0x1301, 0x1302)
    body += struct.pack('BB', 1, 0) + struct.pack('>H', len(exts)) + exts
    hs = struct.pack('B', 1) + struct.pack('>I', len(body))[1:] + body
    return struct.pack('B', 0x16) + struct.pack('>HH', 0x0301, len(hs)) + hs

def dns_query(domain):
    d = struct.pack('>HHHHH', random.randint(1,65535), 0x0100, 1, 0, 0)
    for label in domain.split('.'):
        d += struct.pack('B', len(label)) + label.encode()
    d += struct.pack('>BHH', 0, 1, 1)
    return d

def main():
    w = PCAPWriter('benchmark_test.pcap')
    user_ip = '192.168.1.100'
    seq = 1000

    sites = [
        ('142.250.185.206','www.google.com'), ('142.250.185.110','www.youtube.com'),
        ('157.240.1.35','www.facebook.com'), ('157.240.1.174','www.instagram.com'),
        ('104.244.42.65','twitter.com'), ('52.94.236.248','www.amazon.com'),
        ('23.52.167.61','www.netflix.com'), ('140.82.114.4','github.com'),
        ('104.16.85.20','discord.com'), ('35.186.224.25','zoom.us'),
        ('35.186.227.140','web.telegram.org'), ('99.86.0.100','www.tiktok.com'),
        ('35.186.224.47','open.spotify.com'), ('192.0.78.24','www.cloudflare.com'),
        ('13.107.42.14','www.microsoft.com'), ('17.253.144.10','www.apple.com'),
        ('151.101.1.69','www.reddit.com'), ('104.18.32.68','www.stackoverflow.com'),
        ('185.199.108.133','docs.github.com'), ('172.217.14.99','mail.google.com'),
    ]

    src_ips = [f'192.168.1.{i}' for i in range(100, 200)]

    # Generate many TLS connections (each = 4 packets: SYN, SYN-ACK, ACK, ClientHello)
    for round_num in range(50):
        for dst_ip, sni in sites:
            src_ip = random.choice(src_ips)
            sp = random.randint(49152, 65535)
            e = eth()
            # SYN
            w.write_packet(e + ip_hdr(src_ip, dst_ip, 6, 20) + tcp_hdr(sp, 443, seq, 0, 0x02))
            # SYN-ACK
            w.write_packet(eth('aa:bb:cc:dd:ee:ff','00:11:22:33:44:55') +
                           ip_hdr(dst_ip, src_ip, 6, 20) + tcp_hdr(443, sp, seq+1000, seq+1, 0x12))
            # ACK
            w.write_packet(e + ip_hdr(src_ip, dst_ip, 6, 20) + tcp_hdr(sp, 443, seq+1, seq+1001, 0x10))
            # Client Hello
            tls = tls_hello(sni)
            w.write_packet(e + ip_hdr(src_ip, dst_ip, 6, 20+len(tls)) + tcp_hdr(sp, 443, seq+1, seq+1001, 0x18) + tls)
            seq += 10000

    # HTTP traffic
    http_sites = [('93.184.216.34','example.com'), ('185.199.108.153','httpbin.org')]
    for _ in range(100):
        for dst_ip, host in http_sites:
            sp = random.randint(49152, 65535)
            e = eth()
            w.write_packet(e + ip_hdr(user_ip, dst_ip, 6, 20) + tcp_hdr(sp, 80, seq, 0, 0x02))
            http_data = f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
            w.write_packet(e + ip_hdr(user_ip, dst_ip, 6, 20+len(http_data)) +
                           tcp_hdr(sp, 80, seq+1, 1, 0x18) + http_data)
            seq += 5000

    # DNS traffic
    domains = ['www.google.com','www.youtube.com','www.facebook.com','api.twitter.com',
               'www.reddit.com','cdn.discord.com','api.spotify.com','www.amazon.com']
    for _ in range(100):
        for domain in domains:
            sp = random.randint(49152, 65535)
            d = dns_query(domain)
            w.write_packet(eth() + ip_hdr(user_ip, '8.8.8.8', 17, 8+len(d)) + udp_hdr(sp, 53, len(d)) + d)

    w.close()
    print(f"Created benchmark_test.pcap with {w.pkt_count} packets")

if __name__ == '__main__':
    main()
