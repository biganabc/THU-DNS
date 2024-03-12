import argparse
from scapy.all import *
import time

DEFAULT_MAX_HOPS = 32

parser = argparse.ArgumentParser(description='处理 --dst 参数的示例')
parser.add_argument('--dest', type=str, required=True, help='dest addr')
parser.add_argument('--qname', type=str, required=True, help='qname')
parser.add_argument('--qtype', type=str, help='qtype', default='A')
parser.add_argument('--dnsport', type=int, help='dns port', default=53)
parser.add_argument('--timeout', type=int, help='time out', default=5)
parser.add_argument('-i', type=str, help='iface', default='any')
args = parser.parse_args()

for i in range(1, DEFAULT_MAX_HOPS + 1):
    sport_list = [random.randint(1, 65535) for _ in range(3)]
    route_ips = []
    cost_times = []
    for repeat in range(3):
        p = IP(dst=args.dest, ttl=i) / UDP(sport=sport_list[repeat], dport=53) / DNS(rd=1, qd=DNSQR(qname=args.qname,
                                                                                                    qtype=args.qtype))
        start_time = time.time()
        answer = sr1(p, timeout=args.timeout, verbose=False)
        end_time = time.time()
        route_ips.append(answer.src if answer is not None else None)
        cost_times.append(end_time - start_time)
    for repeat in range(3):
        print("{} {} ".format(route_ips[repeat], cost_times[repeat]), end="")
    print("")
    if args.dest in route_ips:
        break
