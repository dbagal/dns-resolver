from dnsresolver import *
from dnssecresolver import *
import argparse

parser=argparse.ArgumentParser(description="add numbers")
parser.add_argument("server", type=str)
parser.add_argument("type", type=str)
parser.add_argument("--dnssec", action='store_true')
args = parser.parse_args()

if args.dnssec:
    resolver = DNSSECResolver()
else:
    resolver = DNSResolver()

response = resolver.resolve(args.server, args.type)
print(response)