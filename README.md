# DNS Resolution

This project implements an iterative DNS and DNSSEC resolver for resolving A, NS and MX records.

**Programming Language:** *Python*

# External libraries used

- *dnspython==2.1.0*
- *cryptography==3.4.8*
- *matplotlib==3.3.4*
- *numpy==1.20.1*
- *argparse==1.1*
- *re==2.2.1*

# Project structure

- **dnsresolver.py:** Defines **DNSResolver** class
- **dnssecresolver.py:** Defines **DNSSECResolver** class
- **dnsexceptions.py:** Defines all exceptions needed for the DNS resolution
- **mydig.py:** Command line DNS resolver
- **usage.py:** Defines the correct usage of the DNSResolver and DNSSECResolver classes
- **logs:** Folder which stores the logs collected as a part of each query
- **mydig_output.rtf:** Output of DNSResolver for few domain names
- **mydig_dnssec_output.rtf:** Output of DNSSECResolver for few domain names
- **performance.py:** Script that measures the performance of the resolver on the top 25 sites from <https://www.alexa.com/topsites>
- **performance-report.txt:** Contains the response times for all the top 25 sites using mydig resolver, local resolver and google's resolver
- **documentation.pdf:** Documentation of the algorithms working in the background 
- **performance-analysis.pdf:** Documentation of the results obtained during performance analysis

# Installation and setup

```
$ pip3 install -r requirements.txt
```

# Usage

For regular DNS resolution, do the following:
```
$ python3 mydig.py amazon.com A
```

For DNSSEC resolution, just add *--dnssec* flag
```
$ python3 mydig.py amazon.com A --dnssec
```

You can also use the DNSResolver and DNSSECResolver in your program as follows:

```
from dnsresolver import *
from dnssecresolver import *

hosts = ['dnssec-failed.org', 'google.co.jp', 'verisigninc.com']

resolver = DNSResolver() # DNSSECResolver()

for h in hosts:
    response = resolver.resolve(h, "A")
    print(response)
```

# Exceptions

- **ResolutionError:** Raised when resource records for the input domain name don't exist
- **ResourceRecordTypeError:** Raised when the input resource record is invalid
- **KSKVerificationError:** Raised when KSK for the input domain name cannot be verified
- **ZSKVerificationError:** Raised when ZSK for the input domain name cannot be verified
- **RRSetVerificationError:** Raised when RRSets for the input domain name cannot be verified
- **NoDNSSECSupportError:** Raised when the input domain name doesn't have DNSSEC enabled
