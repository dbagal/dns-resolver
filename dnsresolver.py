import datetime
import sys
import dns.query
import dns.resolver
import time
import os
from collections import defaultdict
from dns_exceptions import *

class DNSResolver():

    def __init__(self) -> None:
        self.root_servers_ip = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',\
            '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129',\
            '199.7.83.42', '202.12.27.33']

        self.logs = []
        self.resolver = dns.resolver.get_default_resolver()
        self.rdatatype = {"A":dns.rdatatype.A, "NS": dns.rdatatype.NS, "MX": dns.rdatatype.MX}

        dir = os.path.dirname(os.path.abspath(__file__))
        self.logs_path = os.path.join(dir,'logs')
        if not os.path.exists(self.logs_path):
            os.makedirs(self.logs_path)


    def _log(self, msg):
        self.logs += [msg]


    def _flush_logs(self, hostname, type):
        with open(self.logs_path+"/"+hostname+"-"+type+".txt", "w") as fp:
            fp.write("\n".join(self.logs))


    def _current_timestamp(self):
        current_time_object = datetime.datetime.now()
        weekday = current_time_object.strftime("%a")
        month = current_time_object.strftime("%b")
        date = current_time_object.strftime("%d")
        time = current_time_object.strftime('%H:%M:%S')
        year = current_time_object.strftime("%Y")
        timestamp = f"{weekday} {month} {date} {time} {year}"
        
        return timestamp


    def _query_server(self, zone_name, query, servers):
        """ 
        @params:
        - zone_name: Complete domain name rather than zones. E.g: cs.stonybrook.edu
        - query: Dnspython dns.message object, containing the query to be sent to the server
        - servers: Python list of strings which are urls/ip-addresses of the nameservers

        @function:
        - Selects a nameserver from 'servers'
        - Determines the ip address of this nameserver
        - Sends the query to this nameserver
        - In case of failure, it retries everything by selecting the next server in the list

        @returns:
        - response: Unprocessed/unfiltered response from the server
        - ns_ip: Ip address of the name server selected and queried for the response
        """
        i=0
        while True:
            try:
                # Check if 'servers' contain ip-addresses which are all numeric 
                if not str(servers[0]).replace(".","").isnumeric():
                    server_ip = self.resolver.resolve(servers[i]).rrset[0].to_text()
                else:
                    server_ip = servers[i] 

                response = dns.query.udp(query, server_ip)

                if response.rcode() != dns.rcode.NOERROR:
                    i+=1
                else:
                    break
                
            except IndexError:
                raise ResolutionError(zone_name, servers)

        return response, server_ip


    def _get_resource_records(self, zone_name, type, nameservers):  
        """  
        @params:
        - zone_name: Complete domain name rather than zones. E.g: cs.stonybrook.edu
        - type: string in ("A", "NS", "MX") determining the type of dns record
        - nameservers: Python list of strings which are urls/ip-addresses of the nameservers

        @function:
        - Send the query for the 'zone_name'-'type' and get the response
        - Organize the results in a python dictionary indexed by the record types

        @returns:
        - rrsets_dict: Dictionary containing resource records indexed by the record types 
        - ns_ip: Ip address of the name server selected and queried for the response
        """
        query = dns.message.make_query(zone_name, type)

        main_response, ns_ip = self._query_server(zone_name, query, nameservers)
        rrsets = main_response.authority + main_response.answer

        rrsets_dict = defaultdict(list)

        for rrset in rrsets:
            for resource_record in rrset:
                if resource_record.rdtype == dns.rdatatype.A:
                    rrsets_dict["A"] += [resource_record]
                elif resource_record.rdtype == dns.rdatatype.MX:
                    rrsets_dict["MX"] += [resource_record]
                elif resource_record.rdtype == dns.rdatatype.NS:
                    rrsets_dict["NS"] += [resource_record]

        return rrsets_dict, ns_ip


    def resolve(self, hostname, type):
        self.logs = []
        self._log(f"Querying '{hostname}' for {type}-record\n")
        if type not in ("A", "NS", "MX"): raise ResourceRecordTypeError(type)

        timestamp = self._current_timestamp()
        start_time = time.time()

        hostname = hostname.replace("https://","").replace("http://","").replace("www.","").rstrip(".")+"."
        n = len(hostname.split("."))-1
        i=0
        while i<n:
            if i==0:
                nameservers = self.root_servers_ip

            # Query the nameservers iteratively
            rrsets, ns_ip = self._get_resource_records(hostname, self.rdatatype[type], nameservers)
            self._log(f"Redirecting to {ns_ip}")

            # Get the IP-addresses/URLs of the nameservers
            A_records = rrsets.get("A", None)
            NS_records = rrsets.get("NS", None)
            if  A_records is not None :
                nameservers = []
                try:
                    for i in range(len(A_records.items)):
                        nameservers += [A_records.items[i].address]
                except:
                    nameservers = A_records

            elif NS_records is not None:
                nameservers = [ns_record.target for ns_record in NS_records]

            i+=1
        
        # In case of A and MX records, query the final authoritative nameserver to get the result
        if type in ("A", "MX") and rrsets.get(type, None) is None:
            rrsets, ns_ip = self._get_resource_records(hostname, self.rdatatype[type], nameservers)

        records = "\n".join([record.to_text() for record in rrsets[type]])
        response = str(records).rstrip("\n")

        msg_size = sys.getsizeof(response)
        end_time = time.time()

        time_elapsed = int(round((end_time - start_time) * 1000)) 

        reply = f"\nQUESTION SECTION:\n{hostname}\t\tIN\t{type}\n\nANSWER SECTION:\n{response}\
            \n\nQuery time: {time_elapsed} msec\nWHEN: {timestamp}\n\nMSG SIZE rcvd: {msg_size}\n"

        self._log(reply)
        self._flush_logs(hostname, type)

        return reply
