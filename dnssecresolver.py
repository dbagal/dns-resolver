import datetime
import sys
import dns.query
import dns.resolver
import time
import os
from collections import defaultdict
from dns_exceptions import *

class DNSSECResolver():

    def __init__(self) -> None:
        self.root_servers_ip = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10',\
            '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129',\
            '199.7.83.42', '202.12.27.33']

        self.logs = []

        # Create a resolver object to resolve ips for the urls of the nameservers
        self.resolver = dns.resolver.get_default_resolver()

        dir =  os.path.dirname(os.path.abspath(__file__))
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


    def _verify_ksk(self, zone_name, ksks, ds_response_from_parent):
        """  
        @params:
        - zone_name: Complete domain name rather than zones. E.g: cs.stonybrook.edu
        - ksks: Python list of all KSKs received in the DNSKEY record
        - ds_response_from_parent: DS query response from the parent 

        @function:
        - Extract all hashed KSKs from the parent's DS record
        - Hash all of the KSKs received from the DNSKEY record and compare them with every hashed KSK from the DS record
        - On finding a match, break the loop and return True
        """
        ds_rrsets = ds_response_from_parent.authority + [ds_response_from_parent.additional] + ds_response_from_parent.answer
        
        # Gather all the hashes in the DS record from the parent
        hashed_ksks_from_ds = []
        digest_types = []
        for rrset in ds_rrsets:
            for rr in rrset:
                if rr.rdtype == dns.rdatatype.DS:
                    hashed_ksks_from_ds += [rr]
                    digest_types += [rr.digest_type]

        # Determine the hashing algorithm used in the DS records and the hex digests of the hashes
        hashing_algo = {1: "SHA1", 2: "SHA256"}
        ds_record_hex_digests = [str(hashed_ksks_from_ds[i]).split(" ")[-1] for i in range(len(hashed_ksks_from_ds))]
        
        # For every ksk, hash it and compare it with all the hashes in the DS record
        # On finding a match, break the loop and return true
        match = False
        for i, ds_record in enumerate(ds_record_hex_digests):
            for ksk in ksks:
                hash_ksk_calculated = dns.dnssec.make_ds(zone_name, ksk, hashing_algo[digest_types[i]])
                hash_ksk_calculated_hex_digest = str(hash_ksk_calculated).split(" ")[-1]

                if hash_ksk_calculated_hex_digest == ds_record:
                    match = True
                    break
        
        return match
        

    def _verify_rrset(self, zone_name, response, dnskey_response):
        """  
        @params:
        - zone_name: Complete domain name rather than zones. E.g: cs.stonybrook.edu
        - response: Response to the original DNS query for A/NS/MX records
        - dnskey_response: Response to the DNSKEY query

        @function:
        - Validate the RRSet and RRSig from the original response using the keys from the dnskey_response
        """
        
        try:
            RRSets = dict()
            RRSigs = dict()

            for rrset in response.answer+response.authority:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    RRSigs[rrset.covers] = rrset
                else:
                    RRSets[rrset.rdtype] = rrset

            zsks_and_ksks = dnskey_response.answer[0]
            zone_name = dns.name.from_text(zone_name)
            record_types = list(RRSigs.keys())
            
            for record_type in record_types:
                dns.dnssec.validate(RRSets[record_type], RRSigs[record_type], {zone_name: zsks_and_ksks})
            
            return True

        except dns.dnssec.ValidationFailure:
            return False
    

    def _verify_zsk(self, zone_name, dnskey_response):
        """  
        @params:
        - zone_name: Complete domain name rather than zones. E.g: cs.stonybrook.edu
        - dnskey_response: Response to the DNSKEY query

        @function:
        - Sign ZSK with KSK and compare it with RRSig to verify 
        """
        try:
            zsks_and_ksks = dnskey_response.answer[0]
            rrsig_zsk = dnskey_response.answer[1]
            dns.dnssec.validate(zsks_and_ksks, rrsig_zsk, {dns.name.from_text(zone_name): zsks_and_ksks})
            return True
        except dns.dnssec.ValidationFailure:
            return False


    def _check_trust(self, zone_name, main_response, redirection_history):
        """ 
        @params:
        - zone_name: Complete domain name rather than zones. E.g: cs.stonybrook.edu
        - main_response: Response to the original DNS query for A/NS/MX records
        - redirection_history: List of all the IPs of the previous nameservers queried 

        @function:
        - Get the ZSK, KSK and RRSig by sending the DNSKEY query to the final authoritative nameserver
        - Trace the route upwards and verify the KSKs for each zone.
        - If all the KSKs up the chain are valid, ZSK and RRSig can be consequently verified using it
        - Verify ZSK for the domain using the validated KSK (chain of trust)
        - Verify RRSet using ZSK for the domain
        """
        n = len(redirection_history)-1

        # Query FINAL authoritative nameserver for DNSKEY record 
        # For querying DNSKEY records use tcp instead of udp otherwise you won't get RRsig record if you go with udp
        dnskey_query = dns.message.make_query(zone_name, dns.rdatatype.DNSKEY, want_dnssec=True)
        dnskey_response = dns.query.tcp(dnskey_query, redirection_history[n]) 

        main_dnskey_response = dnskey_response
        
        # DNSSec is not enabled if response to the DNSKEY record is empty
        if len(dnskey_response.answer)==0:
            raise NoDNSSECSupportError(zone_name)

        # Traverse up the chain and verify the KSKs for each zone
        for i in range(n, 1, -1):

            # Get hashed KSK of the child from the parent via DS record
            ds_query = dns.message.make_query(zone_name, dns.rdatatype.DS, want_dnssec=True)
            ds_response = dns.query.tcp(ds_query, redirection_history[i-1])

            # Extract KSK from the dnskey_response 
            # ZSKs and KSKs are present in answer[0] and RRSig in answer[1]
            ksks = []
            for key in dnskey_response.answer[0]:
                if key.flags == 257:
                    ksks += [key]

            # Verify KSK for the current zone
            ksk_check = self._verify_ksk(zone_name, ksks, ds_response)
            if not ksk_check:
                raise KSKVerificationError(zone_name)
                
            # Query intermediate nameservers for the DNSKEY record to verify KSKS for all of them
            dnskey_query = dns.message.make_query(zone_name, dns.rdatatype.DNSKEY, want_dnssec=True)
            dnskey_response = dns.query.tcp(dnskey_query, redirection_history[i-1])
        
        # Verify ZSK for the final authoritative nameserver
        zsk_check = self._verify_zsk(zone_name, main_dnskey_response)
        if zsk_check==False: 
            raise ZSKVerificationError(zone_name)

        # Verify RRSet received as the response
        rrset_check = self._verify_rrset(zone_name, main_response, main_dnskey_response)
        if rrset_check==False: 
            raise RRSetVerificationError(zone_name)


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
        main_query = dns.message.make_query(zone_name, type, want_dnssec=True)
        
        main_response, ns_ip = self._query_server(zone_name, main_query, nameservers)
        rrsets = main_response.authority + main_response.answer

        rrsets_dict = defaultdict(list)

        for rrset in rrsets:
            for resource_record in rrset:
                if resource_record.rdtype == dns.rdatatype.A:
                    rrsets_dict["A"] += [resource_record]
                elif resource_record.rdtype == dns.rdatatype.MX:
                    rrsets_dict["MX"] += [resource_record]
                elif resource_record.rdtype in (dns.rdatatype.NS, dns.rdatatype.CNAME):
                    rrsets_dict["NS"] += [resource_record]

        return rrsets_dict, ns_ip, main_response


    def resolve(self, hostname, type):
        self.logs = []
        if type not in ("A", "NS", "MX"): raise ResourceRecordTypeError(type)

        rdatatype = {"A":dns.rdatatype.A, "NS": dns.rdatatype.NS, "MX": dns.rdatatype.MX}

        timestamp = self._current_timestamp()
        start_time = time.time()

        hostname = hostname.replace("https://","").replace("http://","").replace("www.","").rstrip(".")+"."
        n = len(hostname.split("."))-1

        i=0
        redirection_history = []
        main_response = None
        while i<n:
            
            if i==0:
                nameservers = self.root_servers_ip

            # Query the nameservers iteratively
            rrsets, ip, main_response = self._get_resource_records(hostname, rdatatype[type], nameservers)
            redirection_history += [ip]

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
        # Run DNSSec on top of DNS
        if type in ("A", "MX") and rrsets.get(type, None) is None:
            rrsets, ip, main_response = self._get_resource_records(hostname, rdatatype[type], nameservers)
            redirection_history += [ip]
            self._check_trust(hostname, main_response, redirection_history)
            
        elif type in ("A", "MX") and rrsets.get(type, None) is not None:
            self._check_trust(hostname, main_response, redirection_history)

        records = "\n".join([record.to_text() for record in rrsets[type]])
        response = str(records).rstrip("\n")

        msg_size = sys.getsizeof(response)
        end_time = time.time()

        time_elapsed = int(round((end_time - start_time) * 1000)) 

        reply = f"QUESTION SECTION:\n{hostname}\t\tIN\t{type}\n\nANSWER SECTION:\n{response}\
            \n\nQuery time: {time_elapsed} msec\nWHEN: {timestamp}\n\nMSG SIZE rcvd: {msg_size}\n"

        return reply

