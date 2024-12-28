import struct
import socket
import sys

'''
This is a class to parse the Global header of a capture file and grab the magic number.
The magic number is then used to determine the endianness of the packets and how to read them.
'''
class Global_Header:
    magic_number = None    

    def __init__(self, global_header):
        self.magic_number= struct.unpack('I', global_header[:4])[0]
        
    def endianness(self):
        is_little_endian = (self.magic_number == 0xa1b2c3d4)
        if is_little_endian:
            endian_prefix = '<' 
        else:
            endian_prefix = '>'
        
        return endian_prefix

'''
This is a class to parse the packet header and unpack all the fields.
'''
class Packet_Header:
    ts_sec = None
    ts_usec = None
    incl_len = None
    orig_len = None	
    
    def update_header_info(self,packet_header,endian_prefix):
        self.ts_sec, self.ts_usec, self.incl_len, self.orig_len = struct.unpack('IIII', packet_header)

'''
Class to unpack the ethernet headers and read the type field.
We then want to check if the type field is set to IPv4 or not.
    Code was written based on assigment where we only considered IPv4 packets.
'''
class Eth_header:
    eth_type= None
    
    def set_eth_type(self,packet_data):
        eth_type = struct.unpack('!H', packet_data[12:14])[0]
        if eth_type == 0x0800:
            self.eth_type = "IVP4"
        else:
            self.eth_type == "Not IVP4"

'''
Class to read and unpack the IPv4 header and all the important details.
'''
class IP_Header:
    verson = None
    ihl = None
    total_length = None
    identification = None
    flags = None
    fragment_offset = None
    ttl = None
    protocol = None
    source_ip = None
    dest_ip = None
    
    def update_header_info(self,packet_data):
        #offsetting to correst spot in packet data and reading that IP header.
        ip_header_start = 14
        ip_header = packet_data[ip_header_start:ip_header_start + 20]
        iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        #now storing all read IP header data by its corresponding fields.
        version_ihl = iph[0]
        #Shifting right by 4 bits to only have the version bits
        self.version = version_ihl >> 4
        #Using AND mask to only get ihl bits then multiplying by 4 to get the value in bytes
        self.ihl = (version_ihl & 0x0F) *4
        self.total_length = iph[2]
        self.identification = iph[3]
        #flags and offset are in same 16 bit segment
        flags_fragment_offset = iph[4]
        #ensuring only top 3 bits are saved as those are the flag bits
        self.flags = (flags_fragment_offset >> 13) & 0x07
        #ensuring bottom 13 bits are saved as they are the fragment offset then multiplying by 8 to get value in bytes
        self.fragment_offset = (flags_fragment_offset & 0x1FFF) *8
        self.ttl = iph[5]
        self.protocol = iph[6]
        #neat function that easy reads the 32 bit ip values and translates them into IPv4 format we know
        self.source_ip = socket.inet_ntoa(iph[8])
        self.dest_ip = socket.inet_ntoa(iph[9])

'''
Class to read UDP header and store all values.
'''
class UPD_header:
    source_port = None
    dest_port = None
    udp_length = None
    checksum = None
    
    def update_header_info(self,packet_data, ip_header_length):
        #ensuring we read correct part of packet data
        ip_header_start = 14
        udp_header_start = ip_header_start + ip_header_length
        udp_header = packet_data[udp_header_start:udp_header_start + 8]
        udph = struct.unpack('!HHHH', udp_header)
        
        self.source_port = udph[0]
        self.dest_port = udph[1]
        self.udp_length = udph[2]
        self.checksum = udph[3]

'''
Class to parse ICMP header and store all values.
This also takes into account differences between Windows and linux implementations of traceroute.
    Windows and linux both use the ICMP packets a bit different for traceroute.
'''
class ICMP_Header:
    type = None
    code = None
    soruce_port = None
    dest_port = None
    sequence = None
    
    def update_header_info(self,packet_data, ip_header_length):
        #RMaking sure we get correct offset to readt the type and code
        icmp_header_start = 14 + ip_header_length
        icmp_header = packet_data[icmp_header_start:icmp_header_start + 8]
        icmph = struct.unpack('!BBHHH', icmp_header)
        
        #type and code are important as they indicate what type of ICMP reply was given and will indicate what we have to do.
        self.type = icmph[0]
        self.code = icmph[1]
        
        #If the ICMP type is 8 or 0 we simply need to read the sequence.
        if self.type == 8 or self.type == 0: #Echo request/reply
            self.sequence = icmph[4]

        #If if itsnt a type 8 or 0 there is a ICMP header followed by another IP header and then finally is the information we want.
        payload_start = icmp_header_start + 8 + ip_header_length
        if len(packet_data) >= payload_start + 8:
            payload = packet_data[payload_start:payload_start + 8]
            icmp = struct.unpack('!HHHH', payload)
            self.source_port = icmp[0]
            self.dest_port = icmp[1]
            if self.type != 8 and self.type != 0:
                self.sequence = icmp[3]
        else:
            # Default to 0 if ports are not available
            self.source_port = 0
            self.dest_port = 0
        
'''
A class that is used to keep track of each packet itself and upde information about each header.
'''
class Packet:
    global_header = None
    packet_header = None
    eth_header = None
    ip_header = None
    udp_header = None
    icmp_header = None
    data = None
    timestamp = None
    
    def __init__(self):
        self.global_header = None
        self.packet_header = Packet_Header()
        self.eth_header = Eth_header()
        self.ip_header = IP_Header()
        self.udp_header = UPD_header()
        self.icmp_header = ICMP_Header()
        self.data = b''
        self.timestamp = 0

    def update_global_header(self, global_header):
        self.global_header = Global_Header(global_header)
        
    def update_packet_header(self,packet_header):
        endian_prefix = self.global_header.endianness()
        self.packet_header.update_header_info(packet_header, endian_prefix)
    
    def data_read(self,data):
        self.data = data
    
    def set_timestamp(self,first_packet_time):
        seconds = self.packet_header.ts_sec
        microseconds = self.packet_header.ts_usec
        self.timestamp = 1000 * round(seconds + microseconds * 0.000000001 - first_packet_time, 6)
    
    def update_eth(self):
        self.eth_header.set_eth_type(self.data)
    
    def update_ip_header(self):
        self.ip_header.update_header_info(self.data)
    
    def update_icmp_header(self):
        self.icmp_header.update_header_info(self.data, self.ip_header.ihl)     
        
    def update_upd_header(self):
        self.udp_header.update_header_info(self.data, self.ip_header.ihl)

'''
A helper function that given is given information about capture file onces its all been processed.
After capture file is processed there a list of 
    -packets from soruce
    -packets from destinations
    -the time of the first packet in the caputre

All that information then can to be processed to determine
    -the intermediate ips between source and destination
    -all intermidate packets
    -the RTT for all of these packets
'''
def determine_intermediate_ips_and_rtt(source_packets,destination_packets,start_time):
        #Depedning on if traceroute was done on windows ors linux we process things differently
        
        #For windows implmentation ICMP packets are used for all communcation
        #Specifcally ICMP type 8 (echo ping) is used as out going messages is if there at any packets with this value
        #We know this is a widnows traceroute and analyze accordingly
        if any(packet.icmp_header.type == 8 for packet in destination_packets):
            
            #the way we parsed the capture file we placed all ICMP messages in the destination_packets
            icmp_all = destination_packets
            source_packets = []
            destination_packets = []
            
            #Since we know this is windows
            #Messages from source are Type 8 (echo ping)
            #Responses from destinations are type 0 (echo reply) or type 11 (time exceeded)
            for packet in icmp_all:
                if packet.icmp_header.type == 8:
                    source_packets.append(packet)
                if packet.icmp_header.type == 11 or packet.icmp_header.type == 0:
                    destination_packets.append(packet)
            
            #Now that the packets are correctly sorted for a windows traceroute we begin looking for the intermediate ips and track thier RTTs
            intermediate_ips = []
            intermediate_packets = []
            rtt_tracker = {}
            
            #For each packet sent from source we check each reply form destination
            for packet1 in source_packets:
                for packet2 in destination_packets:
                    #If the packets having matching icmp sequence numbers we know they are a request and reply pair 
                    if packet1.icmp_header.sequence == packet2.icmp_header.sequence:
                        #if the packet from the destination has an ip we havent stored yet then it is a new intermediate ip.
                        if packet2.ip_header.source_ip not in intermediate_ips:
                            intermediate_ips.append(packet2.ip_header.source_ip)
                            intermediate_packets.append(packet2)
                            rtt_tracker[packet2.ip_header.source_ip] = []

                        #Otherwise we already have entry for the intermediate ip so we now want to calculate the RTT
                        packet1.set_timestamp(start_time)
                        packet2.set_timestamp(start_time)
                        rtt_tracker[packet2.ip_header.source_ip].append(packet2.timestamp - packet1.timestamp)
        
        #If none of the ICMP messages are type 8 then we know we have a capture file using a link implementation of traceroute.
        #Linx traceroutes used UDP as the messages going out from the source and have ICMP replies of type 11 and0 
        else:
            #No need to update the source and destination packets list since they were parsed and stored for this type of traceroute.
            #Can simply being analyzing.
            intermediate_ips = []
            intermediate_packets = []
            rtt_tracker = {}

            #For each packet sent from source we check each reply form destination
            for packet1 in source_packets:
                for packet2 in destination_packets:
                    #Again in linux implementation the source sends out UDP packets and get ICMP replies.
                    #The ICMPs are formated in such a way they we are able to extra port information.
                    #We can check if packets are request and reply by checking if the ports between UDP request and ICMP reply match.
                    if packet1.udp_header.source_port == packet2.icmp_header.source_port:
                        #if the packet from the destination has an ip we havent stored yet then it is a new intermediate ip
                        if packet2.ip_header.source_ip not in intermediate_ips:
                            intermediate_ips.append(packet2.ip_header.source_ip)
                            intermediate_packets.append(packet2)
                            rtt_tracker[packet2.ip_header.source_ip] = []
                        
                        #Otherwise we already have entry for the intermediate ip so we now want to calculate the RTT
                        packet1.set_timestamp(start_time)
                        packet2.set_timestamp(start_time)
                        rtt_tracker[packet2.ip_header.source_ip].append(packet2.timestamp - packet1.timestamp)
        
        return source_packets,destination_packets,intermediate_ips,intermediate_packets,rtt_tracker

'''
This is a helper check how many fragments there are for each datagram.
'''
def fragement_calcuations(source_packets):
    #A dictionary to store the fragments for each datagram storing by the datagram identification 
   
    frag_packet_match = {}
    
    #for all packets check they have a matching datagram identification and store the packet
    for packet in source_packets:
        if packet.ip_header.identification not in frag_packet_match:
            frag_packet_match[packet.ip_header.identification] = []
        
        frag_packet_match[packet.ip_header.identification].append(packet)
    
    #This frag count is just to check if there are than any fragments
    frag_count = 0
    for identity in frag_packet_match:
        if len(frag_packet_match[identity]) > 1:
            frag_count += 1    
   
    
    return frag_packet_match,frag_count

'''
A helper function that given is given information about a capture file once its all been processed.
After capture file is processed there a list of 
    -packets from soruce
    -packets from destinations
    -which protocls were used
    -the time of the first packet in the capture

This function then takes this information and calls other helpers as needs or processes information itself.
Once all is processed the information is printed in assignments specified format.
'''
def format_and_print(source_packets,destination_packets,protocol_used,start_time):
    
    # Print the table with horizontal line dividers
    print("{:<5} {:<60} {}".format('Row', 'Components', 'Details'))
    print("=" * 90)
    
    update_source_packets, updated_destination_packets , intermediate_ips,intermediate_packets,rtt_tracker = determine_intermediate_ips_and_rtt(source_packets,destination_packets,start_time)
    source_ip = update_source_packets[0].ip_header.source_ip
    dest_ip = update_source_packets[0].ip_header.dest_ip

    # Display each rubric component with row numbers and horizontal dividers
    print("{:<5} {:<60} {}".format('1', 'The IP address of the source node (R1)', source_ip))
    print("-" * 90)
    print("{:<5} {:<60} {}".format('2', 'The IP address of ultimate destination node (R1)', dest_ip))
    print("-" * 90)
    print("{:<5} {:<60} {}".format('3', 'The IP addresses of the intermediate destination nodes (R1)', ', '.join(intermediate_ips[0:len(intermediate_ips)-1])))
    print("-" * 90)
    print("{:<5} {:<60} {}".format('4', 'The correct order of the intermediate destination nodes (R1)', ', '.join(intermediate_ips[0:len(intermediate_ips)-1])))
    print("-" * 90)
    
    # Protocol values
    protocol_details = ", ".join("{}: {}".format(p, 'ICMP' if p == 1 else 'UDP' if p == 17 else 'Unknown') for p in sorted(protocol_used))
    print("{:<5} {:<60} {}".format('5', 'The values in the protocol field of IP headers (R1)', protocol_details))
    print("-" * 90)

    frag_packet_match, frag_count = fragement_calcuations(update_source_packets)
    
    frag_count = len(frag_packet_match[update_source_packets[0].ip_header.identification])
    if frag_count == 1:
        frag_count = 0 
    # Fragmentation details for first datagram
    print("{:<5} {:<60} {}".format('6', 'The number of fragments created from the original datagram (R1)', frag_count))
    #cacluclate and print fragement count for all datagrams aside from the first
    for identity in sorted(frag_packet_match):
        if identity == update_source_packets[0].ip_header.identification or identity < update_source_packets[0].ip_header.identification:
            continue
        frag_count = len(frag_packet_match[identity])
        if frag_count == 1:
            frag_count = 0
        print("{:<5} {} {:<17} {}".format('', 'The number of fragments created from datagram',identity, frag_count))
    print("-" * 90)
    
    #calculate the last fragment offset for the first datagram
    packets = frag_packet_match[update_source_packets[0].ip_header.identification]
    offset = packets[len(packets)-1].ip_header.fragment_offset
    print("{:<5} {:<60} {}".format('7', 'The offset of the last fragment (R1)', offset))
    #Calculate and print all last fragment offset values for all datagrams side from the first
    for identity in sorted(frag_packet_match):
        if identity == update_source_packets[0].ip_header.identification or identity < update_source_packets[0].ip_header.identification:
            continue
        frag_count = len(frag_packet_match[identity])
        if frag_count == 1:
            offset = 0
        else:
            packets = frag_packet_match[identity]
            offset = packets[len(packets)-1].ip_header.fragment_offset
        print("{:<5} {} {:<19} {}".format(' ', 'The last fragments offset from datagram ',identity, offset))
    print("-" * 90)
    
    #This is calculation for the ultimate destination node.
    dest_ip = update_source_packets[0].ip_header.dest_ip
    avg_rtt = round(sum(rtt_tracker[dest_ip]) / len(rtt_tracker[dest_ip]), 6)
    std_dev_rtt = round( (sum(pow(x-avg_rtt,2) for x in rtt_tracker[dest_ip]) / len(rtt_tracker[dest_ip]))**0.5, 6)
    
    # RTT details
    print("{:<5} {:<60} {} ms".format('8', 'The avg RTT to ultimate destination node (R1)', avg_rtt))
    #calculation and printing avg rrt between soruce and intermediate ips
    for i in range(len(intermediate_ips)-1):
        avg_rtt = round(sum(rtt_tracker[intermediate_ips[i]]) / len(rtt_tracker[intermediate_ips[i]]), 6)
        print("{:<5} {:<20}{:<12}{:<5}{:<11}{:<6} {} ms".format(' ', 'The avg RTT between ',update_source_packets[0].ip_header.source_ip," and ",intermediate_ips[i]," is:", avg_rtt))
    print("-" * 90)
    
    print("{:<5} {:<60} {} ms".format('9', 'The std deviation of RTT to ultimate destination node (R1)', std_dev_rtt))
    #calculation and printing s.d rtt between soruce and intermediate ips
    for i in range(len(intermediate_ips)-1):
        avg_rtt = round(sum(rtt_tracker[intermediate_ips[i]]) / len(rtt_tracker[intermediate_ips[i]]), 6)
        std_dev_rtt = round((sum(pow(x-avg_rtt,2) for x in rtt_tracker[intermediate_ips[i]]) / len(rtt_tracker[intermediate_ips[i]]))**0.5, 6)
        print("{:<5} {:<16}{:<12}{:<5}{:<11}{:<3} {} ms".format(' ', 'The s.d between ',update_source_packets[0].ip_header.source_ip," and ",intermediate_ips[i]," is:", std_dev_rtt))
    print("-" * 90)
    
    
    # R2 TTL probe calculation:
    ttl_dict = {}
    for p in update_source_packets:
        if p.ip_header.ttl not in ttl_dict:
            ttl_dict[p.ip_header.ttl] = []
        ttl_dict[p.ip_header.ttl].append(p)

    #print(ttl_dict)
    #for ttl in sorted(ttl_dict):
    #    print("ttl: {:2d} -> {} probes".format(ttl, len(ttl_dict[ttl])))
        #print(len(ttl_dict[ttl]))
    # Probes and question answers
    print("{:<5} {:<60} {}".format('10','The number of probes per TTL (R2)', ', '.join("TTL {}: {}".format(ttl, len(probes)) for ttl, probes in ttl_dict.items())))
    print("-" * 90)
    print("{:<5} {:<60} {}".format('11', 'Right answer to the second question (R2)', 'please ignore and read pfd'))
    print("-" * 90)
    print("{:<5} {:<60} {}".format('12', 'Right answer to the third/or fourth question (R2)', 'please ignore and read pfd'))
    print("=" * 90)
'''
This function opens the capture file and parses it.
By the end it stores information about all the packets and the headers within each packet.
Then it also keep track of what protocols were used and the start time of the capture file later perform RTT>
'''
def parse_pcap(tracefile):
    #Open the capture file
    file = open(tracefile,'rb')

    #read the Global header
    global_header_data = file.read(24)
    
    #initalize the a few variables to keep track of information
    protocol_used = []
    source_packets = []
    destination_packets = []
    first_packet_start_time = None
    
    #After global header we just keep reading packets until the file ends.
    while True:
        #Read packer header data which is always 16 byte
        packet_header_data = file.read(16)

        #if the packet header is less that 16 then we are at the end of the file or there was some corruption
        if len(packet_header_data) < 16:
                break
        
        #if no issues reading packet header we cna create an object for it
        packet = Packet()
        packet.update_global_header(global_header_data)
        packet.update_packet_header(packet_header_data)
        
        #Packer header info was unpacked/updated above
        #Now we can get the incl of the packet to tell us how much data this packet has so we know how much to read
        incl_len = packet.packet_header.incl_len

        if first_packet_start_time == None:
            start_time = round(packet.packet_header.ts_sec + packet.packet_header.ts_usec * 0.000001, 6)
        
        #Read all packet data indicated by the packets incl_len
        packet.data_read(file.read(incl_len))
        
        #updated read ethernet header
        packet.update_eth()
        
        #Check if ethernet header type is IPv4 since thats all we care about for assignment
        if packet.eth_header.eth_type == "IVP4":
            
            #Read the ip header information in the packe
            packet.update_ip_header()
            
            #Second check to see IPv4 is being used
            if packet.ip_header.version == 4:
                
                #if IP used ICMP protocal we unpack ICP header and store it as a packet coming from destination.
                #Generally for traceroute ICMP packets come from destination -- Slight complication about ths with Linux vs Windows but thats dicussed above.
                if packet.ip_header.protocol == 1:
                    packet.update_icmp_header()
                    destination_packets.append(packet)
                    if 1 not in protocol_used:
                        protocol_used.append(1)
                
                #If Ip uses UDP protocol read the UDP header and store it as a packet going out from destination.
                #Linux traceroute sends out UDP messages from host.
                #Windows sends out ICMP but we deal with that elsewhere.
                if packet.ip_header.protocol == 17:
                    packet.update_upd_header()
                    #UDP messages need to be between these ports of assignment otherwise we pick up other packets we are meant to ignore
                    #Targeting just port 53 for DNS isnt enough as there are ICMPv6 packets and others that we process which we dont want to
                    if packet.udp_header.dest_port == 53 or packet.udp_header.source_port == 53:
                        continue
                    source_packets.append(packet)
                    if not (33434 <= packet.udp_header.dest_port <= 33534):
                        continue
                    if 17 not in protocol_used:
                        protocol_used.append(17) ## currently there are ICMP V6 pakcets being read which trigger this
                
                # if its neither protocol we dont care and go to the next iteration of the loop/next packet
                if packet.ip_header.protocol != 1 or packet.ip_header.protocol == 17:
                    continue
    
    #Once we have looped through all packets in capture file we will beign analyzing, formating and printing the information   
    format_and_print(source_packets,destination_packets,protocol_used,start_time)

'''
The main function that grabs users command line argument of the capture file then initates the parsing of the file.
'''
def main():
    if len(sys.argv) != 2:
        print("Usage: python ICMPAnalyzer.py <trace_file>")
        sys.exit(1)

    trace_file = sys.argv[1]
    parse_pcap(trace_file)

if __name__ == "__main__":
    main()
