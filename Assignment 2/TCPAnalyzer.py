import struct
import socket
from collections import defaultdict
import sys
#Coded by Teodor Andrei Georgescu

'''
This is a class created to keep track of each TCP connection and the values which matter to us in terms of the assignment.
'''
class TCPConnection:
    """
    This initaliztion of each function contains all the values we need.
    The values are set to default values.
    """
    def __init__(self, source_ip, dest_ip, source_port, dest_port):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.source_port = source_port
        self.dest_port = dest_port
        self.status = "S0F0"
        self.syn_count = 0
        self.fin_count = 0
        self.rst = False
        self.start_time = None
        self.end_time = None
        self.total_duration = None
        self.packets_src_to_dst = 0
        self.packets_dst_to_src = 0
        self.data_bytes_src_to_dst = 0
        self.data_bytes_dst_to_src = 0
        self.rtt_samples = []
        self.window_sizes = []
        self.sent_packets_timestamps = {}

    '''
    This function is for updating a portion of the values for each connection.
    '''
    def add_packet(self, packet_data, timestamp, src_to_dst=True):
        # Extract the TCP flags from the 13th byte of the TCP header
        # Make sure value is extracted as integer not byte.
        if isinstance(packet_data[13], int):
            tcp_flags = packet_data[13]
        else:
            tcp_flags = ord(packet_data[13])
        
        #Use bitwise and on the bytes that should be set if the corresponding flag is set.
        syn = tcp_flags & 0x02
        fin = tcp_flags & 0x01
        rst = tcp_flags & 0x04
        
        #If the flags are set update connection values accordingly.
        if syn:
            self.syn_count += 1
        if fin:
            self.fin_count += 1
            #Make sure the end time of each connection is the last packet with a FIN.
            self.end_time = timestamp
        if rst:
            self.rst = True

        # Update the status accordingly based on which flags may have been updated above.
        self.status = "S{}F{}".format(self.syn_count, self.fin_count)
        if self.rst:
            self.status = self.status + "/R"

        #Update the number of packets send in the corresponding direction.
        if src_to_dst:
            self.packets_src_to_dst += 1
        else:
            self.packets_dst_to_src += 1

        #The first packet in each connection should be the start time for the connection.
        if self.start_time == None:
            self.start_time = timestamp
        
        #This is is the method to update the endtime as the connection keeps going and no FIN.
        #This is so that we dont keep udpating it once we have gotten FINs as assginment spec
        #Says end time should be last FIN packet of connection.
        #This is also so connections that dont close dont error out with start_time(int) - end_time (None)
        if "F0" in self.status:
            self.end_time = timestamp
        
        #Update the durtion of the connection based on the end and start times.
        self.total_duration = self.end_time - self.start_time

'''
This is the function which parses the pcap files from top to bottom.
    Objects are created for each connection.
    All info for each connection is updated and store for later analysis.
'''
def parse_pcap(file_path):
    #Make a dictionary of objects(connetions) for easier analysis later.
    connections = defaultdict(TCPConnection)
    
    #Open the pcap file.
    with open(file_path, 'rb') as f:
        #Read global header and unpack magic number indicating packet endianess.
        global_header = f.read(24)
        magic_number = struct.unpack('I', global_header[:4])[0]
        
        #Do boolean check to see if magic number is littel or big endian and update the prefix accordinfly.
        is_little_endian = magic_number == 0xa1b2c3d4
        if is_little_endian:
            endian_prefix = '<' 
        else:
            endian_prefix = '>'
            
        #Variables used to get the time of the first packet 
        #then use that time to calculate all other packet time relative to first packet.
        first_packet = True
        time_in_first_packet =0
        
        #Once global header is read the rest of the file is just packet headers and payloads.
        #Reading all packets until the end until theres no more left.
        while True:
            
            #Read the packet header which is 16 bytes.
            #If less than 16 bytes then we likely have reached end of file.
            packet_header = f.read(16)
            if len(packet_header) < 16:
                break
            
            #Unpack the packet header into its components all at once using endian prefix we got from Global header.
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian_prefix + 'IIII', packet_header)
            
            #Get the timestamp of the packet relative to first packet in the file.
            timestamp = ts_sec + ts_usec/1000000.00 - time_in_first_packet
            
            #If this is the first packet then store its timestamp for later use
            #Then make timestamp 0 and change condtion to false to not enter condition again.
            if first_packet:
                time_in_first_packet = timestamp
                first_packet = False
                timestamp=0

            #Read the packet data using the incl_len field we grabbed from the header.
            packet_data = f.read(incl_len)
            #If the length is less than 14 bytes theres some issue so we will just skip to next packet.
            if len(packet_data) < 14:
                print("Incomplete packet data, skipping...")
                continue
            
            #If no issues we now unpack eth_type from ethernet header.
            eth_type = struct.unpack('!H', packet_data[12:14])[0]
            
            #Check if it's an IPv4 packet as assignment specifies we will only analyze those packets.
            if eth_type == 0x0800:
                
                #We know Ethernet header is always 14 bytes so we skipp head to 14 so we can read IP header.
                ip_header_start = 14
                
                #IP headers are atleast 20 bytes so we read that amount.
                ip_header = packet_data[ip_header_start:ip_header_start + 20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                #Read version_IHL
                #Also total_ip_length = ip header + TCP header + payload
                version_ihl = iph[0]
                total_ip_length = iph[2]
                #Bitwise and operations will all 1s for lower bytes ot get IHL value
                ihl = version_ihl & 0x0F
                
                #Right version_ihl 4 byte right so only version bytes remain.
                #Second check to ensure packet is IPV4 version
                if version_ihl >> 4 == 4:  # Version 4 for IPv4
                    
                    #Calculate true IP header length from IHL
                    ip_header_length = ihl * 4
                    protocol = iph[6]

                    #Check that IP protocol is TCP as we only want to analyze those packets.
                    if protocol == 6:  
                        
                        #Storing source and destination IP from  IP header.
                        source_ip = socket.inet_ntoa(iph[8])
                        dest_ip = socket.inet_ntoa(iph[9])
                        
                        #Now read TCP header whichwill start after IP header and is also 
                        #A minimum of 20 bytes long without options.
                        tcp_header_start = ip_header_start + ip_header_length
                        tcp_header = packet_data[tcp_header_start:tcp_header_start + 20]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        
                        #Store all information that is important from TCP header
                        source_port = tcph[0]
                        dest_port = tcph[1]
                        seq_num = tcph[2]
                        ack_num = tcph[3]
                        data_offset = (tcph[4] >> 4) *4
                        flags = tcph[5]
                        ack = flags & 0x10
                        window_size = tcph[6]
                        
                        #Calculate the Paylod length from Total length gotten from IP header - ip header length - data offset.
                        #Data offset is total length of TCP header including options.
                        #We use this method to avoid the padding 0s introduced by some ethernet headers.
                        tcp_payload_length = total_ip_length - ip_header_length - data_offset
                        
                        #Identify the connection by unique 4 tuple.
                        #We will be storing everything in an object with client side info.
                        #Reverse connection is done so it will match client side connection.
                        connection_id = (source_ip, dest_ip, source_port, dest_port)
                        reverse_id = (dest_ip, source_ip, dest_port, source_port)

                        #If the connection doesnt exist yet create and object and add it to the dictionary by the 4-tuple.
                        if connection_id not in connections and reverse_id not in connections:
                            connections[connection_id] = TCPConnection(source_ip, dest_ip, source_port, dest_port)
            
                        #Add packet to the correct connection but also keeping track of client or server side packet.
                        #Important to keep track so we update information for connection correctly. 
                        if connection_id in connections:
                            connections[connection_id].add_packet(tcp_header, timestamp, src_to_dst=True)
                            connections[connection_id].data_bytes_src_to_dst += tcp_payload_length
                            connections[connection_id].window_sizes.append(window_size)
                            #If client side we want to add packet to a dictionary with the expected ACK for RTT purposes.
                            expected_ack = seq_num +1 + tcp_payload_length
                            connections[connection_id].sent_packets_timestamps[expected_ack]= timestamp
                        else:
                            connections[reverse_id].add_packet(tcp_header, timestamp, src_to_dst=False)
                            connections[reverse_id].data_bytes_dst_to_src += tcp_payload_length
                            connections[reverse_id].window_sizes.append(window_size)
                            #If and ACK is set we want to match ack_num to the packet to whom its responding.
                            #We do this by checking dictionary and matching out ack_num.
                            #If we have a match then use timestamp in that match and this packet for one RTT caluclation in the connection.
                            #Also remove the macthed packet from dictionary so we dont double count RTT values.
                            if ack_num in connections[reverse_id].sent_packets_timestamps:
                                rtt = timestamp - connections[reverse_id].sent_packets_timestamps[ack_num] 
                                connections[reverse_id].rtt_samples.append(rtt)
                                connections[reverse_id].sent_packets_timestamps.pop(ack_num)
    return connections


'''
This is the function that read the dictionary of objects and sumarizes data into the format specified by assignment.
Then prints out the formated information.
Format details are included in the read me.
'''
def summarize_connections(connections):
    #A few variables to sumarize all values from all connections.
    output = []
    total_reset = 0
    total_open = 0
    total_before_capture = 0
    complete_connections = []
    all_packets_counts = []
    all_window_sizes = []
    all_rtt_samples = []
   
    #Format the printing out of total number of connectiions.
    output.append("A) Total number of connections: {}".format(len(connections)))
    output.append("________________________________________________\n")
    
    #Now being looping through all objects in dictionary and adding all information in desired format for printing.
    output.append("B) Connections' details:\n")
    for i, (conn_id, conn) in enumerate(connections.items(), 1):
        
        #Only complete conection with atleast 1 SYN and 1 find get all details printed out.
        #The atleast 1 SYN 1 FIN is an assignent specification.
        if "F0" not in conn.status and "S0" not in conn.status:
            output.append("Connection {}:".format(i))
            output.append("Source Address: {}".format(conn.source_ip))
            output.append("Destination address: {}".format(conn.dest_ip))
            output.append("Source Port: {}".format(conn.source_port))
            output.append("Destination Port: {}".format(conn.dest_port))
            output.append("Status: {}".format(conn.status))
            output.append("Start time: {:.6f} seconds".format(conn.start_time))
            output.append("End Time: {:.6f} seconds".format(conn.end_time))
            output.append("Duration: {:.6f} seconds".format(conn.total_duration))
            output.append("Number of packets sent from Source to Destination: {}".format(conn.packets_src_to_dst))
            output.append("Number of packets sent from Destination to Source: {}".format(conn.packets_dst_to_src))
            output.append("Total number of packets: {}".format(conn.packets_src_to_dst + conn.packets_dst_to_src))
            output.append("Number of data bytes sent from Source to Destination: {}".format(conn.data_bytes_src_to_dst))
            output.append("Number of data bytes sent from Destination to Source: {}".format(conn.data_bytes_dst_to_src))
            output.append("Total number of data bytes: {}".format(conn.data_bytes_src_to_dst + conn.data_bytes_dst_to_src))
            output.append("END")
        
        #If incomplete conection we only print out some details
        else:
            output.append("Connection {}:".format(i))
            output.append("Source Address: {}".format(conn.source_ip))
            output.append("Destination address: {}".format(conn.dest_ip))
            output.append("Source Port: {}".format(conn.source_port))
            output.append("Destination Port: {}".format(conn.dest_port))
            output.append("Status: {}".format(conn.status))
        
        #If connection is not the last one we use a differnt seperator as shown in sample output. 
        if i < len(connections.items()):
            output.append("++++++++++++++++++++++++++++++++")
        else:
            output.append("________________________________________________\n")

        #Updating general values that will be printed later.
        some_fins = True
        some_syns = True
        if conn.rst:
            total_reset += 1
        if "F0" in conn.status:
            total_open += 1
            some_fins = False
        if "S0" in conn.status:
            total_before_capture += 1
            some_syns = False
        
        #Store complete connections for later when we need to analyze all complete connections.
        if some_fins == True and some_syns == True:
            complete_connections.append(conn)
            all_packets_counts.append(conn.packets_src_to_dst + conn.packets_dst_to_src)
            all_window_sizes.extend(conn.window_sizes)
            all_rtt_samples.extend(conn.rtt_samples)
            
    #From complete connections get min,mean, and mx values for printing.
    durations = [conn.total_duration for conn in complete_connections if conn.total_duration]
    min_duration, mean_duration, max_duration = calculate_min_mean_max(durations)
    min_packets, mean_packets, max_packets = calculate_min_mean_max(all_packets_counts)
    min_window_size, mean_window_size, max_window_size = calculate_min_mean_max(all_window_sizes)
    min_rtt_value, mean_rtt_value, max_rtt_value = calculate_min_mean_max(all_rtt_samples)

    #Print all general information gotten from while looping through all connections.
    output.append("C) General\n")
    output.append("The total number of complete TCP connections: {}".format(len(complete_connections)))
    output.append("The number of reset TCP connections: {}".format(total_reset))
    output.append("The number of TCP connections that were still open when the trace capture ended: {}".format(total_open))
    output.append("The number of TCP connections established before the capture started: {}".format(total_before_capture))
    output.append("________________________________________________\n")
    
    #Print out all min,mean, and max values we are interested in for the complete connections.
    output.append("D) Complete TCP connections:\n")
    output.append("Minimum time duration: {} seconds".format(min_duration))
    output.append("Mean time duration: {} seconds".format(mean_duration))
    output.append("Maximum time duration: {} seconds\n".format(max_duration))
    
    output.append("Minimum RTT value: {}".format(min_rtt_value))
    output.append("Mean RTT value: {}".format(mean_rtt_value))
    output.append("Maximum RTT value: {}\n".format(max_rtt_value))
    
    output.append("Minimum number of packets including both send/received: {}".format(min_packets))
    output.append("Mean number of packets including both send/received: {}".format(mean_packets))
    output.append("Maximum number of packets including both send/received: {}\n".format(max_packets))
    
    output.append("Minimum receive window size including both send/received: {} bytes".format(min_window_size))
    output.append("Mean receive window size including both send/received: {} bytes".format(mean_window_size))
    output.append("Maximum receive window size including both send/received: {} bytes".format(max_window_size))

    #Prinout all formated information
    print("\n".join(output))

'''
This function takes a list of values and calculates the min, mean, and max for the list.
'''
def calculate_min_mean_max(values):
    if not values:
        return 0, 0, 0
    min_val = min(values)
    max_val = max(values)
    mean_val = sum(values) / len(values)
    return round(min_val,6), round(mean_val,6), round(max_val,6)


'''
Main function that check for input file from STDIN which should be a capture file.
Then reads parses the file with parse_pcap to get all connections and information about each.
Then uses summarize_connections to format all infromation about connections as specified in assignment and print it all out.
'''
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ourcode.py input_file.cap")
        sys.exit(1)
    
    file_path = sys.argv[1]
    connections = parse_pcap(file_path)
    summarize_connections(connections)
