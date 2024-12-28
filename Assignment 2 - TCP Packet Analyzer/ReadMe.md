TCP Packet Analyzer

This tool is a TCP Packet Analyzer that processes a pcap (packet capture) file to analyze TCP connections. 
It computes key statistics such as the number of packets sent, bytes transferred, and calculates Round Trip Time (RTT) values based on TCP packet acknowledgments.

Features:
	-Connection Tracking: Tracks each unique TCP connection based on IP addresses and ports.
	-RTT Calculation: Calculates RTT using the first matching ACK for each data packet.
	-Data Analysis: Reports the number of packets, bytes transferred, and connection duration.
	-TCP Flags: Tracks SYN, FIN, and RST flags to determine connection status.
Output Summary: Provides a detailed summary of each TCP connection, including minimum, mean, and maximum RTT values.

Usage:
	Prerequisites:
		-Ensure Python 3 is installed on your machine. This script also requires access to a pcap file to analyze.

	Run the Analyzer:
		-To use the TCP Packet Analyzer, run the following command:
			python TCPAnalyzer.py input_file.cap

Output:
	The script will output details in a structured format:
		-Total number of TCP connections.
		-Details of each connection:
			-Source and destination addresses.
			-TCP ports used.
			-Number of packets sent/received.
			-Number of bytes transferred.
			-Duration of the connection.
			-RTT statistics for each connection (minimum, mean, and maximum).
Example Output:

	A) Total number of connections: X
	________________________________________________

	B) Connections' details:
	Connection 1:
	Source Address: 
	Destination address: 
	Source Port: 
	Destination Port: 
	Status: 
	Start time: seconds
	End Time: seconds
	Duration: seconds
	Number of packets sent from Source to Destination: 
	Number of packets sent from Destination to Source: 
	Total number of packets: 
	Number of data bytes sent from Source to Destination: 
	Number of data bytes sent from Destination to Source: 
	Total number of data bytes: 
	..
	..
	..
	Connection N
	Source Address: 
	Destination address: 
	Source Port: 
	Destination Port: 
	Status: 
	Start time: seconds
	End Time: seconds
	Duration: seconds
	Number of packets sent from Source to Destination: 
	Number of packets sent from Destination to Source: 
	Total number of packets: ZZ
	Number of data bytes sent from Source to Destination: 
	Number of data bytes sent from Destination to Source: 
	Total number of data bytes: 
	________________________________________________

	C) General

 	The total number of complete TCP connections: 
	The number of reset TCP connections: 
	The number of TCP connections that were still open when the trace capture ended:
 	The number of TCP connections established before the capture started: 
	________________________________________________
	
	D) Complete TCP connections:
 
	Minimum time duration: 
	Mean time duration: 
	Maximum time duration: 

	Minimum RTT value: 
	Mean RTT value: 
	Maximum RTT value: 

	Minimum number of packets including both send/received: 
	Mean number of packets including both send/received: 
	Maximum number of packets including both send/received: 

	Minimum receive window size including both send/received: 
	Mean receive window size including both send/received: 
	Maximum receive window size including both send/received:

Assumptions/Limiations 
	There are many simplications done to bring down the scope of the project the most signficant being:
		-The analysis is based on the top-down approach: the trace is scanned from top to bottom, and only the first matching ACK is considered for RTT calculations.
		-Packets without a matching ACK are ignored in RTT calculations.
		-Incomplete packets are skipped to ensure data accuracy.
		-This tool assumes the input is well-formed TCP traffic in a pcap file.
		-The RTT calculation may slightly overestimate due to the use of the first matching ACK, which is a known limitation in network analysis.
		-A connection is defined as a Unique 4 tuple of (source_ip, dest_ip, source_port, dest_port).
		-Completed connections are those with atleast 1 Syn and atleast 1 Fin.
		-Connections start at the first Syn sent and end at the last Fin sent.
		-Only IVP4 wrapped TCP packets are analyzed.
	