# TCP Packet Analyzer

## Purpose
The purpose of this project is to analyze TCP traffic and understand the details of state management in the Transmission Control Protocol (TCP). This tool processes packet capture (pcap) files and computes summary information about TCP connections, providing insights into the protocol's behavior.
It computes key statistics such as the number of packets sent, bytes transferred, and calculates Round Trip Time (RTT) values based on TCP packet acknowledgments.

## Background
TCP is a core protocol of the Internet Protocol Suite, enabling reliable, ordered, and error-checked delivery of data. Understanding TCP state management, such as connection establishment and termination, is critical for analyzing network performance and troubleshooting.

In this project, a TCP connection is identified by a 4-tuple:
- Source IP address
- Destination IP address
- Source port
- Destination port

Packets flow in both directions (duplex) and are arbitrarily interleaved in time. The program associates packets with the correct connection and extracts meaningful statistics.


## Features
- **Connection Tracking**: Tracks unique TCP connections using the 4-tuple.
- **State Analysis**: Identifies connection states (e.g., S1F1, S2F2, R) based on SYN, FIN, and RST flags.
- **RTT Calculation**: Computes Round Trip Time (RTT) using the first matching ACK for each data packet.
- **Data Analysis**: Reports:
  - Number of packets sent in both directions.
  - Total bytes transferred.
  - Connection durations.
- **Statistical Summary**: Provides minimum, mean, and maximum values for:
  - Connection durations.
  - RTT values.
  - Packet counts.
  - Receive window sizes.

## Usage:
### Prerequisites:
		- Ensure Python 3 is installed on your machine. 
		- This program also requires access to a pcap file to analyze.

### Run the Analyzer:
To use the TCP Packet Analyzer, run the following command:
```bash
python TCPAnalyzer.py input_file.cap
```

## Output:
The script will output details in a structured format:
	-Total number of TCP connections.
	-Details of each connection:
		-Source and destination addresses.
		-TCP ports used.
		-Number of packets sent/received.
		-Number of bytes transferred.
		-Duration of the connection.
		-RTT statistics for each connection (minimum, mean, and maximum).

### Example Output
You can refer to the **output-24** or **outputformat.pdf** or see below:
```bash
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
```

## Assumptions/Limiations 
There are many simplications done to bring down the scope of the project the most signficant being:
	- The analysis is based on the top-down approach: the trace is scanned from top to bottom, and only the first matching ACK is considered for RTT calculations.
	- Packets without a matching ACK are ignored in RTT calculations.
	- Incomplete packets are skipped to ensure data accuracy.
	- This tool assumes the input is well-formed TCP traffic in a pcap file.
	- The RTT calculation may slightly overestimate due to the use of the first matching ACK, which is a known limitation in network analysis.
	- A connection is defined as a Unique 4 tuple of (source_ip, dest_ip, source_port, dest_port).
	- Completed connections are those with atleast 1 Syn and atleast 1 Fin.
	- Connections start at the first Syn sent and end at the last Fin sent.
	- Only IVP4 wrapped TCP packets are analyzed.

## Files in the project
- **TCPAnalyzer.py**: The main script that performs the analysis.
- **sample-capture-file.cap**: A sample pcap file used for testing and development.
- **output-24** or **outputformat.pdf**: Examples of programs output with the output-24 being the output for the sample-capture-file.cap.
- **p2.pdf**: A full project descrption.
- **Q&A-Assignment2-2024.pdf**: Additional clarifications and frequently asked questions.