#Webserver Information Scraper

## Purpose
This project, "WebTester," is a tool designed to collect basic information about a provided web server. It provides hands-on experience with socket programming and helps understand HTTP/HTTPS application-layer protocols.

## Background
- **HTTP/HTTPS**: HTTP (Hypertext Transfer Protocol) is used for communication among web servers and clients. HTTPS is HTTP over Transport Layer Security (TLS).  
- **Cookies**: Cookies are small pieces of data sent by a web server to a user's browser to store stateful information, like login status or user preferences. This project demonstrates basic cookie handling without relying on Python's cookie libraries.
- **Socket Programming**: Sockets are endpoints for communication between two devices in a network.

## Usage
The program accepts a web server URL or hostname as input in one of the following formats:
```bash
python3 WebTester.py www.uvic.ca
```
Other accepted formats for the provided webserver are:

	- http://www.uvic.ca
	- https://www.uvic.ca
	- www.uvic.ca
	- www.uvic.ca:[some port]
	- www.uvic.ca/path/to/reasource

## What the program does
Once this input as been provided the program:
 1. Creates a socket and connects to the server.
 2. Through HTTP or HTTPS it will sent requests and receive responses to collect basic information.
 3. The information will be provided as output and will contain the following:
	- The website URL
	- If http2 is supported
	- The list of cookies (if any)
		- cookie name (if any)
		- cookie expiry time (if any)
		- domain name
	- If the website is password protected

An **example of the ouput** if **www.uvic.ca** is the inputed server:
```bash
	website: www.uvic.ca
	1. Supports http2: no
	2. List of Cookies:
	cookie name: cookie name: PHPSESSID
	cookie name: cookie name: uvic_bar, expires time: Thu, 01-Jan-1970 00:00:01 GMT, domain name: .uvic.ca
	cookie name: cookie name: www_def
	cookie name: cookie name: TS018b3cbd
	cookie name: cookie name: TS0165a077, domain name: .uvic.ca
	3. Password-protected: no
```
## Error Handling
The program includes basic error handling to notify users of issues like:
	- The server being unreachable.
	- The server not supporting the requested protocol.
	- Invalid input URLs.
