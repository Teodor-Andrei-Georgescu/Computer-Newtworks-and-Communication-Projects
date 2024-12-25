PURPOSE:
The purpose of this project is to be a tool that collects some basic information about a provided web server.

USAGE:
The program accepts a web server as an argument if provided like so:
	
	python3 WebTester.py www.uvic.ca

Other accepted formats for the provided webserver are:
	
	http://www.uvic.ca
	https://www.uvic.ca
	www.uvic.ca
	www.uvic.ca:[some port]
	www.uvic.ca/path/to/reasource

Once this input as been provided the program will create a socket and connect to the server.
Then through HTTP or HTTPS it will sent requests and receive responses to collect basic information.
The information will be provided as output and will contain the following:

	the website
	If http2 is supported
	the list of cookies (if any)
		cookie name (if any)
		cookie expiry time (if any)
		domain name
	if the website is password protected

An example of the ouput if www.uvic.ca is the inputed server is:

	website: www.uvic.ca
	1. Supports http2: no
	2. List of Cookies:
	cookie name: cookie name: PHPSESSID
	cookie name: cookie name: uvic_bar, expires time: Thu, 01-Jan-1970 00:00:01 GMT, domain name: .uvic.ca
	cookie name: cookie name: www_def
	cookie name: cookie name: TS018b3cbd
	cookie name: cookie name: TS0165a077, domain name: .uvic.ca
	3. Password-protected: no


There has been basic error handling implemented within this program to alert users of any problems.
