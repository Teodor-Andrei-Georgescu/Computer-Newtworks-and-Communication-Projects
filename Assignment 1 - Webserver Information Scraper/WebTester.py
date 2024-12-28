import socket
import ssl
import re
import sys
'''
This project was coded by Teodor Andrei Georgescu (V00979120)
'''

'''
This function will be used to parse a user provided URI.
We are parsing it for the following infromation:
    -protocol (http or https)
    -a specifed port (or just used default based on protocol if nothing else provided)
    -a specified path (or just use "/" if nothing else provided)
    -a hostname (domain name)
Once we have this information we return it to be used further.
'''
def parse_uri(uri):
    #Check if the protocol is HTTP or HTTPS or throw error if its neither
    #Prepare the default port number to use
    if uri.startswith("https://"):
        protocol = "https"
        uri = uri[8:]
        default_port = 443
    elif uri.startswith("http://"):
        protocol = "http"
        uri = uri[7:]
        default_port = 80
    else:
        #raise ValueError("Unsupported protocal, only HTTP and HTTPS are currently supported.")
        protocol = "http"
        default_port = 80

    #Split remainder of URI into hostname and path by looking for first "/"
    #If no "/" is found, the host is the entire remainder of the URI and path is just "/"
    if '/' in uri:
        host_section, path = uri.split('/',1)
        path = '/' + path
    else:
        host_section = uri
        path = '/'

    #Split the host into hostname and port by looking for a ":"
    #If no ":" is found, the port is the default port for the protocol and the whole this is the hostname
    if ':' in host_section:
        hostname, port = host_section.split(':')
        port = int(port)
    else:
        hostname = host_section
        port = default_port
        
    return protocol, hostname, port, path

'''
This is a helper function that will send a request to a specifed host through a given port, protocol and at a specific location (path).
All this given information will come from Parsing the URI with parse_uri.
This function will return the response from the server to be further processed a needed.
'''
def send_http_or_https_request(protocol, hostname, port,path):
    #Create our socket
    try:
        our_socket= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print("There was an error creating the socket.")
        print("Please try again or ask somebody else for help.")
        sys.exit()
    
    #Wrap the socket with SSL if the protocol is HTTPS
    if protocol == "https":
        context = ssl.create_default_context()
        try:
            our_socket = context.wrap_socket(our_socket,server_hostname=hostname)
        except socket.error:
            print("There was an error wrapping the socket.")
            print("Please try again or ask somebody else for help.")
            sys.exit()

    #Prepare request, connect to host, send request, and store response.
    request = f"HEAD {path} HTTP/1.1\r\nHost: {hostname}\r\n\r\n".encode()
    try:
        our_socket.connect((hostname,port))
    except socket.error:
        print("There was an error connecting to the host.")
        print("Please try again, ask somebody else for help, or double check the URI you are provding.")
        sys.exit()
        
    try:
        our_socket.send(request)
    except socket.error:
        print('There was an error senind the HTTP request')
        sys.exit()
        
    try:
        response = our_socket.recv(4096).decode()
    except socket.error:
        print('There was an error receiving the HTTP response')
        sys.exit() 
    
    our_socket.close()
    
    if "404" in response:
        print("Error page does not exist.")
        print('')
        print("Please check your provided URI.")
        sys.exit()
    #Return response provided by our host for further processing
    return response

'''
This is a very smaller helper that simply looks at if the response contains a HTTP 401 response.
If it does then we know the page is password protected and return that.
'''
def check_password_protection(response):
    if "401 Unauthorized" in response:
        return "yes"
    else:
        return "no"


'''
This helper function goes through the response and extracts the cookies (if any) and their desired information:
    -cookie name (if any)
    -expiry (if any)
    -domain (if any)
Then we return the cookies in a desired format ready to be printed or that no cookies were found.
'''
def extract_cookies_list(response):
    #Search response for cookie headers.
    cookies = re.findall("Set-Cookie: (.+)",response)
    formated_cookies = []
    
    #If there are cookies we need to go through and extract the desired information
    #We use regex for ease of searching.
    if cookies != []:
        for cookie in cookies:
            cookie_name = re.search("(.*?)[=:]",cookie)
            if cookie_name:
                cookie_name = "cookie name: " + cookie_name.group(1)
            
            expiry = re.search("expires=(.*?);",cookie)
            if expiry:
                expiry = ", expires time: " + expiry.group(1)
            
            domain = re.search("domain=(.*?);",cookie)
            if domain:
                domain =", domain name: " + domain.group(1)

            #At this point we found all information we want if it exists and are ready to format it.
            #Once formated we add to a list to store it
            formated_cookie = (cookie_name or '') + (expiry or '') + (domain or '') 
            formated_cookies.append(formated_cookie)
        
        #Now that we have all the cookies nicely formated we return the list    
        return formated_cookies
    
    #There were no cookies in response
    else:
        return "No Cookies Found"

'''
This is helper function to check for an HTTPS server if h2 is supported.
Essentially we create a new socket and wrap it, but we also use the ALPN extension.
This ALPN (Application layer protocol negotiation) extension allows us to negotiate which protocol to use.
Using this we connect to the host and see h2 is a supported option.

Please note that there is no error checking for the sockets here.
This is because by the time this helper is called we would have already managed to connect before.
If an error were to occur I dont see why it would happen after being successful atleast once before.
'''
def http2_supported_via_alpn(host,port):
    #Create socket, add ALPN for h2, wrap it, connect to host, and store negotiated protocol.
    context = ssl.create_default_context()
    context.set_alpn_protocols(['http/1.1', 'h2'])
    our_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    our_socket = context.wrap_socket(our_socket,server_hostname=host)
    our_socket.connect((host,port))
    protocol = our_socket.selected_alpn_protocol()
    our_socket.close()

    #We check h2 was protocol negotiated with host.
    #Then return if prototocl is supproted.
    if protocol == "h2":
        return "yes"
    else:
        return "no"

'''
This is a helper funtion for HTTP servers to check if h2c, HTTPS's h2 counterpart, is supported by the server.
Essentailly we just create a new socket and sent a specific request to the host at the specifed path.
This specific request should prompt a response that indicates if server supports h2c.
Then we return if it is supported or not.

Please note that there is no error checking for the sockets here.
This is because by the time this helper is called we would have already managed to connect before.
If an error were to occur I dont see why it would happen after being successful atleast once before.
'''
def check_h2c_support(hostname,path,port):
    #Creating a socket, preparing specific request, connecting to host, sending request, then storing response.
    our_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    request = f"HEAD {path} HTTP/1.1\r\nHost: {hostname}\r\nAccept: */*\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n\r\n".encode()
    our_socket.connect((hostname,port))
    our_socket.send(request)
    response = our_socket.recv(4096).decode()
    our_socket.close()
    
    #Checking if server supports h2c by looking for specific response headers.
    #Then returning if it is supported.
    if "101 Switching Protocols" in response:
        return "yes"
    else:
        return "no"

'''
This helper function is used to check if a particular response has given the 301/302 HTTP response code.
Those codes mean the location of the host has either temporaily or permanently moved.
Either way if we get one of those codes we want to send another request to the new location and get a new response.
We keep sending these request until the resposnes no longer have this 301/302 error code meaning we are finally not being redirected anymore.
Once we are doing being redirected we return the response so it can be passed to the other helpers and we can extract information.
'''
def handle_redirects(response, protocol ,hostname, port, path):
    #If the 301 or 302 response is there we need to follow redirect.
    #Search for the new "location" in the response and store it as our "new_uri".
    #The we parse this "new uri" for needed information by calling parse_uri.
    #Then we passed needed information to send_http_or_https_request and send a request to this new URI 
    #Finally we recursively call handle_redirects function so that if the new response also has 302/301 we follow the "new uri again".
    if "301" in response or "302" in response:
        for line in response.splitlines():
            if line.startswith("Location:"):
                new_uri = line.split(": ")[1]
                #print(f"Redirecting to new uri {new_uri}")
                new_protocol, new_hostname, new_port, new_path = parse_uri(new_uri)
                new_response = send_http_or_https_request(new_protocol, new_hostname, new_port, new_path)
                return handle_redirects(new_response, new_protocol, new_hostname, new_port, new_path)
    
    #Eventually (or on the first try) the response no longer has 301/302 so its not a redirect response.
    return response

'''
This main function simply calls helper functions above with their needed arguments to complete the task.
The task being to connect to a provided URI and search desired infromation.
The desired information is:
    -the website name
    -if http2 is supported
    -the cookies (if any)
        -cookie name
        -cookie expiry
        -cookie domain
    -if the uri is password protected
Once infromation is collected it is printed out for user to see.
'''
def main():
    if len(sys.argv) > 2:
        print("Too many arguments provided")
        print("Please use the following example as refernce")
        print("")
        print("python3 WebTester.py https://example.com/path/to/whatever/if/any")
        print('or')
        print('python3 WebTestery.py example.com')
        exit()
    elif len(sys.argv) < 2:
        print("Not enough arguments provided")
        print("Please use the following example as refernce")
        print("")
        print("python3 WebTester.py https://example.com/path/to/whatever/if/any")
        print('or')
        print('python3 WebTester.py example.com')
        exit()
    
    '''
    Store the inputed URI then parse it to extract the protocol, hostname, port, and path.
    '''    
    uri = sys.argv[1]
    protocol, hostname, port, path = parse_uri(uri)

    '''
    Use extracted information from URI and sent the request to the desired host then store the response
    '''
  
    response = send_http_or_https_request(protocol, hostname, port, path)
    '''
    The orginal response above could have return 301/302 permanetly/temporily moved.
    As a result we run it through a function to check if we have been redicted and then to handle the redirects.
    The output will be a normal 200 ok response when no longer get redirected.
    '''
    final_response = handle_redirects(response,protocol,hostname,port,path)

    '''
    Printing website name as asked by specification.
    '''
    print(f"website: {hostname}")

    '''
    Depending on the type of protocal we call the corresdponing function to check for compatability.
    HTTPS we look for h2 compatability.
    HTTP we look for h2c compatability.
    Then we store response and print it as asked by specification.
    '''
    if protocol == "https":
        http2_support = http2_supported_via_alpn(hostname,port)
    else:
        http2_support = check_h2c_support(hostname,path,port)
    print(f"1. Supports http2: {http2_support}")

    '''
    We provide the final response after all redirects into the function to parse for the cookies
    If no cookies were found that is printed, otherwise cookies are fromated in specifed format and printed.
    '''
    cookies_list = extract_cookies_list(final_response)
    if cookies_list == "No Cookies Found":
        print("2. List of Cookies:")
    else:
        print("2. List of Cookies:")
        for cookie in cookies_list:
            print(f"cookie name: {cookie}")

    '''
    The last thing we do is check the final response to see if host is password proected.
    Then store and print the result as asked by specification.
    '''
    password_protected = check_password_protection(final_response)
    print(f"3. Password-protected: {password_protected}")

if __name__ == "__main__":
    main()
