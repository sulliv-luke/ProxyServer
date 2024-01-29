import socket
import threading
import re
import logging

# Setting up the requestsLogger
requestsLogger = logging.getLogger('requestsLogger')
requestsLogger.setLevel(logging.DEBUG)
requests_file_handler = logging.FileHandler('requests.log')
requests_formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(message)s')
requests_file_handler.setFormatter(requests_formatter)
requestsLogger.addHandler(requests_file_handler)

# Setting up the relayLogger
relayLogger = logging.getLogger('relayLogger')
relayLogger.setLevel(logging.DEBUG)
relay_file_handler = logging.FileHandler('relay.log')
relay_formatter = logging.Formatter('%(asctime)s [%(threadName)s] %(message)s')
relay_file_handler.setFormatter(relay_formatter)
relayLogger.addHandler(relay_file_handler)


# Get-Content -Path "requests.log" -Wait 

class ProxyServer:

    def __init__(self, host, port, block_list):

        # Clear the log files at the start
        open('requests.log', 'w').close()
        open('relay.log', 'w').close()

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.block_list = block_list
        self.initialize_server()
        self.command_thread = threading.Thread(target=self.read_commands)
        self.command_thread.start()

    def initialize_server(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Proxy Server running on {self.host}:{self.port}")

    def handle_client(self, client_socket):
        request = client_socket.recv(1024).decode('utf-8')
        requestsLogger.debug(f"Request Received: {request}")

        # Check if the request is empty
        if not request:
            requestsLogger.warning("Empty request received. Ignoring.")
            client_socket.close()
            return

        # Check for URL Blocking
        url = self.get_url_from_request(request)
        normalized_url = self.normalize_url(url)
        normalized_block_list = [self.normalize_url(blocked_url) for blocked_url in self.block_list]
        if normalized_url in normalized_block_list:
            requestsLogger.debug(f"Blocked URL: {url}")
            client_socket.close()
            return
        
        # Check for HTTPS CONNECT method
        if request.startswith('CONNECT'):
            self.handle_https_request(client_socket, request)
        else:
            requestsLogger.debug(f"Handling HTTP request: {request}")
            # Forward the request and retrieve response
            response = self.forward_request(url, request)

            # Check if a valid response was received
            if response:
                requestsLogger.debug(f"Sending Response back to client. Response size: {len(response)} bytes")
                # Send the response back to the client
                client_socket.sendall(response)
            else:
                requestsLogger.debug("No response received from the server or error occurred.")

            client_socket.close()
    
    def handle_https_request(self, client_socket, request):
        requestsLogger.debug(f"Handling HTTPS request: {request}")
        target_host = request.split(' ')[1].split(':')[0]
        target_port = int(request.split(' ')[1].split(':')[1])

        # Establish connection to the target server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((target_host, target_port))

        # Send connection established message to the client
        client_socket.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')

        # Start threads to relay data with unique names
        client_to_server_thread = threading.Thread(target=self.relay_data, args=(client_socket, server_socket, True), name=f"ClientToServer-{target_host}:{target_port}")
        server_to_client_thread = threading.Thread(target=self.relay_data, args=(server_socket, client_socket, False), name=f"ServerToClient-{target_host}:{target_port}")

        client_to_server_thread.start()
        server_to_client_thread.start()

        # Don't join threads here, let them run in background

        """Joining a thread is a blocking operation, meaning it will halt the execution of the main thread until the joined thread completes. 
        In the context of a proxy server, you want the main thread to continue accepting new connections rather than waiting for 
        individual data relay operations to complete."""

    def relay_data(self, source, destination, close_source):    
        try:
            source_address = source.getpeername()
            destination_address = destination.getpeername()
            while True:
                try:
                    data = source.recv(4096)
                    if not data:
                        break
                    relayLogger.debug(f"Relaying {len(data)} bytes from {source_address} to {destination_address}")
                    destination.sendall(data)
                except ConnectionResetError:
                    relayLogger.warning("Connection was reset by the remote host.")
                    break  # Exit the loop if the connection is reset
                except socket.error as e:
                    relayLogger.error(f"Socket error: {e}", exc_info=True)
                    break  # Handle other socket-related errors
        except Exception as e:
            relayLogger.error(f"Unexpected error in relay_data: {e}", exc_info=True)
        finally:
            # Close only the source socket if it's specified to avoid closing twice
            if close_source:
                relayLogger.debug("Closing source socket")
                source.close()


    def extract_host_port(self, url):
        # Extracting host and port from a URL
        match = re.search(r'^(?:http://|https://)?([^:/]+)(?::(\d+))?', url)
        if match:
            host = match.group(1)
            port = match.group(2) if match.group(2) else (80 if url.startswith("http") else 443)
            return host, int(port)
        else:
            raise ValueError("Invalid URL")


    def forward_request(self, url, request):
        target_host, target_port = self.extract_host_port(url)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.connect((target_host, target_port))
            server_socket.sendall(request.encode())

            response = b''
            while True:
                part = server_socket.recv(4096)
                if not part:
                    break
                response += part
            return response
        except Exception as e:
            requestsLogger.error(f"Error in forward_request: {e}", exc_info=True)
            return None
        finally:
            server_socket.close()  # Ensures that this socket is always closed


    def get_url_from_request(self, request):
        # First line of the request should contain the method and URL
        first_line = request.split('\n')[0]
        url = ''
        if first_line:  # Check if first_line is not empty
            method, url_part, _ = first_line.split()
            if method == 'CONNECT':  # For CONNECT (HTTPS) requests
                # URL is in the format host:port for CONNECT requests
                # Remove the port number
                host = url_part.split(':')[0]
                url = 'https://' + host  # Add 'https://' to match the block list format
            else:
                # Extract the full URL for HTTP requests
                match = re.search(r'http://[^\s]+', request)
                if match:
                    url = match.group()
                    # Remove port from HTTP URL if present
                    url = re.sub(r':\d+', '', url)
        else:
            print(request)
        return url

    
    def normalize_url(self, url):
        # Remove http:// or https:// from the URL
        url = re.sub(r'^https?://', '', url)
        # Remove 'www.' from the URL if it exists
        url = re.sub(r'^www\.', '', url)
        # Remove port number if present
        url = re.sub(r':\d+', '', url)
        return url
    
    def read_commands(self):
        while True:
            command = input("> ")
            if command.startswith("block "):
                url = command.split(" ", 1)[1]
                if url == "--showall":
                    for url in self.block_list:
                        print(f"{url}")
                else:
                    self.block_list.append(url)
                    print(f"Blocked URL: {url}")
            elif command.startswith("unblock "):
                url == command.split(" ", 1)[1]
                print(f"{url}")
                if url in self.block_list:
                    self.block_list.remove(url)
                    print(f"Unblocked URL: {url}")
                else:
                    print(f"{url} already unblocked\n")
            elif command == "--help":
                print("Commands\n- block <url>: blocks url specified by <url>\n")
            else:
                print("Unknown command, use --help for a list of commands\n")


    def start(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            requestsLogger.debug(f"Connection established with {addr}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()


block_list = ['leetcode.com', 'www.yahoo.com']
proxy = ProxyServer('127.0.0.1', 4003, block_list)
proxy.start()
