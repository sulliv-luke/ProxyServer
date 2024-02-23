import hashlib
import select
import socket
import threading
import re
import logging
import time

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

        self.cache = {}  # Dictionary for storing cached responses
        self.default_ttl = 300  # Default TTL in seconds (e.g., 5 minutes)

        self.display_logs_active = False
        
        self.initialize_server()
        self.command_thread = threading.Thread(target=self.read_commands)
        self.command_thread.start()

    def initialize_server(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(9)
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
        
        cache_key = self.generate_cache_key(request)
        if self.is_cache_valid(cache_key):
            data = self.get_from_cache(cache_key)
            client_socket.sendall(data)
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

        # Notice we don't join threads here, let them run in background

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
        server_socket.settimeout(2.0)  # Set a timeout for connection operations

        try:
            server_socket.connect((target_host, target_port))
            server_socket.sendall(request.encode())

            response = bytearray()
            server_socket.setblocking(0)  # Set the socket to non-blocking mode

            content_length = None
            headers_received = False
            body_read = 0
            total_expected_length = None

            while True:
                ready = select.select([server_socket], [], [], 2.0)
                if ready[0]:
                    part = server_socket.recv(4096)
                    if not part:
                        break  # Break the loop if no more data is received

                    if not headers_received:
                        # Accumulate header data until headers are fully received
                        response.extend(part)
                        if b'\r\n\r\n' in response:
                            headers, body_initial = response.split(b'\r\n\r\n', 1)
                            headers_received = True
                            for line in headers.split(b'\r\n'):
                                if line.lower().startswith(b'content-length:'):
                                    content_length = int(line.split(b': ')[1])
                                    total_expected_length = content_length + len(headers) + 4  # Include header length and separator
                            response = bytearray(headers + b'\r\n\r\n' + body_initial)  # Reconstruct response with correct split
                            body_read += len(body_initial)
                    else:
                        # Directly append to response if headers are already processed
                        response.extend(part)
                        body_read += len(part)

                    # Check if we have read the entire content
                    if content_length is not None and len(response) >= total_expected_length:
                        break

            if response:
                cache_key = self.generate_cache_key(request)
                self.save_to_cache(cache_key, response)
            return bytes(response)
        except Exception as e:
            requestsLogger.error(f"Error in forward_request: {e}", exc_info=True)
            return None
        finally:
            server_socket.close()




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
                    # url = re.sub(r':\d+', '', url)
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
    
    def generate_cache_key(self, request):
        # Generate a unique cache key based on the request
        return hashlib.sha256(request.encode()).hexdigest()
    
    def is_cache_valid(self, cache_key):
        if cache_key in self.cache:
            timestamp, _ = self.cache[cache_key]
            if (time.time() - timestamp) < self.default_ttl:
                return True
        self.evict_expired_cache()
        return False
    
    def get_from_cache(self, cache_key):
        return self.cache[cache_key][1] if self.is_cache_valid(cache_key) else None
    
    def save_to_cache(self, cache_key, data):
        self.cache[cache_key] = (time.time(), data)

    def evict_expired_cache(self):
        current_time = time.time()
        expired_keys = [key for key, (timestamp, _) in self.cache.items() if (current_time - timestamp) >= self.default_ttl]
        for key in expired_keys:
            del self.cache[key]

    def display_logs(self, filename='./requests.log', interval=1.0):
        # Function to display to contents of the requests log files as they are updated
        self.display_logs_active = True
        with open(filename, 'r') as file:
            # Move the cursor to the end of the file
            file.seek(0, 2)
        
            while self.display_logs_active:
                # Read the next line
                line = file.readline()
            
                # If the line is non-empty, print it to the console
                if line:
                    print(line, end='')
                else:
                    # Wait for a short period before checking for new content
                    time.sleep(interval)
 
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
            elif command == "cache":
                for entry in self.cache:
                    print(f"{self.cache[entry]}\n")
            elif command == "clear cache":
                self.cache.clear()
            elif command == "requests --start":
                if not self.display_logs_active:  # Only start if not already active
                    print("Displaying requests...\n")
                    thread = threading.Thread(target=self.display_logs)
                    thread.daemon = True  # Daemonize thread
                    thread.start()
                else:
                    print("Log display already running\n")
            elif command == "requests --stop":
                self.display_logs_active = False
                print("Log display deactivated\n")
            elif command == "--help":
                print("Commands\n- block <url>: blocks url specified by <url>\n- unblock <url> unblocks specified url\n- cache: show all cached HTTP requests\n - clear cache: clears all cache entries")
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
