import requests

# Proxy configuration
proxy_host = "127.0.0.1"
proxy_port = 4003
proxies = {
    "http": f"http://{proxy_host}:{proxy_port}",
    "https": f"http://{proxy_host}:{proxy_port}"
}

# HTTP request
url = "http://httpbin.org/get"  # A simple service for testing HTTP requests

try:
    response = requests.get(url, proxies=proxies)
    print("Response from server:\n", response.text)
except requests.exceptions.RequestException as e:
    print("Error making request:", e)
