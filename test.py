import requests
import time

# Function to perform a request and measure response time and size with higher precision
def measure_request(url, proxies=None, repeats=1):
    total_duration = 0
    total_size_bytes = 0
    for _ in range(repeats):
        start_time = time.perf_counter()  # Higher precision timing
        response = requests.get(url, proxies=proxies)
        duration = time.perf_counter() - start_time
        total_duration += duration
        total_size_bytes += len(response.content)
    
    average_duration = total_duration / repeats
    average_size_bytes = total_size_bytes / repeats
    response_size_kb = average_size_bytes / 1024  # Convert size to kilobytes for readability
    throughput_kb_per_second = response_size_kb / average_duration if average_duration > 0 else 0
    return average_duration, average_size_bytes, throughput_kb_per_second

# Adjust the script to use these more sensitive measurements

# Example usage
url = "http://127.0.0.1:5051/get"  # Adjust with your actual testing URL
#url = "http://httpbin.org/get"


# Measure without proxy
duration_without_proxy, size_without_proxy, throughput_without_proxy = measure_request(url, repeats=10)
print(f"Direct access - Duration: {duration_without_proxy:.4f} seconds, Size: {size_without_proxy:.2f} bytes, Throughput: {throughput_without_proxy:.4f} KB/s")

# Measure with proxy
duration_with_proxy, size_with_proxy, throughput_with_proxy = measure_request(url, proxies={"http": "http://127.0.0.1:4003", "https": "http://127.0.0.1:4003"}, repeats=10)
print(f"Proxy access - Duration: {duration_with_proxy:.4f} seconds, Size: {size_with_proxy:.2f} bytes, Throughput: {throughput_with_proxy:.4f} KB/s")

# Calculate and display bandwidth savings
bandwidth_savings_bytes = size_without_proxy - size_with_proxy
bandwidth_savings_percentage = (bandwidth_savings_bytes / size_without_proxy) * 100 if size_without_proxy > 0 else 0
print(f"Bandwidth Savings: {bandwidth_savings_bytes:.2f} bytes ({bandwidth_savings_percentage:.2f}%)")
