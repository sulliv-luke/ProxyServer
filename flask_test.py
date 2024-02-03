from flask import Flask, jsonify
import string
import random

app = Flask(__name__)

def generate_large_text(size=1024):  # Size in kilobytes
    """Generate a large string of specified size in kilobytes."""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(size * 1024))  # 1 KB = 1024 bytes

@app.route('/get', methods=['GET'])
def get_hello_world():
    return jsonify({'message': 'Hello, world!'})

@app.route('/get_rand', methods=['GET'])
def get_random_text():
    large_text = generate_large_text(512)  # Generate 512 KB of random text
    return jsonify({'message': 'Hello, world!', 'largeText': large_text})

if __name__ == '__main__':
    app.run(debug=True, port=5050)

