#!/usr/bin/env python3
"""
Helper script to start both nodes automatically
Run this script to launch both Node A and Node B
"""

import subprocess
import time
import sys

def start_node(name, host, port, peer_host, peer_port):
    """Start a chat node in a new terminal window"""
    if sys.platform == "win32":
        # Windows
        cmd = f'start cmd /k python chat_node.py {name} {host} {port} {peer_host} {peer_port}'
    elif sys.platform == "darwin":
        # macOS
        cmd = f'''
        osascript -e 'tell app "Terminal" to do script "cd \\"{__file__}\\"/.. && python3 chat_node.py {name} {host} {port} {peer_host} {peer_port}"'
        '''
    else:
        # Linux
        cmd = f'''
        gnome-terminal -- bash -c "python3 chat_node.py {name} {host} {port} {peer_host} {peer_port}; exec bash"
        '''
    
    subprocess.Popen(cmd, shell=True)
    time.sleep(1)  # Give time for terminal to open

def main():
    print("Starting Distributed Chat Application...")
    print("This will open two terminal windows for Node A and Node B")
    print("-" * 50)
    
    # Configuration
    config = {
        "Node A": ("A", "127.0.0.1", 5000, "127.0.0.1", 5001),
        "Node B": ("B", "127.0.0.1", 5001, "127.0.0.1", 5000)
    }
    
    # Start both nodes
    for node_name, params in config.items():
        print(f"Starting {node_name}...")
        start_node(*params)
    
    print("\nBoth nodes have been started!")
    print("Instructions:")
    print("1. Type your message and press Enter to send")
    print("2. Type 'exit' to quit")
    print("3. Messages from peer will appear automatically")
    print("\nYou can now chat between Node A and Node B!")

if __name__ == "__main__":
    main()