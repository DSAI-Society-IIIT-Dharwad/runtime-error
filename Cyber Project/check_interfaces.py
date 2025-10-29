#!/usr/bin/env python3
"""Check available network interfaces for packet capture."""

try:
    from scapy.all import get_if_list, get_if_addr, conf
    import subprocess
    import sys
    
    print("=== Network Interface Detection ===")
    print()
    
    # Get Scapy interfaces
    print("Scapy detected interfaces:")
    interfaces = get_if_list()
    for i, iface in enumerate(interfaces):
        try:
            addr = get_if_addr(iface)
            print(f"  {i+1}. {iface} - {addr}")
        except:
            print(f"  {i+1}. {iface} - No IP")
    
    print()
    
    # Try to get Windows interface info
    try:
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            print("Windows ipconfig output:")
            lines = result.stdout.split('\n')
            for line in lines:
                if 'adapter' in line.lower() or 'IPv4 Address' in line:
                    print(f"  {line.strip()}")
        print()
    except:
        pass
    
    # Recommend interface
    print("Recommendations:")
    active_interfaces = []
    for iface in interfaces:
        try:
            addr = get_if_addr(iface)
            if addr and addr != '127.0.0.1' and not addr.startswith('169.254'):
                active_interfaces.append((iface, addr))
        except:
            pass
    
    if active_interfaces:
        print("Active interfaces suitable for monitoring:")
        for iface, addr in active_interfaces:
            print(f"  - {iface} ({addr})")
        
        # Recommend the first non-loopback interface
        recommended = active_interfaces[0][0]
        print(f"\nRecommended interface: {recommended}")
        
        # Write to environment file
        with open('.env.live', 'w') as f:
            f.write(f"CAPTURE_MODE=live\n")
            f.write(f"IFACE={recommended}\n")
        print(f"Created .env.live with interface: {recommended}")
    else:
        print("No suitable interfaces found for monitoring")
        
except ImportError:
    print("Scapy not installed. Please install with: pip install scapy")
except Exception as e:
    print(f"Error: {e}")
