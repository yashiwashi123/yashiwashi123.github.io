# Iced ID Backconnect Server Tracking


#### Summary

This tutorial servers as a means to track BokBot, also know as IcedID, BackConnect infrastructure. BackConnect servers are used as C2 and include an VNC module thus allowing TAs remote access. They additinoally turn victim machines into socks5 proxies and allow TAs to execude commands remotely. You can read more about BackConnect [here](https://www.team-cymru.com/post/inside-the-icedid-backconnect-protocol).

This is a tutorial on how to track IcedID backconnect infrastructure. 

Based on my research, you can find BokBot/IcedID backconnect servers using Censys search relatively easily. 

#### Censys Query

You can accomplish this by running this query in Censys: 
```services.banner="-bad format\n"```

These ```-bad format\n``` banners typically appear on ports ```8084``` and ```8085```. 

#### Validation

Now, I have run into at least one instance where a server had these ports open, and the banned read ```-bad format\n```, but the server was benign. 

Fortunately I came up with a script to quickly validate your potential backconnect servers. 

This script was developed by reading through [xors](https://nikpx.github.io/) technical analysis and finding a implementation of BokBot's BackConnect command decryption algorithm in python.

```python
ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))

max_bits = 64
#Encodes function address  0x000002442432D450
encoded_function = ror(0x000002442432D450 ^ 0x123456789ABCDEF,7,64)
decoded_function_address = hex(rol(encoded_function,7,64) ^ 0x123456789ABCDEF)

```

I extended this script by allowing the user to send encrypted data to a potential C2, running it through the decode function above, and printing the result. This script contains a base64 encoded string that BackConnect servers expect from new victims. It is esentially mimicking a compromised host asking the server for furture commands. I obtained this string by looking at a pcap of a compromised host uploaded to [Brad's wonderful blog](malware-traffic-analysis.net) and looking through communications between the compromised host and the C2. Eventually I found a crypted string that was a bot registration packet in the pcap.

Here is the full script: 

```
import socket
import base64
import binascii
import struct

based64 = "G7ey0ARiplH11970TRWco/rCSC1tnNYX1grGnx6ZXWcs+T+AJBrE1jonFcCb++vXtQyMjGvhGpsa4LRjxiNmUnc7DIXXAjfifmxZBd8/Lxv6UdHQryZf4F/XC1XdVprAiVKXO+i2eybCsJ1JJIRzXz6VFRXzaqMkoxtQmSKa3wTOltx/LPq/awb04o1oyLijgtlZWTiu52jnX5TdZt8jSBLbIMNxPgSvSzkm0qwM/OjGHZ2dfPIrrCuk2CGqI2eNVh9kB7WDSPOPfWoW8VBALAti4uHAN3DxcOgdZu9nq9GbY6hM+ceMN9PBrlo1lYVwT6YmJgV7tDW0"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Change the IP here 
s.connect(("ENTER IP HERE", 443))
s.send(base64.b64decode(based64))
msg = s.recv(1024)

ror = lambda val, r_bits, max_bits: \
    ((val & (2**max_bits-1)) >> r_bits%max_bits) | \
    (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))

rol = lambda val, r_bits, max_bits: \
    (val << r_bits%max_bits) & (2**max_bits-1) | \
    ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))


def decrypt_packet(crypted_packet):
    key = struct.unpack("<I", crypted_packet[:4])[0]
    crypted_packet = crypted_packet[4:]
    decrypted_packet = bytearray()
    for i in range(len(crypted_packet)):
        decrypted_byte = (crypted_packet[i] ^ (key & 0xff))
        decrypted_packet.append(decrypted_byte)
        key = i + rol(key, 7, 32) + 1
        key &= 0xFFFFFFFF

    print(decrypted_packet)
decrypt_packet(msg)
print(binascii.hexlify(msg))
```

