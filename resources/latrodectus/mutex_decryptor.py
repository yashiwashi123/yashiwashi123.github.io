import binascii
import struct 

def decode_str(s) -> str:
	is_wide_str = len(s) > 1 and s[1] == 0

	result_str = ""

	if not is_wide_str:
		result_str = s.decode("utf8")
	else:
		result_str = s.decode("utf-16le")
		
	if result_str.isascii():
		return result_str
	
	return ""

def decrypt(a1):
    result = bytearray()
	#carrot says endianess, I specifies it's a 4 byte unsigned int, signed would be lowercase
    key, encyrpted_length = struct.unpack("<IH", a1[:6]) 
    actual_len = (key ^ encyrpted_length) & 0xFFFF
	
    extracted_data = a1[6:6+actual_len]

    for i in range(actual_len):
        key = key + 1
        print(f"Debug: key: {hex(key)}, extracted_data[i] : {hex(extracted_data[i])}, result: {extracted_data[i] ^ key}")
        result.append((extracted_data[i] ^ key) & 0xFF)        
    
    #decoded = result.decode('utf-8')

    #decoded = result.decode('utf-16le')
    print(f"Debug: {len(result)} | {decode_str(result)}")
    #return decoded


barry = binascii.unhexlify('')
decrypt(barry)

'''
Steps to create ida pro 

Find all instances of a func, 
Look for lea instruction with rcx argument

Go through entire file 
'''