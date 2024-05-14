import time
import string

charset = string.ascii_lowercase + string.digits

def old_string_to_seed(string_seed): 
     seed = sum(ord(v) << i*8 for i, v in enumerate(string_seed))
     return seed

def random_num(seed): 
    pass 

def dga(seed, num_domains, domain_length): 
    for i in range(num_domains): 
        domain = ''
        for j in range(domain_length): 
            rand_num = random_num(r)
            domain += charset[rand_num % 24]
