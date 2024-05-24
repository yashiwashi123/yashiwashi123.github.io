import time
import string
import argparse
# new seed : 0x0A1FE2A56A2CFEC79

charset = string.ascii_lowercase + string.digits
print(charset)

def init_seed(magic: int):

    secs = 32
    month = 13 
    year = 1899 
    return magic + (secs | ((month + 256) << 8)) + year

def random_num(seed): 
    pass 

def random_num_generator(seed):

    seed = (1664525 * seed + 1013904223) & 0xFFFFFFFFFFFFFFFF

    v5 = 32
    while v5 > 0:
        v6 = (((seed >> 1) ^ -((seed & 1) != 0) & 0xF5000000) >> 1) ^ -((seed & 2) != 0) & 0xF5000000
        seed = (((v6 >> 1) ^ -((v6 & 1) != 0) & 0xF5000000) >> 1) ^ -((v6 & 2) != 0) & 0xF5000000
        v5 -= 4

    return seed 


def dga(seed, num_domains, domain_length): 
    for i in range(num_domains): 
        domain = ''
        for j in range(domain_length):
            print(seed)
            seed = random_num_generator(seed)
            
            domain += charset[seed % len(charset)]
        print(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser() 
    parser.add_argument("--seed", '-s', default=0x0A1FE2A56A2CFEC79)
    
    parser.add_argument("--length", '-l', type = int)
    parser.add_argument('--numd', '-n', type = int)
    args = parser.parse_args()
    print(args.seed)
    seed = init_seed(args.seed)
    dga(seed, args.numd, args.length)
    
