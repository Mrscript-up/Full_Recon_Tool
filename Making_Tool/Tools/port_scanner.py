import requests
from pathlib import Path
import json
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor
import json
#----------------------

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

#----------------------

def print_error(massage):
    print(f'{RED}[!]{END} {massage}')

def print_status(massage):
    print(f'{GREEN}[+]{END} {massage}')

class start:
    def __init__(self,args):
        if args.subdomain_list:
            with open(args.subdomain_list , 'r') as file:
                re = file.read(args.subdomain_list)
            print(len(re))
            self.url_sb = re
        else:
            self.url = args.target_url
        self.user_list = args.user_list
        self.file_list = args.file_list
        self.time_out = args.time_out
        self.user_selection = []
        if args.status:
            self.importent_status_code = args.status
        else:
            self.importent_status_code = [200, 301, 302, 403, 401 ,400 ,500]
        self.output = args.output
        self.json_output = args.json

        
    
    def checking(self):
        if not self.url:
            print_error('you most select a target like =>\n -t https://example.com')
        if self.url:
            print('start option...')
            if self.user_list:
                l = '-' * 40
                number_of_urls = len(self.user_list.split(','))
                print(f"""
{l}
list default =\n {''.join(self.user_list)}
{l}
exmaple = https://example.com:{self.user_list.split(',')[0]}
{l}
const number_of_urls = {number_of_urls}
{l}
status codes = {','.join(map( str, self.importent_status_code))}
{l}
""")
                if self.file_list:
                    print(f'file list = {self.file_list}')
                    with open(self.file_list, 'r') as f:
                        file_list = f.read().splitlines()
                        file_list_main = ','.join(file_list)
                        print(f'file list = {file_list_main}')
                        self.user_selection.append(file_list_main)
                        print(self.user_selection)
                if not self.file_list:
                    try:
                        ready = input('are you ready to start? (y/n) => ')
                        if ready.lower() == 'y':
                            self.user_selection.append(self.user_list)
                        if ready.lower() == 'n':
                            print_error('Error')
                            sys.exit('see you leater...')

                    except Exception as E:
                        print_error(f'Error:\n{E}')
                    except KeyboardInterrupt:
                        print_error('BY')

    def start_port_scan(self):
        if self.url: 
            if self.user_selection:
                wordlist = self.user_selection

            if not self.user_selection:
                wordlist = self.user_list.split(',')
            for wordlistt in wordlist:
                urll = f'{self.url}:{wordlistt}'

            try:
                if self.url_sb:
                    sb_url = f'{self.url_sb:{wordlist}}'
                    for sb_option in sb_url:
                            r1 = requests.get(sb_option , timeout=self.time_out)
                            if r1.status_code in self.importent_status_code:
                                print_status(f"OK => ({r1.status_code}): \n{sb_option}")
                                print(f"{YELLOW}{'-'*20}{END}")

                if not self.url_sb:             
                    for urll in wordlist:
                    
                        r = requests.get(self.url , timeout=self.time_out)
                        if r.status_code in self.importent_status_code:
                            print_status(f"OK => ({r.status_code}): \n{urll}")
                            print(f"{YELLOW}{'-'*20}{END}")
                
                if self.output:
                    with open(f'{self.output}port_scan_res.txt','w') as f:
                        f.write(f'resoulve:\n{r.status_code} : {urll}\n')

                    print_status(f'done. [{self.output}port_scan_res.txt]')

                if self.json_output:
                    json.dump(self)

                                
            except Exception as E:
                print_error(f'Error {E}')
            except KeyboardInterrupt:
                print_error('BY')

        
if __name__ == "__main__":

    print(f"{BLUE}============================================={END}")
    print(f"{BLUE}            Port Scanner (Python) {END}")
    print(f"{BLUE}============================================={END}\n")
    print(f'''{BLUE}
exmaple:
exmaple = python port_scaner.py -t https://example.com
{RED}#dont write target like => https://example.com/ [dont use / ] #{END}
{END}
''')
    words = [122,2,3,4,5,6,7,8,9,10]
    argument_parser = argparse.ArgumentParser(description="""Port Scanner""")
    argument_parser.add_argument('-t', "--target_url", help="Target URL for reconnaissance")
    argument_parser.add_argument('-ul', "--user_list",default=f'{",".join(map(str,words))}' , help="personal domain list")
    argument_parser.add_argument('-fl', "--file_list", help="file list")
    argument_parser.add_argument('-T', "--time_out", help="default time out. [default=5]", default=5)
    argument_parser.add_argument('-s', "--status", help="add status code.")
    argument_parser.add_argument('-p', "--proxy", help="Proxy")
    # output option:
    argument_parser.add_argument('-j', "--json", help="json output.")
    argument_parser.add_argument('-o', "--output", help="output file.", default='./port_scaner/')
    #---------------
    argument_parser.add_argument('-sb', "--subdomain_list", help="subdomain list file for scan.")
    

    args = argument_parser.parse_args()
    ST = start(args)
    ST.checking()