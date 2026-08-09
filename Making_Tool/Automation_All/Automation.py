#!/usr/bin/env python3
import subprocess
import sys
import os
# main files:




BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

class Fucking_Start:
    def __init__(self,domain):
        self.target_domain = domain
        self.All_Output = []

    def run_1_subdomain(self):
        print(f'Stating subdomain takover by these command :\nsubdomain.py -d {self.target_domain} -o subdomain_output/{self.target_domain}/')
        chaking_subdomain_file = subprocess.run(['ls', '|', 'grep', '-i', '"subdomain.py"'],shell=True,text=True)
        if chaking_subdomain_file.stderr:
            print('[subdomain.py] NOT FOUND!!')
            check = True
        if not chaking_subdomain_file.stderr:
            print('[subdomain.py] FOUND.')
        if check == True:
            DOMAIN = self.target_domain
            subprocess.run(['./subdomain.py', '-d', f'{DOMAIN}', '-o', f'subdomain_output/{DOMAIN}/'],shell=True,capture_output=True)
            self.All_Output.append(f'subdomain_output/{DOMAIN}/')
























if __name__ == "__main__":
    
    print(f'''                                        {GREEN}Automation Recon Tool{END}
Tools:
{GREEN}[-]{END} Subdomain Tackover
{GREEN}[-]{END} Tec Discovery
{GREEN}[-]{END} spidering attack
    {YELLOW}=>{END} download js files
        {YELLOW}=>{END} is js file junk?
            {YELLOW}=>{END} if yes {YELLOW}=>{END} cleanjs tool
                {YELLOW}=>{END} linkfinder {YELLOW}=>{END} is there is new js files {YELLOW}=>{END} linkfinder , secrets finder , taking information js , vulnerability scan
                {YELLOW}=>{END} secrets finder
                {YELLOW}=>{END} taking information js
                {YELLOW}=>{END} vulnerability scan
            {YELLOW}=>{END} if isnt 
                {YELLOW}=>{END} linkfinder {YELLOW}=>{END} is there is new js files {YELLOW}=>{END} linkfinder , secrets finder , taking information js , vulnerability scan
                {YELLOW}=>{END} secrets finder
                {YELLOW}=>{END} taking information js
                {YELLOW}=>{END} vulnerability scan
    {GREEN}[-]{END} comment finder
    {GREEN}[*]{END} compackt all resoulves
{GREEN}[-]{END} port scan {YELLOW}=>{END} take from subdomain tool.
    ''') 
    
