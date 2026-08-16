#!/usr/bin/env python3
import subprocess
import sys
import os
# main files:
import requests
import time

from Making_Tool.Automation_All.needs.tec2 import run_Tec_tool


BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

class Fucking_Start:
    def __init__(self,domain):
        self.target_domain = domain
        self.All_Output = []
        self.prosess_tool = []
        self.online_js_files = []
        self.clean_js_files = []

    def run_1_subdomain(self):
        print(f'Stating subdomain takover by these command :\nsubdomain.py -d {self.target_domain} -o subdomain_output/{self.target_domain}/')
        chaking_subdomain_file = os.path.exists('subdomain.py')
        if not chaking_subdomain_file.stderr:
            print('[subdomain.py] NOT FOUND.')
            check = False
        else:
            check = True
        if check == True:
            DOMAIN = self.target_domain
            res1 = subprocess.run(['./subdomain.py', '-d', f'{DOMAIN}', '-o', f'subdomain_output/{DOMAIN}/'],shell=True,capture_output=True)
            self.All_Output.append(f'subdomain_output/{DOMAIN}/')

            if res1.returncode == 0:
                print('finish subdomain.py tool \n stating next tool...')
                self.prosess_tool.append('FINISH_TOOL1')
            else:
                print(f'subdomain.py tool error :\n {res1.stderr.decode()}')
            
    def run_2_tec(self):
        if 'FINISH_TOOL1' in self.prosess_tool:
            checking = os.path.exists('tec.py')
            if not checking:
                print('FILE [tec.py] NOT FOUND!')
            else:
                run_Tec_tool(self.target_domain)
                self.All_Output.append(f'tec_Reports/Tec_{self.target_domain}.html')
                self.prosess_tool.append('FINISH_TOOL2')

    def run_3_spidering(self):
        if 'FINISH_TOOL2' in self.prosess_tool:
            checking = os.path.exists('spidering.py')
            if not checking:
                print(f"FILE [spidering.py] NOT FOUND!")
            else:
                print('run [spidering.py] tool...')

                res = subprocess.run(['./spidering.py', '-d', f'{self.target_domain}', '-o', f'./spidering_resoulve/{self.target_domain}'],shell=True,capture_output=True)
                
                if res.returncode == '0':
                    print('spidering processing done...')
                    self.prosess_tool.append('FINISH_TOOL3')
                    self.All_Output.append(f'spidering_resoulve/{self.target_domain}')
                else:
                    print(f'Erorr in processing \n {res.stderr.decode('utf-8')}')

    def run_bottom_cheking_files(self):
        if 'FINISH_TOOL3' in self.prosess_tool:
            print('starting cheking files process....')
            check1 = os.path.exists(f'./spidering_resoulve/{self.target_domain}')
            
            if not check1:
                print(f'FILE OR DIRECTORY [./spidering_resoulve/{self.target_domain}] {RED}NOT FOUND!{END}')
            else:
                os_out_dir = os.listdir(path=f'./spidering_resoulve/{self.target_domain}/')
                if 'all_things_in_katana.out' in os_out_dir:
                    print('extracking JS files...')
                    res = subprocess.run('grep', '-i', '".js"', f'./spidering_resoulve/{self.target_domain}/all_things_in_katana.out', '>>', './ALL_JS_FILES.txt',shell=True,capture_output=True)

                    if res.returncode == '0':
                        print('done process 1.\nstart process 2.')
                    else:
                        print(f"Error in run command\n [grep -i .js ./spidering_resoulve/{self.target_domain}/all_things_in_katana.out' '>>' './ALL_JS_FILES.txt']")
                        print(f'Error => {res.stderr.decode('utf-8')}')

                    che = os.path.exists('./ALL_JS_FILES.txt')
                    if che:
                        with open('ALL_JS_FILES.txt','r') as f:
                            READ = f.read()

                        print('start requesting files for cheking exist js files...')
                        print(f'{len(READ)} JS FILES.')

                        for URLS in READ:
                            res_req = requests.get(url={URLS})
                            if res_req.status_code == "200":
                                print(f'online => {URLS}')
                                self.online_js_files.append(URLS)

                        print('done access process.')
                        print(f'''
online js files:
{self.online_js_files}

ROW: {len(self.online_js_files)}

''')
                        print('starting download js files...')
                        time.sleep(2)
                        for URLS2 in self.online_js_files:
                            res_wget = subprocess.run(['wget', '-c', '--tries=5', '--timeout=30', '--user-agent="Mozilla/5.0"', f'-O ./script_js/{URLS2}', f'{URLS2}', '--no-check-certificate'],shell=True,capture_output=True)
                            time.sleep(2)
                        if res_wget.returncode == "0":
                            print('done wget js files.')
                        else:
                            print(f'Error in run wget command => \n{res_wget.stderr.decode('utf-8')}')

                        self.All_Output.append(f'script_js/{URLS2}')
                        os.remove(path='./ALL_JS_FILES.txt')
                        print('REMOVE FILE [ALL_JS_FILES.txt]')
                        lenn = os.listdir(path='./script_js/')
                        print(f'ALL CONT JS FILES: {len(lenn)}')
                        self.prosess_tool.append('FINISH_TOOL4')

                    if not che:
                        print(f'FILE [ALL_JS_FILES.txt] {RED}NOT FOUND!{END}')

    def run_cheking_js_files(self):
        if 'FINISH_TOOL4' in self.prosess_tool:
            print('starting cheking js files...')
            check = os.path.exists('./script_js/')
            if not check:
                print(f'DIRECTORY [./script_js/] {RED}NOT FOUND!{END}')
            else:
                print('starting cheking js files...')
                os_list = os.listdir(path='./script_js/')
                for jsfiles in os_list:
                        
                    if not os.path.exists(jsfiles):
                        print(f"FILE {jsfiles} {RED}NOT FOUND!{END}")
                    
                    try:
                        with open(jsfiles, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        
                        clean_content = content.replace(" ", "").replace("\n", "").replace("\r", "").replace("\t", "")
                        
                        
                        if not clean_content:
                            print(f"FILE {jsfiles} IS NULL!")
                            
                        
                        jsfuck_chars = set('[]()!+')
                        
                        
                        is_jsfuck = all(char in jsfuck_chars for char in clean_content)
                        
                        if is_jsfuck:
                            print(f"ITS A JSFUCK FILE {jsfiles}")
                            os.remove(jsfiles)
                        else:
                            print(f"ITS A PLAIN JS FILE {jsfiles}")
                            self.clean_js_files.append(jsfiles)

                    except Exception as e:
                        print(f"Error on reading process : {e}")
                print(f'cont of clean js files => {len(self.clean_js_files)}')
                print(f'Files => \n{self.clean_js_files}')
                self.prosess_tool.append('FINISH_TOOL5')
                self.All_Output.append('./script_js/')
                  

    def run_5_clern_js_files(self):
        if 'FINISH_TOOL5' in self.prosess_tool:
            
            from pathlib import Path

            
            print('[-] run clean js')

            script = """
            const fs = require('fs');
            const path = require('path');
            const { execSync } = require('child_process');

            const inputDir = './script_js/';
            const outputDir = './output_clean_js/';

            if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }

            const files = fs.readdirSync(inputDir).filter(file => {
                // filtering (Source Maps)
                if (file.endsWith('.js.map')) return false;
                // just js files...
                return file.endsWith('.js');
            });

            files.forEach(file => {
                const inputPath = path.join(inputDir, file);
                const baseName = path.basename(file, '.js');
                const outputFileName = `${baseName}_clean.js`;
                const outputPath = path.join(outputDir, outputFileName);

                // read file... (Obfuscation)
                const content = fs.readFileSync(inputPath, 'utf8');
                
                // simple check for JSFuck...
                const jsFuckRegex = /^[()[\]!+]+$/;
                const cleanContent = content.replace(/\s/g, ''); // for check...
                if (cleanContent.length > 20 && jsFuckRegex.test(cleanContent)) {
                    console.log(`[*] dont accept (JSFuck): ${file}`);
                    return; // dont processing
                }

                console.log(`[-] processing: ${file} ...`);

                try {
                    // dont give this tool brainfuck or jsfuck files.
                    execSync(`npx prettier --parser babel "${inputPath}" > "${outputPath}"`, { stdio: 'inherit' });
                    console.log(`[+] save (: ${outputFileName}\n`);
                } catch (err) {
                    console.error(`[!] error ${file} (anknow syntask for Prettier ): `);
                }
            });
            """
            path = Path('script.js')
            path.write_text(script,encoding='utf-8')
            subprocess.run(['node', 'script.js'],shell=True,capture_output=True)
            self.All_Output.append('./output_clean_js/')
            self.prosess_tool.append('FINISH_TOOL6')
            os.remove(path='./script.js')
    
    def run_js_linkfinder(self):
        if 'FINISH_TOOL6' in self.prosess_tool:
            print('start linkfinder tool...')
            check = os.path.exists(path='./_main_.py')
            if not check:
                print('FILE [_main_.py] NOT FOUND')
            else:
                FILES = './output_clean_js/'
                check2 = os.path.exists(path=FILES)
                if not check2:
                    print('Directory [output_clean_js/] NOT FOUND!')
                else:
                    res = subprocess.run(['./_main_.py', '-lfjs'],shell=True)
                    if res.returncode == "0":
                        print('write your files and those option that you want.')
                        print('use -h')
                    else:
                        print(f'Error in run [_main_.py]:\n{res.stderr.decode('utf-8')}')
                    

                
























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
    
