import subprocess
import re
import os
import html
from datetime import datetime

def run_Tec_tool():
    print('[-] run tec tool discovery...')


    bash_script = """
    #!/bin/bash
    # ==========================================
    # Reconnaissance Automation Script
    # ==========================================

    RED='\\033[0;31m'
    GREEN='\\033[0;32m'
    YELLOW='\\033[1;33m'
    BLUE='\\033[0;34m'
    NC='\\033[0m'

    if [ -z "$1" ]; then
        echo -e "${RED}[!] Error: No target URL provided.${NC}"
        echo -e "${YELLOW}[-] Usage: $0 <http://target-url.com>${NC}"
        exit 1
    fi

    TARGET="$1"

    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        TARGET="http://$TARGET"
        echo -e "${YELLOW}[+] No protocol specified, defaulting to http. Target set to: $TARGET${NC}"
    fi

    echo -e "${BLUE}==================================================${NC}"
    echo -e "${BLUE}       Starting Recon for: $TARGET               ${NC}"
    echo -e "${BLUE}==================================================${NC}\\n"

    TOOLS=("whatweb" "wpscan")
    for TOOL in "${TOOLS[@]}"; do
        if ! command -v $TOOL &> /dev/null; then
            echo -e "${RED}[!] Error: $TOOL is not installed. Please install it before running this script.${NC}"
            exit 1
        fi
    done

    echo -e "${GREEN}[*] Phase 1: Running WhatWeb (Stealthy - Aggression Level 1)...${NC}"
    whatweb -a 1 --no-errors "$TARGET" 2>/dev/null
    echo -e "\\n"

    echo -e "${GREEN}[*] Phase 2: Running WhatWeb (Aggressive - Aggression Level 3)...${NC}"
    whatweb -a 3 --no-errors "$TARGET" 2>/dev/null
    echo -e "\\n"

    echo -e "${GREEN}[*] Phase 3: Running WPScan (Enumeration)...${NC}"
    wpscan -e --url "$TARGET" --ignore-main-redirect 2>/dev/null

    echo -e "\\n${BLUE}==================================================${NC}"
    echo -e "${GREEN}       Reconnaissance Complete!                  ${NC}"
    echo -e "${BLUE}==================================================${NC}"
    """

    
    target = input('writing your target => ')
    if not target:
        print("[!] No target provided.")
        return
    

    try:
        
        result = subprocess.run(
            ["bash", "-c", bash_script, "bash", target],
            capture_output=True,
            text=True
        )
    except FileNotFoundError:
        
        print("\n" + "="*50)
        print("[!] CRITICAL ERROR: 'bash' command not found!")
        print("[!] It seems you are on Windows and Bash (WSL/Git Bash) is not installed or not in PATH.")
        print("[!] Please install 'Windows Subsystem for Linux (WSL)' or 'Git Bash',")
        print("[!] and ensure 'bash' is accessible from your command prompt.")
        print("="*50 + "\n")
        return
    except Exception as e:
        print(f"\n[!] An unexpected error occurred while executing bash: {e}\n")
        return


    if result.stdout:
        print(result.stdout)
    if result.stderr:
    
        print("[*] Stderr:\n", result.stderr)

    
    clean_output = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', result.stdout or "")

    
    safe_target = html.escape(target)
    safe_output = html.escape(clean_output)

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>MRSCRIPT Tec Report - {safe_target}</title>
        <style>
            body {{ background-color: #0d1117; color: #c9d1d9; font-family: 'Courier New', monospace; padding: 30px; }}
            pre {{ background: #161b22; padding: 20px; border-radius: 5px; border: 1px solid #30363d; white-space: pre-wrap; word-wrap: break-word; }}
            h2 {{ color: #58a6ff; }}
        </style>
    </head>
    <body>
        <h2>Target: {safe_target} | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
        <pre>{safe_output}</pre>
    </body>
    </html>
    """

    os.makedirs("MRSCRIPT_Reports", exist_ok=True)

    
    safe_name = re.sub(r'^https?://', '', target)
    safe_name = re.sub(r'[\\/:*?"<>|]+', '_', safe_name).strip('_') or "target"

    with open(f"MRSCRIPT_Reports/Tec_{safe_name}.html", "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n[+] HTML report saved in MRSCRIPT_Reports/Tec_{safe_name}.html")


