import subprocess

def run_Tec_tool():
    print('[-] run tec tool descovary...')
    
    def run():

        bash = """
        #!/bin/bash
        # ==========================================
        # Reconnaissance Automation Script
        # ==========================================

        # Color codes for terminal output
        RED='\033[0;31m'
        GREEN='\033[0;32m'
        YELLOW='\033[1;33m'
        BLUE='\033[0;34m'
        NC='\033[0m' # No Color

        # 1. Check if a target was provided
        if [ -z "$1" ]; then
            echo -e "${RED}[!] Error: No target URL provided.${NC}"
            echo -e "${YELLOW}[-] Usage: $0 <http://target-url.com>${NC}"
            exit 1
        fi

        TARGET="$1"

        # Ensure the URL has a protocol (whatweb prefers it)
        if [[ ! "$TARGET" =~ ^https?:// ]]; then
            TARGET="http://$TARGET"
            echo -e "${YELLOW}[+] No protocol specified, defaulting to http. Target set to: $TARGET${NC}"
        fi

        echo -e "${BLUE}==================================================${NC}"
        echo -e "${BLUE}       Starting Recon for: $TARGET               ${NC}"
        echo -e "${BLUE}==================================================${NC}\n"

        # 2. Verify required tools are installed (removed wafw00f)
        TOOLS=("whatweb" "wpscan")
        for TOOL in "${TOOLS[@]}"; do
            if ! command -v $TOOL &> /dev/null; then
                echo -e "${RED}[!] Error: $TOOL is not installed. Please install it before running this script.${NC}"
                exit 1
            fi
        done

        # ---------------------------------------------------------
        # PHASE 1: WhatWeb Fingerprinting (Stealthy)
        # ---------------------------------------------------------
        echo -e "${GREEN}[*] Phase 1: Running WhatWeb (Stealthy - Aggression Level 1)...${NC}"
        whatweb -a 1 "$TARGET"
        echo -e "\n"

        # ---------------------------------------------------------
        # PHASE 2: WhatWeb Fingerprinting (Aggressive)
        # ---------------------------------------------------------
        echo -e "${GREEN}[*] Phase 2: Running WhatWeb (Aggressive - Aggression Level 3)...${NC}"
        whatweb -a 3 "$TARGET"
        echo -e "\n"

        # ---------------------------------------------------------
        # PHASE 3: CMS Scanning (WordPress)
        # ---------------------------------------------------------
        echo -e "${GREEN}[*] Phase 3: Running WPScan (Forcing update & Enumeration)...${NC}"
        echo -e "${YELLOW}[!] Note: The '--force update' flag will download the latest WPScan database. This may take a moment.${NC}"

        wpscan -e --url "$TARGET" --ignore-main-redirect

        echo -e "\n${BLUE}==================================================${NC}"
        echo -e "${GREEN}       Reconnaissance Complete!                  ${NC}"
        echo -e "${BLUE}==================================================${NC}"
        """
        subprocess.run(bash,shell=True,text=True)

    run()
