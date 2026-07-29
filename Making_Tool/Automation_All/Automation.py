import sys
import colorama
from colorama import Fore, Style


from Tools.spidering import run_spidering_attack_tool
from Tools.tec import run_Tec_tool
from Tools.subdomain import run_subdomain_takover
from Tools.JS_Tools.cleanjs import run_clean_js_tool
from Tools.JS_Tools.taking_informationjs import run_taking_information_tool
from Tools.JS_Tools.linkfinder import run_linkfinder
from Tools.comment.comment import run_commnet_descovary_tool as comment

colorama.init(autoreset=True)


def banner():
    print(f"""{Fore.CYAN}
╔══════════════════════════════════════════════════╗
║               AUTO RECON — MRSCRIPT              ║
║             Full Target Automation Mode          ║
╚══════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def run_step(title, func, *args, **kwargs):
    """Run one tool, print a clear header/footer around it, and never let
    one tool's crash stop the rest of the pipeline."""
    print(f"\n{Fore.YELLOW}{Style.BRIGHT}[>] {title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}")
    try:
        func(*args, **kwargs)
    except Exception as e:
        print(f"{Fore.RED}[!] Error in {title}: {e}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 60}{Style.RESET_ALL}\n")


def main():
    banner()
    try:
        target = input(f"{Fore.GREEN}Target (domain/URL): {Style.RESET_ALL}").strip()
        if not target:
            print(f"{Fore.RED}[!] No target provided. Exiting.{Style.RESET_ALL}")
            sys.exit(1)

        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[*] Starting full automated recon on: {target}{Style.RESET_ALL}\n")
    
        
    # --- Tools with a confirmed keyword-argument interface -----------------
        run_step("Spidering", run_spidering_attack_tool, target_domain=target)
        run_step("JS Information Extraction", run_taking_information_tool, args=target)

        # --- Tools that follow the args=None / str / Namespace pattern ---------
        # (established for linkfinder & comment) — passing target as the
        # "initial command" runs it once, then those tools may drop into their
        # own interactive loop. If you want single-shot (no loop) behavior,
        # tell me and I'll switch these to build a proper argparse.Namespace
        # instead of a raw string.
        run_step("Link Finder (JS Endpoints)", run_linkfinder, target)
        run_step("Comment Discovery", comment, target)

        # --- Tools with an UNKNOWN signature — currently called with no args,
        # exactly like main.py does. If they expect the target too, share
        # subdomain.py / tec.py / cleanjs.py and I'll wire target= in here. -----
        run_step("Subdomain Takeover Check", run_subdomain_takover)   # TODO: confirm target param
        run_step("Technology Fingerprinting", run_Tec_tool)           # TODO: confirm target param
        run_step("JS Cleaning", run_clean_js_tool)                    # TODO: confirm target param

        print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] Full recon completed for {target}{Style.RESET_ALL}")
    except:
        print(f'{Fore.RED}\n[!] Error: {Style.RESET_ALL}')
if __name__ == "__main__":
    main()