import sys
import colorama
import os
import argparse
from Tools.spidering import run_spidering_attack_tool
from Tools.tec import run_Tec_tool
from Tools.subdomain import run_subdomain_takover
from Tools.JS_Tools.cleanjs import run_clean_js_tool
from Tools.JS_Tools.taking_informationjs import run_taking_information_tool
from Tools.JS_Tools.linkfinder import run_linkfinder
from Tools.comment.comment import run_commnet_descovary_tool as comment
from Tools.JS_Tools.vulnerability import run_vulnerability_tool
from Tools.JS_Tools.secrets import run_secrets_tool
#from Automation_All.Automation import main as automation_tool


class tool_start:
    def __init__(self):
        self.start = None


def build_tool_kwargs(parsed_args, tool_name):
    kwargs = {}

    if tool_name == 'spidering' and getattr(parsed_args, 'target_domain', None):
        kwargs['target_domain'] = parsed_args.target_domain

    if tool_name == 'taking_information_js' and getattr(parsed_args, 'js_input', None):
        kwargs['args'] = parsed_args.js_input

    return kwargs


def run_tool(handler, parsed_args, tool_name):
    kwargs = build_tool_kwargs(parsed_args, tool_name)
    if not kwargs:
        handler()
        return

    try:
        handler(**kwargs)
    except TypeError as exc:
        if 'unexpected keyword argument' in str(exc):
            handler()
            return
        raise


if __name__ == "__main__":
    tool_start = tool_start()
    
    print("""
╔══════════════════════════════════════════════════╗
║                                                  ║
║                                                  ║
║            ███╗   ███╗██████╗ ███████╗           ║
║            ████╗ ████║██╔══██╗██╔════╝           ║
║            ██╔████╔██║██████╔╝███████╗           ║
║            ██║╚██╔╝██║██╔══██╗╚════██║           ║
║            ██║ ╚═╝ ██║██║  ██║███████║           ║
║            ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝           ║
║                                                  ║
║                 M R S C R I P T                  ║
║               Private Recon Tool                 ║
║                                                  ║
╚══════════════════════════════════════════════════╝
""")
    print('[-] * WE SEE YOU * [-]')
    
    args = argparse.ArgumentParser(description='MRSCRIPT - Private Recon Tool')
    args.add_argument('-s', '--subdomain', help='subdomain_discovery_tool',action="store_true")
    args.add_argument('-t', '--tec', help='technology_finder tool',action="store_true")
    args.add_argument('-S', '--spidering', help='spidering_tool',action="store_true")
    args.add_argument('-d', '--target-domain', help='target domain for spidering tools')
    args.add_argument('-j', '--js-input', help='input file/directory/URL for JS analysis tool')
    args.add_argument('-c', '--comment', help='comment_finder_tool',action="store_true")
    args.add_argument('-cjs', '--clean_js', help='cleaner_js_files_tool',action="store_true")
    args.add_argument('-tfjs', '--taking_information_js', help='extracking_info_js_files',action="store_true")
    args.add_argument('-lfjs', '--link_finder', help='find_link_in_js_files',action="store_true")
    args.add_argument('-vsjs', '--vulnerability_scan', help='find_(simple)_vul_in_js',action="store_true")
    args.add_argument('-sfjs', '--secrets_finder', help='find_secrets_in_js_files',action="store_true")
    args.add_argument('-automation', '--automation', help='automation all of them', action='store_true')
    args.add_argument('-ps', '--port_scan', help='port scanner [subdomain]', action='store_true')    
    pa = args.parse_args()

    if not any(vars(pa).values()):
        print('[-] select a tool to run')
        args.print_help()
        sys.exit(1)

    if pa.subdomain:
        run_tool(run_subdomain_takover, pa, 'subdomain')

    if pa.tec:
        run_tool(run_Tec_tool, pa, 'tec')

    if pa.spidering:
        run_tool(run_spidering_attack_tool, pa, 'spidering')

    if pa.comment:
        run_tool(comment, pa, 'comment')

    if pa.clean_js:
        run_tool(run_clean_js_tool, pa, 'clean_js')

    if pa.taking_information_js:
        run_tool(run_taking_information_tool, pa, 'taking_information_js')

    if pa.link_finder:
        run_tool(run_linkfinder, pa, 'link_finder')

    #if pa.automation:
        #run_tool()

    if pa.vulnerability_scan:
        run_tool(run_vulnerability_tool, pa ,'vulnerability_scan')

    if pa.secrets_finder:
        run_tool(run_secrets_tool, pa, 'secrets_finder')

    if pa.port_scan:
        run_tool()

        