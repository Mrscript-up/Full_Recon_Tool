import os
import sys
import subprocess
import shutil
import re
import time
from pathlib import Path
import datetime
from datetime import datetime


def run_spidering_attack_tool(target_domain=None):
    print("[-] run_spidering_attack_tool")
    
    def run():
        # Try importing colorama for colored output, fallback to clean text if not installed
        try:
            from colorama import init, Fore, Style
            init(autoreset=True)
            GREEN = Fore.GREEN
            RED = Fore.RED
            YELLOW = Fore.YELLOW
            BLUE = Fore.BLUE
            RESET = Style.RESET_ALL
        except ImportError:
            GREEN = RED = YELLOW = BLUE = RESET = ""

        # Adjustable delay configuration (in seconds)
        PHASE_DELAY = 3.0    # Delay between major phases to cool down resources
        CMD_DELAY = 1.5      # Delay between individual external tool calls

        def print_status(message):
            print(f"{GREEN}[+]{RESET} {message}")

        def print_error(message):
            print(f"{RED}[!] {message}", file=sys.stderr)

        def print_info(message):
            print(f"{YELLOW}[*]{RESET} {message}")

        def check_tools():
            """Verify that all required system binaries are available in PATH."""
            tools = ["gospider", "paramspider", "httpx", "qsreplace", "katana"]
            missing_tools = [tool for tool in tools if shutil.which(tool) is None]

            if missing_tools:
                print_error(f"Missing required tools: {', '.join(missing_tools)}")
                print_error("Please install them and ensure they are in your PATH.")
                sys.exit(1)
            print_status("All required external tools are installed.")

        def run_command_with_pipe(pipeline, output_file=None):
            """
            Executes a shell pipeline safely.
            pipeline: list of command lists, e.g., [['gospider', '-s', ...], ['grep', ...]]
            """
            processes = []
            for i, cmd in enumerate(pipeline):
                try:
                    if i == 0:
                        # First command
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    else:
                        # Pipe output from previous command
                        p = subprocess.Popen(cmd, stdin=processes[-1].stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    processes.append(p)
                except Exception as e:
                    print_error(f"Failed to execute: {' '.join(cmd)}. Error: {e}")
                    return False

            # Allow middle processes to receive SIGPIPE if subsequent processes exit early
            for p in processes[:-1]:
                p.stdout.close()

            # Get final output
            stdout, _ = processes[-1].communicate()

            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(stdout)

            # Short cooldown post-execution to yield CPU cycles
            time.sleep(0.5)
            return stdout.decode('utf-8', errors='ignore')

        def main():
            print(f"{BLUE}============================================={RESET}")
            print(f"{BLUE}   Security Reconnaissance Automation (Python) {RESET}")
            print(f"{BLUE}============================================={RESET}\n")

            check_tools()

            # User Input
            domain = (target_domain or "").strip()
            if not domain:
                domain = input("write yout target domain\n=> ").strip()
            if not domain:
                print_error("Domain cannot be empty.")
                sys.exit(1)

            # Basic domain validation
            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", domain):
                print_error("Invalid domain format.")
                sys.exit(1)

            # Output directory setup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"recon_{domain}_{timestamp}"
            temp_dir = os.path.join(output_dir, "temp")
            results_dir = os.path.join(output_dir, "results")
            extracted_dir = os.path.join(output_dir, "extracted")

            os.makedirs(temp_dir, exist_ok=True)
            os.makedirs(results_dir, exist_ok=True)
            os.makedirs(extracted_dir, exist_ok=True)
            for category in ["paths", "params", "files"]:
                os.makedirs(os.path.join(extracted_dir, category), exist_ok=True)

            print_status(f"Output directory initialized: {output_dir}")

            # Escaped regex pattern for the domain
            escaped_domain_regex = rf"(?:\w+\.)*{re.escape(domain)}\b"

            # ==================== PHASE 1: GoSpider ====================
            print_status("Phase 1: Launching GoSpider...")
            gospider_resolve_file = os.path.join(results_dir, "gospider_resolve.txt")

            # gospider -s https://target.com -d 2 | grep -Ei <regex> | httpx
            pipeline_gospider = [
                ["gospider", "-s", f"https://{domain}", "-d", "2"],
                ["grep", "-Ei", escaped_domain_regex],
                ["httpx", "-silent"]
            ]
            run_command_with_pipe(pipeline_gospider, gospider_resolve_file)

            print_info(f"GoSpider complete. Sleeping for {PHASE_DELAY}s to stabilize system resources...")
            time.sleep(PHASE_DELAY)

            # ==================== PHASE 2: ParamSpider ====================
            print_status("Phase 2: Launching ParamSpider...")
            paramspider_resolve_file = os.path.join(results_dir, "paramspider_for_now_resolve.txt")

            # paramspider -d target.com -s | grep -Ei <regex> | httpx
            pipeline_paramspider = [
                ["paramspider", "-d", domain, "-s"],
                ["grep", "-Ei", escaped_domain_regex],
                ["httpx", "-silent"]
            ]
            run_command_with_pipe(pipeline_paramspider, paramspider_resolve_file)

            print_info(f"ParamSpider complete. Sleeping for {PHASE_DELAY}s...")
            time.sleep(PHASE_DELAY)

            # ==================== PHASE 3: Parameter Reflection Analysis ====================
            print_status("Phase 3: Analysing parameters for potential reflection...")

            res_aa2a_txt = os.path.join(temp_dir, "res_aa2a.txt")
            res_bb1b_txt = os.path.join(temp_dir, "res_bb1b.txt")
            res_aa2a_httpx = os.path.join(temp_dir, "res_aa2a_httpx.txt")
            res_bb1b_httpx = os.path.join(temp_dir, "res_bb1b_httpx.txt")

            if os.path.exists(paramspider_resolve_file) and os.path.getsize(paramspider_resolve_file) > 0:
                # qsreplace aa2a
                pipeline_qs_aa = [["cat", paramspider_resolve_file], ["qsreplace", "aa2a"]]
                run_command_with_pipe(pipeline_qs_aa, res_aa2a_txt)
                time.sleep(CMD_DELAY)

                # qsreplace bb1b
                pipeline_qs_bb = [["cat", paramspider_resolve_file], ["qsreplace", "bb1b"]]
                run_command_with_pipe(pipeline_qs_bb, res_bb1b_txt)
                time.sleep(CMD_DELAY)

                # httpx checks
                subprocess.run(["httpx", "-l", res_aa2a_txt, "-content-length", "-silent", "-sc", "-hash", "mmh3", "-o", res_aa2a_httpx], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(CMD_DELAY)

                subprocess.run(["httpx", "-l", res_bb1b_txt, "-content-length", "-silent", "-sc", "-hash", "mmh3", "-o", res_bb1b_httpx], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(CMD_DELAY)
            else:
                # Create empty files to satisfy the rest of the flow cleanly
                open(res_aa2a_httpx, 'w').close()
                open(res_bb1b_httpx, 'w').close()

            # Clean intermediate files
            for f in [res_aa2a_txt, res_bb1b_txt]:
                if os.path.exists(f): os.remove(f)

            # Sort and Deduplicate using native Python logic
            def sort_uniq_file(input_file, output_file):
                if not os.path.exists(input_file):
                    open(output_file, 'w').close()
                    return
                with open(input_file, 'r', errors='ignore') as f:
                    lines = list(set(f.read().splitlines()))
                lines.sort()
                with open(output_file, 'w') as f:
                    f.write('\n'.join(lines) + '\n')

            res_aa2a_httpx_sort = os.path.join(temp_dir, "res_aa2a_httpx_sort.txt")
            res_bb1b_httpx_sort = os.path.join(temp_dir, "res_bb1b_httpx_sort.txt")

            sort_uniq_file(res_aa2a_httpx, res_aa2a_httpx_sort)
            sort_uniq_file(res_bb1b_httpx, res_bb1b_httpx_sort)

            # Clean un-sorted files
            for f in [res_aa2a_httpx, res_bb1b_httpx]:
                if os.path.exists(f): os.remove(f)

            # Process and detect difference reflection states (Using pure Python instead of complex awk)
            print_info("Processing response data for differences (length, status reflections)...")
            reflection_results = {}

            def parse_reflection_data(filepath):
                if not os.path.exists(filepath):
                    return
                with open(filepath, 'r', errors='ignore') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            url, status, length = parts[0], parts[1], parts[2]
                            # Extract base URL (path without queries)
                            base_url = url.split('?')[0]
                            val = f"{status}_{length}"

                            if base_url not in reflection_results:
                                reflection_results[base_url] = {"seen_values": set(), "urls": set()}
                            reflection_results[base_url]["seen_values"].add(val)
                            reflection_results[base_url]["urls"].add(url)

            parse_reflection_data(res_aa2a_httpx_sort)
            parse_reflection_data(res_bb1b_httpx_sort)

            # Write output reflection file
            main_parameter_file = os.path.join(results_dir, "main_parametr.txt")
            with open(main_parameter_file, 'w') as out:
                for base, data in reflection_results.items():
                    if len(data["seen_values"]) > 1:
                        out.write(f"🔥 {base}\n")
                        for u in data["urls"]:
                            out.write(f"{u}\n")
                        out.write("\n")

            print_info(f"Reflection check complete. Sleeping for {PHASE_DELAY}s...")
            time.sleep(PHASE_DELAY)

            # ==================== PHASE 4: Katana Deep Crawl ====================
            print_status("Phase 4: Running Katana crawler modes...")

            katana_js = os.path.join(temp_dir, "katana_jsfiles.txt")
            katana_xhr = os.path.join(temp_dir, "katana_xhr.txt")
            katana_paths = os.path.join(temp_dir, "katana_paths.txt")
            all_katana_out = os.path.join(results_dir, "all_things_in_katana.out")

            # Katana JS
            print_info("Crawling JS endpoints...")
            run_command_with_pipe([
                ["katana", "-u", f"https://{domain}", "-jc", "-jsl", "-d", "5", "-silent"],
                ["grep", "-Ei", escaped_domain_regex],
                ["sort", "-u"]
            ], katana_js)
            time.sleep(CMD_DELAY)

            # Katana XHR
            print_info("Crawling XHR endpoints...")
            run_command_with_pipe([
                ["katana", "-u", f"https://{domain}", "-xhr", "-kf", "all", "-silent"],
                ["grep", "-Ei", escaped_domain_regex],
                ["sort", "-u"]
            ], katana_xhr)
            time.sleep(CMD_DELAY)

            # Katana Paths
            print_info("Crawling target paths...")
            run_command_with_pipe([
                ["katana", "-u", f"https://{domain}", "-d", "5", "-fs", "fqdn", "-silent"],
                ["grep", "-Ei", escaped_domain_regex],
                ["sort", "-u"]
            ], katana_paths)
            time.sleep(CMD_DELAY)

            # Merge Katana outputs safely in Python
            with open(all_katana_out, 'w') as outfile:
                for f_path in [katana_js, katana_xhr, katana_paths]:
                    if os.path.exists(f_path):
                        with open(f_path, 'r', errors='ignore') as infile:
                            outfile.write(infile.read())
                        os.remove(f_path) # Delete temporary files immediately

            print_info(f"Katana crawls complete. Sleeping for {PHASE_DELAY}s before building reports...")
            time.sleep(PHASE_DELAY)

            # ==================== PHASE 5: Extraction & RegEx Filtering ====================
            print_status("Phase 5: Cleaning, extracting, and sorting results...")

            # Combine Katana results & GoSpider results
            combined_urls = set()
            for source in [all_katana_out, gospider_resolve_file]:
                if os.path.exists(source):
                    with open(source, 'r', errors='ignore') as f:
                        for line in f:
                            clean_line = line.strip()
                            if clean_line:
                                combined_urls.add(clean_line)

            all_urls_file = os.path.join(temp_dir, "all_urls_combined.txt")
            with open(all_urls_file, 'w') as f:
                f.write('\n'.join(sorted(combined_urls)) + '\n')

            # Parse features natively in Python
            paths_without_params = set()
            important_paths = set()
            parameters = set()

            # Extensions categorization dictionary
            extensions_map = {
                "configs": re.compile(r"\.(json|xml|yml|yaml|env|config|conf|ini|properties|log|txt|md)(\?|$|#)", re.IGNORECASE),
                "scripts": re.compile(r"\.(js|js\.map|map|svg)(\?|$|#)", re.IGNORECASE),
                "web_pages": re.compile(r"\.(html|css|asp|php|aspx|jsp|cgi|cfm|do|action)(\?|$|#)", re.IGNORECASE),
                "backups": re.compile(r"\.(git|env|bak|old|zip|tar|gz|sql)(\?|$|#)", re.IGNORECASE)
            }

            # Open files to save categorizations
            cat_files = {cat: open(os.path.join(extracted_dir, "files", f"{cat}.txt"), 'w') for cat in extensions_map}

            # Regex for sensitive/important directory paths
            important_path_rx = re.compile(r"/(api|admin|login|dashboard|v[0-9]|graphql|swagger|wp-json|auth|config|internal|db|test|dev)(\/|$)", re.IGNORECASE)

            for url in combined_urls:
                # 1. Path without parameters extraction
                base_path = url.split('?')[0].split('#')[0]
                paths_without_params.add(base_path)

                # 2. Extract Important Paths
                if important_path_rx.search(base_path):
                    important_paths.add(base_path)

                # 3. Parameter Extraction
                query_parts = url.split('?')
                if len(query_parts) > 1:
                    # Match parameter names (handles values cleanly)
                    found_params = re.findall(r"(?:[?&])([a-zA-Z0-9_\-]+)(?:=)", query_parts[1])
                    for param in found_params:
                        parameters.add(param)

                # 4. Extract categories matching file extensions
                for cat, regex in extensions_map.items():
                    if regex.search(url):
                        cat_files[cat].write(f"{url}\n")

            # Close categorized files
            for f in cat_files.values():
                f.close()

            # Write paths and parameters
            with open(os.path.join(extracted_dir, "paths", "clean_paths.txt"), 'w') as f:
                f.write('\n'.join(sorted(paths_without_params)) + '\n')

            with open(os.path.join(extracted_dir, "paths", "important_paths.txt"), 'w') as f:
                f.write('\n'.join(sorted(important_paths)) + '\n')

            with open(os.path.join(extracted_dir, "params", "extracted_parameters.txt"), 'w') as f:
                f.write('\n'.join(sorted(parameters)) + '\n')

            # Cleanup temporary directory completely
            shutil.rmtree(temp_dir, ignore_errors=True)

            # ==================== PHASE 6: Summary Generator ====================
            print_status("Phase 6: Organizing and printing execution summary...")

            summary_file = os.path.join(results_dir, "RECON_SUMMARY.txt")
            with open(summary_file, 'w') as sf:
                sf.write("=====================================================\n")
                sf.write(f"           RECON RESULTS SUMMARY FOR {domain.upper()}\n")
                sf.write(f"           Date Run: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                sf.write("=====================================================\n\n")
                sf.write(f"[+] Total Distinct URLs Discovered : {len(combined_urls)}\n")
                sf.write(f"[+] Clean Directory Paths Found     : {len(paths_without_params)}\n")
                sf.write(f"[+] Critical/Important Paths Found  : {len(important_paths)}\n")
                sf.write(f"[+] Unique URL Parameter Keys Found : {len(parameters)}\n")
                sf.write(f"[+] Results directory output route  : {os.path.abspath(results_dir)}\n")
                sf.write(f"[+] Structured findings outputs    : {os.path.abspath(extracted_dir)}\n\n")
                sf.write("=====================================================\n")

            with open(summary_file, 'r') as sf:
                print(sf.read())

            print_status(f"Execution successfully finalized! Data saved in: '{output_dir}'")

        
        main()
                        
    run()
