#!/usr/bin/env python3
import os
import sys
import json
import argparse
import subprocess
import shutil
import re
import time
from pathlib import Path
from datetime import datetime


# ==================== CLI ARGUMENT PARSING ====================
def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="spidering.py",
        description="Security Reconnaissance Automation - orchestrates gospider, "
                     "paramspider, katana, httpx and qsreplace against an authorized target.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument("domain", nargs="?", default=None,
                         help="Target domain (e.g. example.com). If omitted, you'll be prompted.")

    # --- Phase control ---
    phase_group = parser.add_argument_group("Phase control")
    phase_group.add_argument("--skip-gospider", action="store_true", help="Skip Phase 1 (GoSpider)")
    phase_group.add_argument("--skip-paramspider", action="store_true", help="Skip Phase 2 (ParamSpider)")
    phase_group.add_argument("--skip-reflection", action="store_true", help="Skip Phase 3 (reflection analysis)")
    phase_group.add_argument("--skip-katana", action="store_true", help="Skip Phase 4 (Katana deep crawl)")
    phase_group.add_argument("--only", choices=["gospider", "paramspider", "katana", "reflection"],
                              help="Run only a single phase (overrides other --skip-* flags)")

    # --- Crawl tuning ---
    tune_group = parser.add_argument_group("Crawl tuning")
    tune_group.add_argument("--depth", type=int, default=None,
                             help="Override crawl depth for both GoSpider and Katana path crawl")
    tune_group.add_argument("--gospider-depth", type=int, default=2, help="GoSpider crawl depth")
    tune_group.add_argument("--katana-depth", type=int, default=5, help="Katana path crawl depth")
    tune_group.add_argument("-t", "--threads", type=int, default=10,
                             help="Concurrency/threads passed to gospider/katana")
    tune_group.add_argument("--rate-limit", type=int, default=0,
                             help="Requests/sec limit for katana & httpx (0 = tool default, unlimited)")
    tune_group.add_argument("--phase-delay", type=float, default=3.0,
                             help="Cooldown (seconds) between major phases")
    tune_group.add_argument("--cmd-delay", type=float, default=1.5,
                             help="Cooldown (seconds) between individual external tool calls")

    # --- Network ---
    net_group = parser.add_argument_group("Network")
    net_group.add_argument("--proxy", default=None,
                            help="Proxy URL (e.g. http://127.0.0.1:8080) applied to all supported tools")
    net_group.add_argument("--header", action="append", default=[], dest="headers",
                            help="Extra header to send, e.g. --header 'Authorization: Bearer xxx' (repeatable)")

    # --- Scope control ---
    scope_group = parser.add_argument_group("Scope control")
    scope_group.add_argument("--scope-file", default=None,
                              help="Path to a file with one allowed host/pattern per line (supports '*' wildcard). "
                                   "Only in-scope URLs are kept in final output.")

    # --- Input / Output ---
    io_group = parser.add_argument_group("Input / Output")
    io_group.add_argument("-o", "--output-dir", default=None,
                           help="Custom output directory (default: recon_<domain>_<timestamp>)")
    io_group.add_argument("--input-urls", default=None,
                           help="Path to a pre-existing URL list; skips GoSpider/Katana crawling and "
                                "uses this file as the crawled URL source instead")
    io_group.add_argument("--resume", action="store_true",
                           help="Resume into an existing --output-dir: skip a phase if its result file already exists")
    io_group.add_argument("--format", choices=["txt", "json", "both"], default="txt",
                           help="Summary report format")

    # --- Misc ---
    misc_group = parser.add_argument_group("Misc")
    misc_group.add_argument("-q", "--quiet", action="store_true", help="Suppress informational output")
    misc_group.add_argument("-v", "--verbose", action="store_true", help="Show underlying tool stderr output")
    misc_group.add_argument("--no-color", action="store_true", help="Disable colored output")

    return parser


def run_spidering_attack_tool(target_domain=None, cli_args=None):
    print("[-] run_spidering_attack_tool")

    def run():
        parser = build_arg_parser()
        args = parser.parse_args(cli_args if cli_args is not None else [])
        if target_domain and not args.domain:
            args.domain = target_domain

        # Apply --only shortcut
        if args.only:
            args.skip_gospider = args.only != "gospider"
            args.skip_paramspider = args.only != "paramspider"
            args.skip_katana = args.only != "katana"
            args.skip_reflection = args.only != "reflection"

        if args.depth is not None:
            args.gospider_depth = args.depth
            args.katana_depth = args.depth

        # --input-urls implies skipping the crawl phases (must happen before check_tools)
        if args.input_urls:
            args.skip_gospider = True
            args.skip_katana = True

        # Try importing colorama for colored output, fallback to clean text if not installed
        try:
            if args.no_color:
                raise ImportError
            from colorama import init, Fore, Style
            init(autoreset=True)
            GREEN = Fore.GREEN
            RED = Fore.RED
            YELLOW = Fore.YELLOW
            BLUE = Fore.BLUE
            RESET = Style.RESET_ALL
        except ImportError:
            GREEN = RED = YELLOW = BLUE = RESET = ""

        PHASE_DELAY = args.phase_delay
        CMD_DELAY = args.cmd_delay

        def print_status(message):
            print(f"{GREEN}[+]{RESET} {message}")

        def print_error(message):
            print(f"{RED}[!] {message}", file=sys.stderr)

        def print_info(message):
            if not args.quiet:
                print(f"{YELLOW}[*]{RESET} {message}")

        # ---- Proxy/env setup applied to every subprocess call ----
        run_env = os.environ.copy()
        if args.proxy:
            run_env["HTTP_PROXY"] = args.proxy
            run_env["HTTPS_PROXY"] = args.proxy
            run_env["http_proxy"] = args.proxy
            run_env["https_proxy"] = args.proxy

        extra_headers_flat = []
        for h in args.headers:
            extra_headers_flat += ["-H", h]

        def check_tools():
            """Verify that all required system binaries are available in PATH."""
            required = set()
            if not args.skip_gospider:
                required.add("gospider")
            if not args.skip_paramspider:
                required.add("paramspider")
            if not args.skip_katana:
                required.add("katana")
            if not args.skip_paramspider or not args.skip_reflection:
                required.add("qsreplace")
            required.add("httpx")

            tools = sorted(required)
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
            stderr_target = None if args.verbose else subprocess.DEVNULL
            processes = []
            for i, cmd in enumerate(pipeline):
                try:
                    if i == 0:
                        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=stderr_target, env=run_env)
                    else:
                        p = subprocess.Popen(cmd, stdin=processes[-1].stdout, stdout=subprocess.PIPE,
                                              stderr=stderr_target, env=run_env)
                    processes.append(p)
                except Exception as e:
                    print_error(f"Failed to execute: {' '.join(cmd)}. Error: {e}")
                    return False

            for p in processes[:-1]:
                p.stdout.close()

            stdout, _ = processes[-1].communicate()

            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(stdout)

            time.sleep(0.5)
            return stdout.decode('utf-8', errors='ignore')

        def load_scope(scope_file):
            """Load scope patterns (supports '*' wildcard) and return a matcher function."""
            if not scope_file:
                return None
            if not os.path.exists(scope_file):
                print_error(f"Scope file not found: {scope_file}")
                sys.exit(1)
            patterns = []
            with open(scope_file, 'r', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        patterns.append(re.compile(
                            "^" + re.escape(line).replace(r"\*", ".*") + "$", re.IGNORECASE))

            def matcher(url):
                try:
                    from urllib.parse import urlparse
                    host = urlparse(url).netloc or url
                except Exception:
                    host = url
                return any(p.match(host) for p in patterns)

            print_status(f"Loaded {len(patterns)} scope pattern(s) from {scope_file}")
            return matcher

        def result_exists(path):
            return args.resume and os.path.exists(path) and os.path.getsize(path) > 0

        def main():
            print(f"{BLUE}============================================={RESET}")
            print(f"{BLUE}   Security Reconnaissance Automation (Python) {RESET}")
            print(f"{BLUE}============================================={RESET}\n")

            check_tools()

            domain = (args.domain or "").strip()
            if not domain:
                domain = input("write yout target domain\n=> ").strip()
            if not domain:
                print_error("Domain cannot be empty.")
                sys.exit(1)

            if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$", domain):
                print_error("Invalid domain format.")
                sys.exit(1)

            scope_matcher = load_scope(args.scope_file)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = args.output_dir or f"recon_{domain}_{timestamp}"
            temp_dir = os.path.join(output_dir, "temp")
            results_dir = os.path.join(output_dir, "results")
            extracted_dir = os.path.join(output_dir, "extracted")

            os.makedirs(temp_dir, exist_ok=True)
            os.makedirs(results_dir, exist_ok=True)
            os.makedirs(extracted_dir, exist_ok=True)
            for category in ["paths", "params", "files"]:
                os.makedirs(os.path.join(extracted_dir, category), exist_ok=True)

            print_status(f"Output directory initialized: {output_dir}")

            escaped_domain_regex = rf"(?:\w+\.)*{re.escape(domain)}\b"

            # Common extra flags built from CLI options
            proxy_flag_katana = ["-proxy", args.proxy] if args.proxy else []
            proxy_flag_httpx = ["-http-proxy", args.proxy] if args.proxy else []
            proxy_flag_gospider = ["-p", args.proxy] if args.proxy else []
            rate_flag_katana = ["-rl", str(args.rate_limit)] if args.rate_limit else []
            rate_flag_httpx = ["-rl", str(args.rate_limit)] if args.rate_limit else []

            gospider_resolve_file = os.path.join(results_dir, "gospider_resolve.txt")
            paramspider_resolve_file = os.path.join(results_dir, "paramspider_for_now_resolve.txt")

            # ==================== INPUT URLS OVERRIDE ====================
            if args.input_urls:
                if not os.path.exists(args.input_urls):
                    print_error(f"--input-urls file not found: {args.input_urls}")
                    sys.exit(1)
                print_status(f"Using provided URL list instead of crawling: {args.input_urls}")
                shutil.copy(args.input_urls, gospider_resolve_file)

            # ==================== PHASE 1: GoSpider ====================
            if not args.skip_gospider:
                if result_exists(gospider_resolve_file):
                    print_info("Resume: gospider_resolve.txt already exists, skipping Phase 1.")
                else:
                    print_status("Phase 1: Launching GoSpider...")
                    pipeline_gospider = [
                        ["gospider", "-s", f"https://{domain}", "-d", str(args.gospider_depth),
                         "-c", str(args.threads)] + proxy_flag_gospider + extra_headers_flat,
                        ["grep", "-Ei", escaped_domain_regex],
                        ["httpx", "-silent"] + rate_flag_httpx + proxy_flag_httpx
                    ]
                    run_command_with_pipe(pipeline_gospider, gospider_resolve_file)

                print_info(f"GoSpider phase done. Sleeping for {PHASE_DELAY}s to stabilize system resources...")
                time.sleep(PHASE_DELAY)
            else:
                print_info("Phase 1 (GoSpider) skipped by flag.")
                open(gospider_resolve_file, 'a').close()

            # ==================== PHASE 2: ParamSpider ====================
            if not args.skip_paramspider:
                if result_exists(paramspider_resolve_file):
                    print_info("Resume: paramspider result already exists, skipping Phase 2.")
                else:
                    print_status("Phase 2: Launching ParamSpider...")
                    pipeline_paramspider = [
                        ["paramspider", "-d", domain, "-s"],
                        ["grep", "-Ei", escaped_domain_regex],
                        ["httpx", "-silent"] + rate_flag_httpx + proxy_flag_httpx
                    ]
                    run_command_with_pipe(pipeline_paramspider, paramspider_resolve_file)

                print_info(f"ParamSpider phase done. Sleeping for {PHASE_DELAY}s...")
                time.sleep(PHASE_DELAY)
            else:
                print_info("Phase 2 (ParamSpider) skipped by flag.")
                open(paramspider_resolve_file, 'a').close()

            # ==================== PHASE 3: Parameter Reflection Analysis ====================
            main_parameter_file = os.path.join(results_dir, "main_parametr.txt")
            if not args.skip_reflection:
                print_status("Phase 3: Analysing parameters for potential reflection...")

                res_aa2a_txt = os.path.join(temp_dir, "res_aa2a.txt")
                res_bb1b_txt = os.path.join(temp_dir, "res_bb1b.txt")
                res_aa2a_httpx = os.path.join(temp_dir, "res_aa2a_httpx.txt")
                res_bb1b_httpx = os.path.join(temp_dir, "res_bb1b_httpx.txt")

                if os.path.exists(paramspider_resolve_file) and os.path.getsize(paramspider_resolve_file) > 0:
                    pipeline_qs_aa = [["cat", paramspider_resolve_file], ["qsreplace", "aa2a"]]
                    run_command_with_pipe(pipeline_qs_aa, res_aa2a_txt)
                    time.sleep(CMD_DELAY)

                    pipeline_qs_bb = [["cat", paramspider_resolve_file], ["qsreplace", "bb1b"]]
                    run_command_with_pipe(pipeline_qs_bb, res_bb1b_txt)
                    time.sleep(CMD_DELAY)

                    stderr_target = None if args.verbose else subprocess.DEVNULL
                    subprocess.run(["httpx", "-l", res_aa2a_txt, "-content-length", "-silent", "-sc",
                                     "-hash", "mmh3"] + rate_flag_httpx + proxy_flag_httpx +
                                    ["-o", res_aa2a_httpx], stdout=subprocess.DEVNULL, stderr=stderr_target, env=run_env)
                    time.sleep(CMD_DELAY)

                    subprocess.run(["httpx", "-l", res_bb1b_txt, "-content-length", "-silent", "-sc",
                                     "-hash", "mmh3"] + rate_flag_httpx + proxy_flag_httpx +
                                    ["-o", res_bb1b_httpx], stdout=subprocess.DEVNULL, stderr=stderr_target, env=run_env)
                    time.sleep(CMD_DELAY)
                else:
                    open(res_aa2a_httpx, 'w').close()
                    open(res_bb1b_httpx, 'w').close()

                for f in [res_aa2a_txt, res_bb1b_txt]:
                    if os.path.exists(f): os.remove(f)

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

                for f in [res_aa2a_httpx, res_bb1b_httpx]:
                    if os.path.exists(f): os.remove(f)

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
                                base_url = url.split('?')[0]
                                val = f"{status}_{length}"

                                if base_url not in reflection_results:
                                    reflection_results[base_url] = {"seen_values": set(), "urls": set()}
                                reflection_results[base_url]["seen_values"].add(val)
                                reflection_results[base_url]["urls"].add(url)

                parse_reflection_data(res_aa2a_httpx_sort)
                parse_reflection_data(res_bb1b_httpx_sort)

                with open(main_parameter_file, 'w') as out:
                    for base, data in reflection_results.items():
                        if len(data["seen_values"]) > 1:
                            out.write(f"\U0001F525 {base}\n")
                            for u in data["urls"]:
                                out.write(f"{u}\n")
                            out.write("\n")

                print_info(f"Reflection check complete. Sleeping for {PHASE_DELAY}s...")
                time.sleep(PHASE_DELAY)
            else:
                print_info("Phase 3 (reflection analysis) skipped by flag.")
                open(main_parameter_file, 'a').close()

            # ==================== PHASE 4: Katana Deep Crawl ====================
            all_katana_out = os.path.join(results_dir, "all_things_in_katana.out")
            if not args.skip_katana:
                if result_exists(all_katana_out):
                    print_info("Resume: katana output already exists, skipping Phase 4.")
                else:
                    print_status("Phase 4: Running Katana crawler modes...")

                    katana_js = os.path.join(temp_dir, "katana_jsfiles.txt")
                    katana_xhr = os.path.join(temp_dir, "katana_xhr.txt")
                    katana_paths = os.path.join(temp_dir, "katana_paths.txt")

                    print_info("Crawling JS endpoints...")
                    run_command_with_pipe([
                        ["katana", "-u", f"https://{domain}", "-jc", "-jsl", "-d", str(args.katana_depth),
                         "-c", str(args.threads), "-silent"] + rate_flag_katana + proxy_flag_katana,
                        ["grep", "-Ei", escaped_domain_regex],
                        ["sort", "-u"]
                    ], katana_js)
                    time.sleep(CMD_DELAY)

                    print_info("Crawling XHR endpoints...")
                    run_command_with_pipe([
                        ["katana", "-u", f"https://{domain}", "-xhr", "-kf", "all",
                         "-c", str(args.threads), "-silent"] + rate_flag_katana + proxy_flag_katana,
                        ["grep", "-Ei", escaped_domain_regex],
                        ["sort", "-u"]
                    ], katana_xhr)
                    time.sleep(CMD_DELAY)

                    print_info("Crawling target paths...")
                    run_command_with_pipe([
                        ["katana", "-u", f"https://{domain}", "-d", str(args.katana_depth), "-fs", "fqdn",
                         "-c", str(args.threads), "-silent"] + rate_flag_katana + proxy_flag_katana,
                        ["grep", "-Ei", escaped_domain_regex],
                        ["sort", "-u"]
                    ], katana_paths)
                    time.sleep(CMD_DELAY)

                    with open(all_katana_out, 'w') as outfile:
                        for f_path in [katana_js, katana_xhr, katana_paths]:
                            if os.path.exists(f_path):
                                with open(f_path, 'r', errors='ignore') as infile:
                                    outfile.write(infile.read())
                                os.remove(f_path)

                print_info(f"Katana crawls done. Sleeping for {PHASE_DELAY}s before building reports...")
                time.sleep(PHASE_DELAY)
            else:
                print_info("Phase 4 (Katana) skipped by flag.")
                open(all_katana_out, 'a').close()

            # ==================== PHASE 5: Extraction & RegEx Filtering ====================
            print_status("Phase 5: Cleaning, extracting, and sorting results...")

            combined_urls = set()
            for source in [all_katana_out, gospider_resolve_file]:
                if os.path.exists(source):
                    with open(source, 'r', errors='ignore') as f:
                        for line in f:
                            clean_line = line.strip()
                            if clean_line:
                                combined_urls.add(clean_line)

            # Apply scope filtering if provided
            dropped_out_of_scope = 0
            if scope_matcher:
                in_scope = set()
                for u in combined_urls:
                    if scope_matcher(u):
                        in_scope.add(u)
                    else:
                        dropped_out_of_scope += 1
                combined_urls = in_scope
                print_info(f"Scope filter applied: {dropped_out_of_scope} out-of-scope URL(s) dropped.")

            all_urls_file = os.path.join(temp_dir, "all_urls_combined.txt")
            with open(all_urls_file, 'w') as f:
                f.write('\n'.join(sorted(combined_urls)) + '\n')

            paths_without_params = set()
            important_paths = set()
            parameters = set()

            extensions_map = {
                "configs": re.compile(r"\.(json|xml|yml|yaml|env|config|conf|ini|properties|log|txt|md)(\?|$|#)", re.IGNORECASE),
                "scripts": re.compile(r"\.(js|js\.map|map|svg)(\?|$|#)", re.IGNORECASE),
                "web_pages": re.compile(r"\.(html|css|asp|php|aspx|jsp|cgi|cfm|do|action)(\?|$|#)", re.IGNORECASE),
                "backups": re.compile(r"\.(git|env|bak|old|zip|tar|gz|sql)(\?|$|#)", re.IGNORECASE)
            }

            cat_files = {cat: open(os.path.join(extracted_dir, "files", f"{cat}.txt"), 'w') for cat in extensions_map}

            important_path_rx = re.compile(r"/(api|admin|login|dashboard|v[0-9]|graphql|swagger|wp-json|auth|config|internal|db|test|dev)(\/|$)", re.IGNORECASE)

            for url in combined_urls:
                base_path = url.split('?')[0].split('#')[0]
                paths_without_params.add(base_path)

                if important_path_rx.search(base_path):
                    important_paths.add(base_path)

                query_parts = url.split('?')
                if len(query_parts) > 1:
                    found_params = re.findall(r"(?:^|&)([a-zA-Z0-9_\-]+)=", query_parts[1])
                    for param in found_params:
                        parameters.add(param)

                for cat, regex in extensions_map.items():
                    if regex.search(url):
                        cat_files[cat].write(f"{url}\n")

            for f in cat_files.values():
                f.close()

            with open(os.path.join(extracted_dir, "paths", "clean_paths.txt"), 'w') as f:
                f.write('\n'.join(sorted(paths_without_params)) + '\n')

            with open(os.path.join(extracted_dir, "paths", "important_paths.txt"), 'w') as f:
                f.write('\n'.join(sorted(important_paths)) + '\n')

            with open(os.path.join(extracted_dir, "params", "extracted_parameters.txt"), 'w') as f:
                f.write('\n'.join(sorted(parameters)) + '\n')

            shutil.rmtree(temp_dir, ignore_errors=True)

            # ==================== PHASE 6: Summary Generator ====================
            print_status("Phase 6: Organizing and printing execution summary...")

            summary_data = {
                "domain": domain,
                "date_run": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "total_urls": len(combined_urls),
                "clean_paths": len(paths_without_params),
                "important_paths": len(important_paths),
                "unique_parameters": len(parameters),
                "out_of_scope_dropped": dropped_out_of_scope,
                "results_dir": os.path.abspath(results_dir),
                "extracted_dir": os.path.abspath(extracted_dir),
            }

            if args.format in ("txt", "both"):
                summary_file = os.path.join(results_dir, "RECON_SUMMARY.txt")
                with open(summary_file, 'w') as sf:
                    sf.write("=====================================================\n")
                    sf.write(f"           RECON RESULTS SUMMARY FOR {domain.upper()}\n")
                    sf.write(f"           Date Run: {summary_data['date_run']}\n")
                    sf.write("=====================================================\n\n")
                    sf.write(f"[+] Total Distinct URLs Discovered : {summary_data['total_urls']}\n")
                    sf.write(f"[+] Clean Directory Paths Found     : {summary_data['clean_paths']}\n")
                    sf.write(f"[+] Critical/Important Paths Found  : {summary_data['important_paths']}\n")
                    sf.write(f"[+] Unique URL Parameter Keys Found : {summary_data['unique_parameters']}\n")
                    if scope_matcher:
                        sf.write(f"[+] Out-of-scope URLs Dropped       : {summary_data['out_of_scope_dropped']}\n")
                    sf.write(f"[+] Results directory output route  : {summary_data['results_dir']}\n")
                    sf.write(f"[+] Structured findings outputs    : {summary_data['extracted_dir']}\n\n")
                    sf.write("=====================================================\n")
                with open(summary_file, 'r') as sf:
                    print(sf.read())

            if args.format in ("json", "both"):
                summary_json_file = os.path.join(results_dir, "RECON_SUMMARY.json")
                with open(summary_json_file, 'w') as jf:
                    json.dump(summary_data, jf, indent=2)
                if args.format == "json":
                    print(json.dumps(summary_data, indent=2))

            print_status(f"Execution successfully finalized! Data saved in: '{output_dir}'")

        main()

    run()


if __name__ == "__main__":
    run_spidering_attack_tool(cli_args=sys.argv[1:])