import argparse
import subprocess
import shutil
import sys
import shlex
from pathlib import Path
import time

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'


def run_subdomain_takover(args):
    print('[-] starting subdomain tool...')

    # ---- Resolve target domains -------------------------------------------------
    target_domains = []
    if getattr(args, "domains_file", None):
        try:
            with open(args.domains_file, "r", encoding="utf-8") as f:
                target_domains = [ln.strip() for ln in f if ln.strip()]
        except Exception as exc:
            print(f"[!] could not read domains file {args.domains_file}: {exc}")
            sys.exit(1)
    elif getattr(args, "domain", None):
        target_domains = [args.domain]

    if not target_domains:
        print("[-] you must provide at least one target domain (-d or --domains-file)")
        sys.exit(1)

    def run():

        REQUIRED_TOOLS = ["subfinder", "dnsx", "naabu", "httpx"]

        def check_tools():
            missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
            if missing:
                print(f"[!] you dont have install need tool. {', '.join(missing)}")
                sys.exit(1)

        def run_pipe(cmd1, cmd2, output_path, append=False):
            mode = "ab" if append else "wb"

            print(f"[*] running {' '.join(cmd1)} | {' '.join(cmd2)} > {output_path}")

            p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE)
            p2 = subprocess.Popen(cmd2, stdin=p1.stdout, stdout=subprocess.PIPE)
            p1.stdout.close()

            out, err = p2.communicate()
            p1.wait()

            with open(output_path, mode) as f:
                f.write(out)

            return output_path

        def run_from_file(cmd, input_file, output_path):
            print(f"[*] runing cat {input_file} | {' '.join(cmd)} > {output_path}")

            with open(input_file, "rb") as inp:
                with open(output_path, "wb") as out:
                    subprocess.run(cmd, stdin=inp, stdout=out, check=False)

            return output_path

        def grep(resolve3_path):
            if not args.grep_option:
                return

            list_status = [401, 403, 500, 501, 505, 200, 301, 302, 307, 204]
            print('grep running\nstatus codes:\n', list_status)

            user_option = input('do you wanna add another status code? [n]\n=> ')
            if user_option and user_option != 'n':
                list_status.append(int(user_option.strip()))
                print(f'new status codes is =>\n{list_status}')

            print('running grep...')
            clean_path = resolve3_path.parent / "clean_resolve3.txt"

            res = subprocess.run(["uro", "-i", str(resolve3_path)], capture_output=True, text=True)
            if res.stdout:
                with open(clean_path, 'w') as f:
                    f.write(res.stdout)
            if res.stderr:
                print(f'error=>\n{res.stderr}')

            print(f'grep in => [{clean_path}]...')
            for code in list_status:
                grep_res = subprocess.run(["grep", str(code), str(clean_path)], capture_output=True, text=True)
                if grep_res.stdout:
                    out_file = resolve3_path.parent / f"grep_{code}_clean_resolve.txt"
                    with open(out_file, 'w') as f:
                        f.write(grep_res.stdout.strip())
                if grep_res.stderr:
                    print(f'Error\n{grep_res.stderr}')
                    return
                time.sleep(1)

        def main():
            check_tools()

            out_dir = Path(args.output)
            out_dir.mkdir(parents=True, exist_ok=True)

            resolve_txt = out_dir / "resolve.txt"
            resolve2_txt = out_dir / "resolve2.txt"
            resolve3_txt = out_dir / "resolve3.txt"

            # -----------------------------------------------------------------------
            # 0️ DNS resolvers
            # -----------------------------------------------------------------------
            if getattr(args, "dns_resolvers", None):
                if not getattr(args, "dnsx_args", None) or "-r" not in args.dnsx_args:
                    args.dnsx_args = (args.dnsx_args or "") + f" -r {shlex.quote(args.dns_resolvers)}"

            # -----------------------------------------------------------------------
            # 1️ Subfinder
            # -----------------------------------------------------------------------
            if not getattr(args, "skip_subfinder", False):
                subfinder_cmd = ["subfinder", "-d", target_domains[0], "-all"]

                if getattr(args, "subfinder_args", None):
                    subfinder_cmd.extend(shlex.split(args.subfinder_args))

                if len(target_domains) > 1:
                    domains_tmp = Path("subfinder_domains.txt")
                    domains_tmp.write_text("\n".join(target_domains), encoding="utf-8")
                    subfinder_cmd = ["subfinder", "-list", str(domains_tmp), "-all"]

                run_pipe(
                    cmd1=subfinder_cmd,
                    cmd2=["dnsx"] + (shlex.split(args.dnsx_args) if getattr(args, "dnsx_args", None) else []),
                    output_path=resolve_txt,
                    append=True,
                )
            else:
                Path(resolve_txt).write_bytes(b"")

            time.sleep(1.5)

            # -----------------------------------------------------------------------
            # 2️ Naabu
            # ----------------------------------------------------------------------
            naabu_cmd = ["naabu"]

            if getattr(args, "naabu_ports", None):
                naabu_cmd.extend(["-p", args.naabu_ports])
            else:
                naabu_cmd.extend(["-top-ports", args.top_ports])

            if getattr(args, "exclude_ports", None):
                naabu_cmd.extend(["-ep", args.exclude_ports])

            if getattr(args, "naabu_args", None):
                naabu_cmd.extend(shlex.split(args.naabu_args))

            run_from_file(
                cmd=naabu_cmd,
                input_file=resolve_txt,
                output_path=resolve2_txt,
            )

            time.sleep(1.5)

            # ---------------------------------------------------------------------
            # 3️ Httpx
            # -----------------------------------------------------------------------
            httpx_cmd = ["httpx", "-title", "-sc", "-cl", "-sc", "-location"]

            if getattr(args, "httpx_args", None):
                httpx_cmd.extend(shlex.split(args.httpx_args))

            run_from_file(
                cmd=httpx_cmd,
                input_file=resolve2_txt,
                output_path=resolve3_txt,
            )

            print("\n[+] done")
            print(f"    - {resolve_txt}")
            print(f"    - {resolve2_txt}")
            print(f"    - {resolve3_txt}")

            return resolve3_txt

        resolve3_txt = main()
        grep(resolve3_txt)

    run()


if __name__ == "__main__":
    print(f"{BLUE}============================================={END}")
    print(f"{BLUE}   subdomain Automation (Python) {END}")
    print(f"{BLUE}============================================={END}\n")

    parser = argparse.ArgumentParser(description="runnig pipline subfinder -> dnsx -> naabu -> httpx")

    parser.add_argument('-d', '--target-domain',
                        dest='domain',
                        help='target domain for spidering tools')

    parser.add_argument('--subfinder-args',
                        help='Additional arguments to pass to subfinder')

    parser.add_argument('--dnsx-args',
                        help='Additional arguments to pass to dnsx')

    parser.add_argument('--naabu-ports',
                        help='Comma-separated list of ports')

    parser.add_argument('--naabu-args',
                        help='Extra args for naabu')

    parser.add_argument('--httpx-args',
                        help='Additional arguments to pass to httpx')

    parser.add_argument('--skip-subfinder',
                        action='store_true',
                        help='Skip subfinder step')

    parser.add_argument('--domains-file',
                        help='File with domains list')

    parser.add_argument('--dns-resolvers',
                        help='Resolvers file for dnsx')

    parser.add_argument('--top-ports', default="100")
    parser.add_argument('--exclude-ports', dest="exclude_ports", default="")
    parser.add_argument('--output', default="output")
    parser.add_argument('--grep-option', action='store_true')

    args = parser.parse_args()
    run_subdomain_takover(args)