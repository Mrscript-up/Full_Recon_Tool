import argparse
import subprocess
import shutil
import sys
from pathlib import Path
import time

def run_subdomain_takover(args):
    print('[-] starting subdomain tool...')
    def run():

        REQUIRED_TOOLS = ["subfinder", "dnsx", "naabu", "httpx"]

        def check_tools():
            """chacking need tool"""
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
            """فقط وقتی -grep داده شده باشه اجرا میشه"""
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

            # step 1
            run_pipe(
                cmd1=["subfinder", "-d", args.domain, "-all"],
                cmd2=["dnsx"],
                output_path=resolve_txt,
                append=True,
            )

            # step 2
            run_from_file(
                cmd=["naabu", "-top-ports", args.top_ports, "-ep", args.exclude_ports],
                input_file=resolve_txt,
                output_path=resolve2_txt,
            )

            # step 3
            run_from_file(
                cmd=["httpx", "-title", "-sc", "-cl", "-sc", "-location"],
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
    parser = argparse.ArgumentParser(description="runnig pipline subfinder -> dnsx -> naabu -> httpx")
    
    parser.add_argument("-d", "--domain", help="target domain")
    parser.add_argument('-o', '--output', default='./subdomain_tool',help='output directory')
    parser.add_argument("-tp", "--top-ports", default="1000", help="top ports to scan (default: 1000)")
    parser.add_argument("-ep", "--exclude-ports", default="", help="ports to exclude from scan (comma-separated)")
    parser.add_argument("-grep", "--grep_option", help="grep option for taking importent information from 'HTTPX'.", action="store_true")
    
    args = parser.parse_args()
    run_subdomain_takover(args)   
