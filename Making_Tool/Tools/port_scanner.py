import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
import subprocess
import requests


BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = (
    "\33[94m",
    "\033[91m",
    "\33[97m",
    "\33[93m",
    "\033[1;35m",
    "\033[1;32m",
    "\033[0m",
)


def print_error(message):
    print(f"{RED}[!]{END} {message}")


def print_status(message):
    print(f"{GREEN}[+]{END} {message}")


class start:
    def __init__(self, args):
        self.url = self._normalise_url(args.target_url) if args.target_url else None
        self.time_out = float(args.time_out)
        self.user_list = args.user_list or ""
        self.file_list = args.file_list
        self.proxy = self._normalise_proxy(args.proxy)
        self.output = args.output
        self.json_output = args.json
        self.user_selection = []
        self.results = []

        self.importent_status_code = self._parse_status_codes(args.status)
        self.subdomains = self._read_lines(args.subdomain_list)

    @staticmethod
    def _normalise_url(url):
        if not url:
            return None
        if "://" not in url:
            url = f"http://{url}"
        return url.rstrip("/")

    @staticmethod
    def _normalise_proxy(proxy):
        if not proxy:
            return None
        if "://" not in proxy:
            proxy = f"http://{proxy}"
        return {"http": proxy, "https": proxy}

    @staticmethod
    def _read_lines(filename):
        if not filename:
            return []
        with open(filename, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip() and not line.lstrip().startswith("#")]

    @staticmethod
    def _parse_status_codes(status):
        if status is None:
            return [200, 301, 302, 400, 401, 403, 500]
        if isinstance(status, (list, tuple)):
            values = status
        else:
            values = str(status).replace(" ", ",").split(",")
        try:
            return [int(value) for value in values if str(value).strip()]
        except ValueError as exc:
            raise ValueError("status codes must be comma-separated integers") from exc

    def checking(self):
        if not self.url and not self.subdomains:
            print_error("you must select a target like => -t https://example.com")
            return False

        if self.file_list:
            self.user_selection = self._read_lines(self.file_list)
        else:
            self.user_selection = [
                item.strip() for item in self.user_list.split(",") if item.strip()
            ]

        if not self.user_selection:
            print_error("no ports were supplied")
            return False

        return True

    def _targets(self):
        hosts = self.subdomains or [self.url]
        for host in hosts:
            host = self._normalise_url(host)
            if not host:
                continue
            for port in self.user_selection:
                yield f"{host}:{port}"

    def _scan(self, target):
        try:
            response = requests.get(
                target,
                timeout=self.time_out,
                proxies=self.proxy,
                allow_redirects=False,
            )
            result = {
                "url": target,
                "status_code": response.status_code,
                "ok": response.status_code in self.importent_status_code,
            }
            return result
        except requests.RequestException as exc:
            return {"url": target, "status_code": None, "ok": False, "error": str(exc)}

    def _write_results(self):
        if self.output:
            output_path = Path(self.output)
            if output_path.suffix.lower() != ".txt":
                output_path.mkdir(parents=True, exist_ok=True)
                output_path = output_path / "port_scan_res.txt"
            else:
                output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as file:
                for result in self.results:
                    if result["ok"]:
                        file.write(f'{result["status_code"]} : {result["url"]}\n')
            print_status(f"done. [{output_path}]")

        if self.json_output:
            json_path = Path(self.json_output) if isinstance(self.json_output, str) else None
            if json_path and json_path.suffix.lower() != ".json":
                json_path.mkdir(parents=True, exist_ok=True)
                json_path /= "port_scan_res.json"
            elif json_path:
                json_path.parent.mkdir(parents=True, exist_ok=True)
            if json_path:
                with json_path.open("w", encoding="utf-8") as file:
                    json.dump(self.results, file, indent=2)
                print_status(f"done. [{json_path}]")
            else:
                print(json.dumps(self.results, indent=2))

    def start_port_scan(self):
        if not self.checking():
            return self.results

        targets = list(self._targets())
        workers = min(32, max(1, len(targets)))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self._scan, target) for target in targets]
            self.results = [future.result() for future in as_completed(futures)]

        self.results.sort(key=lambda result: result["url"])
        for result in self.results:
            if result["ok"]:
                print_status(f'OK => ({result["status_code"]}):\n{result["url"]}')
                print(f"{YELLOW}{'-' * 20}{END}")

        self._write_results()
        return self.results


if __name__ == "__main__":
    print(f"{BLUE}============================================={END}")
    print(f"{BLUE}            Port Scanner (Python) {END}")
    print(f"{BLUE}============================================={END}\n")
    print(f'{YELLOW}NOTE:{END} if you`ve use subdomain tool , give the res to this tool for scan , otherwise nothing :) ')
    
    words = [122, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    argument_parser = argparse.ArgumentParser(description="Port Scanner")
    argument_parser.add_argument("-t", "--target_url", help="Target URL for reconnaissance")
    argument_parser.add_argument(
        "-ul", "--user_list", default=",".join(map(str, words)), help="comma-separated port list"
    )
    argument_parser.add_argument("-fl", "--file_list", help="file containing one port per line")
    argument_parser.add_argument(
        "-T", "--time_out", type=float, default=5, help="request timeout in seconds"
    )
    argument_parser.add_argument("-s", "--status", help="comma-separated HTTP status codes")
    argument_parser.add_argument("-p", "--proxy", help="HTTP/S proxy, for example http://127.0.0.1:8080")
    argument_parser.add_argument(
        "-j", "--json", nargs="?", const=True, help="print JSON or write JSON to the supplied path"
    )
    argument_parser.add_argument("-o", "--output", help="output directory or .txt file")
    argument_parser.add_argument("-sb", "--subdomain_list", help="file containing subdomain URLs")

    
    argument_parser.print_help()
    user_command = input('[-] select your command [exit=exit] => ').split()
    if user_command == 'exit':
        sys.exit()
    args = argument_parser.parse_args(user_command)
    scanner = start(args)
    
    try:
        scanner.start_port_scan()
    except KeyboardInterrupt:
        print_error("BY")
        sys.exit(130)
    except (OSError, ValueError) as exc:
        print_error(f"Error {exc}")
        sys.exit(1)
