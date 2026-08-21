#!/usr/bin/env python3
"""
install_recon_tools.py

Checks whether a set of recon tools are already installed on a Linux
system, and installs whichever ones are missing.

Tools covered:
    Go-based   : gospider, katana, qsreplace, httpx, subfinder, dnsx, naabu
    Pip-based  : uro, paramspider
    Apt-based  : whatweb
    Gem-based  : wpscan

Usage:
    python3 install_recon_tools.py            # check + install missing (asks to confirm)
    python3 install_recon_tools.py --check    # only report what's missing, install nothing
    python3 install_recon_tools.py --yes      # don't prompt, just install everything missing
"""

import argparse
import os
import shutil
import subprocess
import sys
import platform

# ---------------------------------------------------------------------------
# Config: which repo / package each tool comes from
# ---------------------------------------------------------------------------

GO_TOOLS = {
    "gospider":  "github.com/jaeles-project/gospider@latest",
    "katana":    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "qsreplace": "github.com/tomnomnom/qsreplace@latest",
    "httpx":     "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "dnsx":      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "naabu":     "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
}

PIP_TOOLS = {
    "uro": "uro",  # published on PyPI
}

GIT_PIP_TOOLS = {
    # binary name -> git repo (installed with `pip install .` after cloning)
    "paramspider": "https://github.com/devanshbatham/ParamSpider.git",
}

APT_TOOLS = {
    "whatweb": "whatweb",
}

GEM_TOOLS = {
    "wpscan": "wpscan",
}

GITHUB_LINKS = {
    "gospider":   "https://github.com/jaeles-project/gospider",
    "paramspider": "https://github.com/devanshbatham/ParamSpider",
    "katana":     "https://github.com/projectdiscovery/katana",
    "qsreplace":  "https://github.com/tomnomnom/qsreplace",
    "httpx":      "https://github.com/projectdiscovery/httpx",
    "subfinder":  "https://github.com/projectdiscovery/subfinder",
    "dnsx":       "https://github.com/projectdiscovery/dnsx",
    "naabu":      "https://github.com/projectdiscovery/naabu",
    "uro":        "https://github.com/s0md3v/uro",
    "whatweb":    "https://github.com/urbanadventurer/WhatWeb",
    "wpscan":     "https://github.com/wpscanteam/wpscan",
}

GO_BIN_DIRS = [
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def color(text, code):
    return f"\033[{code}m{text}\033[0m"


def ok(text):
    return color(text, "92")


def warn(text):
    return color(text, "93")


def err(text):
    return color(text, "91")


def info(text):
    return color(text, "96")


def run(cmd, **kwargs):
    """Run a shell command, streaming output, return True on success."""
    print(info(f"    $ {cmd}"))
    result = subprocess.run(cmd, shell=True, **kwargs)
    return result.returncode == 0


def is_installed(binary_name):
    """Check PATH plus common Go bin dirs for the binary."""
    if shutil.which(binary_name):
        return True
    for d in GO_BIN_DIRS:
        if os.path.isfile(os.path.join(d, binary_name)):
            return True
    return False


def which_present(binary_name):
    """Return the full path if found (searching PATH + go bin dirs), else None."""
    found = shutil.which(binary_name)
    if found:
        return found
    for d in GO_BIN_DIRS:
        candidate = os.path.join(d, binary_name)
        if os.path.isfile(candidate):
            return candidate
    return None


def ensure_prerequisite(binary, apt_package=None):
    """Make sure a prerequisite command-line tool (go, pip3, gem, git) exists.
    If missing, try to install it with apt (Debian/Ubuntu/Kali)."""
    if shutil.which(binary):
        return True
    print(warn(f"[!] Prerequisite '{binary}' not found."))
    if apt_package and shutil.which("apt-get"):
        print(info(f"[*] Attempting to install prerequisite '{apt_package}' via apt..."))
        return run(f"sudo apt-get update -y && sudo apt-get install -y {apt_package}")
    print(err(f"[x] Could not auto-install '{binary}'. Please install it manually."))
    return False


# ---------------------------------------------------------------------------
# Install functions
# ---------------------------------------------------------------------------

def install_go_tool(binary, module_path):
    if not ensure_prerequisite("go", apt_package="golang-go"):
        return False
    print(info(f"[*] Installing {binary} via 'go install'..."))
    success = run(f"go install {module_path}")
    if success:
        # Make sure ~/go/bin is usable; copy binary to /usr/local/bin as a convenience
        go_bin = os.path.expanduser("~/go/bin")
        src = os.path.join(go_bin, binary)
        if os.path.isfile(src):
            run(f"sudo cp {src} /usr/local/bin/{binary}")
    return success


def install_pip_tool(binary, package_name):
    if not ensure_prerequisite("pip3", apt_package="python3-pip"):
        return False
    print(info(f"[*] Installing {binary} via pip..."))
    return run(f"pip3 install --user --upgrade {package_name}")


def install_git_pip_tool(binary, git_url):
    if not ensure_prerequisite("git", apt_package="git"):
        return False
    if not ensure_prerequisite("pip3", apt_package="python3-pip"):
        return False
    tmp_dir = f"/tmp/{binary}_src"
    print(info(f"[*] Cloning {git_url}..."))
    if not run(f"rm -rf {tmp_dir} && git clone --depth 1 {git_url} {tmp_dir}"):
        return False
    print(info(f"[*] Installing {binary} from source..."))
    return run(f"pip3 install --user {tmp_dir}") or run(f"cd {tmp_dir} && pip3 install --user .")


def install_apt_tool(binary, apt_package):
    if not shutil.which("apt-get"):
        print(err("[x] apt-get not found; install this tool manually for your distro."))
        return False
    print(info(f"[*] Installing {binary} via apt..."))
    return run(f"sudo apt-get update -y && sudo apt-get install -y {apt_package}")


def install_gem_tool(binary, gem_name):
    if not ensure_prerequisite("gem", apt_package="ruby-full"):
        return False
    print(info(f"[*] Installing {binary} via gem..."))
    return run(f"sudo gem install {gem_name}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

ALL_TOOLS = (
    list(GO_TOOLS.keys())
    + list(PIP_TOOLS.keys())
    + list(GIT_PIP_TOOLS.keys())
    + list(APT_TOOLS.keys())
    + list(GEM_TOOLS.keys())
)


def install_tool(name):
    if name in GO_TOOLS:
        return install_go_tool(name, GO_TOOLS[name])
    if name in PIP_TOOLS:
        return install_pip_tool(name, PIP_TOOLS[name])
    if name in GIT_PIP_TOOLS:
        return install_git_pip_tool(name, GIT_PIP_TOOLS[name])
    if name in APT_TOOLS:
        return install_apt_tool(name, APT_TOOLS[name])
    if name in GEM_TOOLS:
        return install_gem_tool(name, GEM_TOOLS[name])
    print(err(f"[x] No installer configured for {name}"))
    return False


def main():
    parser = argparse.ArgumentParser(description="Check/install recon tools on Linux.")
    parser.add_argument("--check", action="store_true", help="Only check, don't install anything.")
    parser.add_argument("--yes", "-y", action="store_true", help="Don't prompt before installing.")
    args = parser.parse_args()

    if platform.system() != "Linux":
        print(err("This script is intended for Linux systems only.\nrun only on linux."))
        sys.exit(1)

    print(info("=" * 60))
    print(info(" Recon Tool Checker / Installer"))
    print(info("=" * 60))

    missing = []
    for tool in ALL_TOOLS:
        path = which_present(tool)
        if path:
            print(ok(f"[✓] {tool:<12} found at {path}"))
        else:
            print(warn(f"[ ] {tool:<12} NOT found  ({GITHUB_LINKS[tool]})"))
            missing.append(tool)

    if not missing:
        print(ok("\nAll tools are already installed. Nothing to do."))
        return

    print(info(f"\n{len(missing)} tool(s) missing: {', '.join(missing)}"))

    if args.check:
        print(info("--check flag set, skipping installation."))
        return

    if not args.yes:
        answer = input("\nInstall missing tools now? [y/N]: ").strip().lower()
        if answer != "y":
            print(info("Aborted by user."))
            return

    print(info("\nStarting installation...\n"))
    results = {}
    for tool in missing:
        print(info(f"--- {tool} ---"))
        results[tool] = install_tool(tool)
        print()

    print(info("=" * 60))
    print(info(" Installation summary"))
    print(info("=" * 60))
    for tool, success in results.items():
        if success:
            print(ok(f"[✓] {tool} installed"))
        else:
            print(err(f"[x] {tool} FAILED — install manually: {GITHUB_LINKS[tool]}"))

    print(warn(
        "\nNote: Go-installed tools land in ~/go/bin. "
        "Make sure that directory is in your PATH, e.g.:\n"
        '  echo \'export PATH=$PATH:~/go/bin\' >> ~/.bashrc && source ~/.bashrc'
    ))


if __name__ == "__main__":
    main()