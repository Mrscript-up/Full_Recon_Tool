import argparse
import sys
import os
import re
import json
import shlex
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def run_commnet_descovary_tool(args=None):
    """
    comment_extractor.py — Extract comments from source code files.

    Now supports three modes, same as LinkFinder:
      1. run_commnet_descovary_tool(self)              -> interactive loop
      2. run_commnet_descovary_tool(self, "some cmd")   -> run one command, then loop
      3. run_commnet_descovary_tool(self, parsed_ns)    -> run once and return (no loop)
    """
    print('[-] run_comment_descovary...')

    # ---------------------------------------------------------------------------
    # Language configuration
    # ---------------------------------------------------------------------------
    LANGUAGES = {
        'web_markup': {
            'name': 'HTML / XML',
            'extensions': ('.html', '.htm', '.xml', '.xhtml', '.vue', '.svg'),
            'filenames': (),
            'line_comments': (),
            'block_comments': (('<!--', '-->'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'css': {
            'name': 'CSS / SCSS / LESS',
            'extensions': ('.css', '.scss', '.sass', '.less'),
            'filenames': (),
            'line_comments': ('//',),
            'block_comments': (('/*', '*/'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'javascript': {
            'name': 'JavaScript / TypeScript',
            'extensions': ('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
                           '.mts', '.cts'),
            'filenames': (),
            'line_comments': ('//',),
            'block_comments': (('/*', '*/'),),
            'strings': ('"', "'", '`'),
            'escape': '\\',
        },
        'php': {
            'name': 'PHP',
            'extensions': ('.php', '.phtml', '.php3', '.php4', '.php5'),
            'filenames': (),
            'line_comments': ('//', '#'),
            'block_comments': (('/*', '*/'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'python': {
            'name': 'Python',
            'extensions': ('.py', '.pyw', '.pyi'),
            'filenames': (),
            'line_comments': ('#',),
            'block_comments': (),
            'strings': ('"""', "'''", '"', "'"),
            'escape': '\\',
        },
        'c_family': {
            'name': 'C / C++ / Java / C# / Go / Rust / Swift / Kotlin',
            'extensions': ('.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hxx',
                           '.java', '.cs', '.go', '.rs', '.swift', '.kt', '.kts'),
            'filenames': (),
            'line_comments': ('//',),
            'block_comments': (('/*', '*/'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'ruby': {
            'name': 'Ruby',
            'extensions': ('.rb', '.rbw'),
            'filenames': (),
            'line_comments': ('#',),
            'block_comments': (('=begin', '=end'),),
            'strings': ('"', "'", '`'),
            'escape': '\\',
        },
        'shell': {
            'name': 'Shell / Bash / Zsh',
            'extensions': ('.sh', '.bash', '.zsh', '.ksh', '.fish'),
            'filenames': (),
            'line_comments': ('#',),
            'block_comments': (),
            'strings': ('"', "'", '`'),
            'escape': '\\',
        },
        'sql': {
            'name': 'SQL',
            'extensions': ('.sql',),
            'filenames': (),
            'line_comments': ('--',),
            'block_comments': (('/*', '*/'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'config': {
            'name': 'YAML / INI / TOML / Config',
            'extensions': ('.yaml', '.yml', '.ini', '.cfg', '.conf',
                           '.toml', '.properties'),
            'filenames': (),
            'line_comments': ('#', ';'),
            'block_comments': (),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'jsonc': {
            'name': 'JSONC / JSON5',
            'extensions': ('.jsonc', '.json5'),
            'filenames': (),
            'line_comments': ('//',),
            'block_comments': (('/*', '*/'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'dockerfile': {
            'name': 'Dockerfile / Makefile',
            'extensions': ('.dockerfile', '.mk'),
            'filenames': ('Dockerfile', 'Makefile', 'makefile', 'GNUmakefile'),
            'line_comments': ('#',),
            'block_comments': (),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'vim': {
            'name': 'Vim Script',
            'extensions': ('.vim',),
            'filenames': ('.vimrc', '_vimrc'),
            'line_comments': ('"',),
            'block_comments': (),
            'strings': ("'",),
            'escape': '\\',
        },
        'lua': {
            'name': 'Lua',
            'extensions': ('.lua',),
            'filenames': (),
            'line_comments': ('--',),
            'block_comments': (('--[[', ']]'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'haskell': {
            'name': 'Haskell',
            'extensions': ('.hs', '.lhs'),
            'filenames': (),
            'line_comments': ('--',),
            'block_comments': (('{-', '-}'),),
            'strings': ('"', "'"),
            'escape': '\\',
        },
        'lisp': {
            'name': 'Lisp / Clojure / Scheme',
            'extensions': ('.lisp', '.clj', '.cljs', '.cljc', '.scm', '.rkt'),
            'filenames': (),
            'line_comments': (';',),
            'block_comments': (('#|', '|#'),),
            'strings': ('"',),
            'escape': '\\',
        },
        'erlang': {
            'name': 'Erlang',
            'extensions': ('.erl', '.hrl'),
            'filenames': (),
            'line_comments': ('%',),
            'block_comments': (),
            'strings': ('"',),
            'escape': '\\',
        },
        'fortran': {
            'name': 'Fortran',
            'extensions': ('.f', '.f90', '.f95', '.for', '.f03'),
            'filenames': (),
            'line_comments': ('!',),
            'block_comments': (),
            'strings': ('"', "'"),
            'escape': '',
        },
        'powershell': {
            'name': 'PowerShell',
            'extensions': ('.ps1', '.psm1', '.psd1'),
            'filenames': (),
            'line_comments': ('#',),
            'block_comments': (('<#', '#>'),),
            'strings': ('"', "'"),
            'escape': '`',
        },
        'batch': {
            'name': 'Batch / CMD',
            'extensions': ('.bat', '.cmd'),
            'filenames': (),
            'line_comments': ('REM', '::'),
            'block_comments': (),
            'strings': (),
            'escape': '',
        },
    }

    # ---------------------------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------------------------

    def _build_lookup_tables():
        """Build (ext -> lang_key) and (filename -> lang_key) tables."""
        ext_map, name_map = {}, {}
        for key, cfg in LANGUAGES.items():
            for ext in cfg['extensions']:
                ext_map[ext.lower()] = key
            for fn in cfg['filenames']:
                name_map[fn.lower()] = key
        return ext_map, name_map

    _EXT_MAP, _NAME_MAP = _build_lookup_tables()

    def detect_language(filepath: Path):
        name = filepath.name.lower()
        if name in _NAME_MAP:
            return _NAME_MAP[name]
        ext = filepath.suffix.lower()
        return _EXT_MAP.get(ext)

    def is_binary(raw: bytes) -> bool:
        return b'\x00' in raw[:8192]

    def _is_word_marker(marker: str) -> bool:
        return bool(marker) and all(c.isalnum() or c == '_' for c in marker)

    # ---------------------------------------------------------------------------
    # Core: state-machine comment extractor
    # ---------------------------------------------------------------------------

    def extract_comments(content: str, cfg: dict):
        """Walk the source character-by-character with a state machine.

        States: code | string | line_comment | block_comment
        Returns a list of dicts: {line_start, line_end, text, type}
        """
        line_comments = sorted(cfg['line_comments'], key=len, reverse=True)
        block_comments = sorted(cfg['block_comments'],
                                 key=lambda x: len(x[0]), reverse=True)
        strings = sorted(cfg['strings'], key=len, reverse=True)
        escape = cfg.get('escape', '\\') or ''

        results = []
        i, n = 0, len(content)
        line = 1
        state = 'code'
        string_delim = ''
        block_end = ''
        buf = []
        comment_start_line = 1

        while i < n:
            ch = content[i]
            rest = content[i:]

            if state == 'code':
                matched = False

                # 1) Block comments (checked first so e.g. Lua --[[ wins over --)
                for bs, be in block_comments:
                    if rest.startswith(bs):
                        state = 'block_comment'
                        block_end = be
                        buf = []
                        comment_start_line = line
                        i += len(bs)
                        matched = True
                        break
                if matched:
                    continue

                # 2) Line comments
                for lc in line_comments:
                    if rest.startswith(lc):
                        if _is_word_marker(lc):
                            prev = content[i - 1] if i > 0 else ''
                            if prev and (prev.isalnum() or prev == '_'):
                                continue
                        state = 'line_comment'
                        buf = []
                        comment_start_line = line
                        i += len(lc)
                        matched = True
                        break
                if matched:
                    continue

                # 3) Strings
                for s in strings:
                    if rest.startswith(s):
                        state = 'string'
                        string_delim = s
                        i += len(s)
                        matched = True
                        break
                if matched:
                    continue

                if ch == '\n':
                    line += 1
                i += 1

            elif state == 'string':
                if escape and ch == escape and i + 1 < n:
                    if content[i + 1] == '\n':
                        line += 1
                    i += 2
                    continue
                if rest.startswith(string_delim):
                    i += len(string_delim)
                    state = 'code'
                    continue
                if ch == '\n':
                    line += 1
                i += 1

            elif state == 'line_comment':
                if ch == '\n':
                    results.append({
                        'line_start': comment_start_line,
                        'line_end': line,
                        'text': ''.join(buf).strip(),
                        'type': 'line',
                    })
                    line += 1
                    i += 1
                    state = 'code'
                    buf = []
                    continue
                buf.append(ch)
                i += 1

            elif state == 'block_comment':
                if rest.startswith(block_end):
                    results.append({
                        'line_start': comment_start_line,
                        'line_end': line,
                        'text': ''.join(buf).strip(),
                        'type': 'block',
                    })
                    i += len(block_end)
                    state = 'code'
                    buf = []
                    continue
                if ch == '\n':
                    line += 1
                buf.append(ch)
                i += 1

        # Handle EOF inside a comment
        if state == 'line_comment' and buf:
            results.append({
                'line_start': comment_start_line,
                'line_end': line,
                'text': ''.join(buf).strip(),
                'type': 'line',
            })
        elif state == 'block_comment' and buf:
            results.append({
                'line_start': comment_start_line,
                'line_end': line,
                'text': ''.join(buf).strip(),
                'type': 'block',
            })

        return results

    # ---------------------------------------------------------------------------
    # File processing
    # ---------------------------------------------------------------------------

    def process_file(filepath: Path, min_length: int = 0):
        try:
            with open(filepath, 'rb') as f:
                raw = f.read()
        except OSError as e:
            return None, f"read error: {e}"

        if is_binary(raw):
            return None, "binary"

        try:
            content = raw.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = raw.decode('latin-1')
            except Exception:
                return None, "decode error"

        lang_key = detect_language(filepath)
        if not lang_key:
            return None, "unknown language"

        cfg = LANGUAGES[lang_key]
        comments = extract_comments(content, cfg)
        if min_length > 0:
            comments = [c for c in comments if len(c['text']) >= min_length]

        return {
            'file': str(filepath),
            'language': cfg['name'],
            'comment_count': len(comments),
            'comments': comments,
        }, None

    def find_files(path, extensions=None, exclude_dirs=None):
        exclude_dirs = set(exclude_dirs or [])
        ext_set = set(extensions) if extensions else None
        p = Path(path)

        if p.is_file():
            if not ext_set or p.suffix.lower() in ext_set \
                    or p.name.lower() in ext_set:
                yield p
            return

        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for f in files:
                fp = Path(root) / f
                if ext_set and fp.suffix.lower() not in ext_set \
                        and fp.name.lower() not in ext_set:
                    continue
                yield fp

    # ---------------------------------------------------------------------------
    # Output formatting
    # ---------------------------------------------------------------------------

    def _lang_slug(lang: str) -> str:
        return re.sub(r'[^a-z0-9]+', '_', lang.lower()).strip('_')

    def format_text(results, stats):
        out = []
        bar = "=" * 72
        out.append(bar)
        out.append("  COMMENT EXTRACTION REPORT  \n           Mrscript")
        out.append(bar)
        out.append(f"Generated           : {stats['generated_at']}")
        out.append(f"Source path         : {stats['path']}")
        out.append(f"Files scanned       : {stats['files_scanned']}")
        out.append(f"Files with comments : {stats['files_with_comments']}")
        out.append(f"Total comments      : {stats['total_comments']}")
        out.append(bar)
        out.append("")

        for r in results:
            if not r['comments']:
                continue
            out.append("-" * 72)
            out.append(f"FILE     : {r['file']}")
            out.append(f"LANGUAGE : {r['language']}")
            out.append(f"COMMENTS : {r['comment_count']}")
            out.append("-" * 72)
            for c in r['comments']:
                rng = f"L{c['line_start']}"
                if c['line_end'] != c['line_start']:
                    rng += f"-L{c['line_end']}"
                tag = 'LINE ' if c['type'] == 'line' else 'BLOCK'
                out.append(f"  [{tag} {rng}]")
                for ln in c['text'].splitlines() or ['']:
                    out.append(f"    {ln}")
                    out.append("-" * 72)
                out.append("")
            out.append("")
        return '\n'.join(out)

    def format_markdown(results, stats):
        out = []
        out.append("# Comment Extraction Report\n")
        out.append(f"- **Generated:** `{stats['generated_at']}`")
        out.append(f"- **Source path:** `{stats['path']}`")
        out.append(f"- **Files scanned:** {stats['files_scanned']}")
        out.append(f"- **Files with comments:** {stats['files_with_comments']}")
        out.append(f"- **Total comments:** {stats['total_comments']}\n")

        if stats['by_language']:
            out.append("## Summary by Language\n")
            out.append("| Language | Files | Comments |")
            out.append("|----------|------:|---------:|")
            for lang, s in sorted(stats['by_language'].items(),
                                   key=lambda x: -x[1]['comments']):
                out.append(f"| {lang} | {s['files']} | {s['comments']} |")
            out.append("")

        out.append("## Extracted Comments\n")
        for r in results:
            if not r['comments']:
                continue
            out.append(f"### `{r['file']}`")
            out.append(f"*{r['language']} — {r['comment_count']} comments*\n")
            for c in r['comments']:
                rng = f"L{c['line_start']}"
                if c['line_end'] != c['line_start']:
                    rng += f"–L{c['line_end']}"
                tag = 'line' if c['type'] == 'line' else 'block'
                out.append(f"**`{tag} {rng}`**")
                out.append(f"\n-----------------------------------------------\n")
                out.append(f"```\n{c['text']}\n```\n")
        return '\n'.join(out)

    def format_json(results, stats):
        return json.dumps({'stats': stats, 'results': results},
                           indent=2, ensure_ascii=False)

    def render(fmt, rs, st):
        if fmt == 'txt':
            return format_text(rs, st)
        if fmt == 'md':
            return format_markdown(rs, st)
        return format_json(rs, st)

    # ---------------------------------------------------------------------------
    # Parser (definition only — no parse_args() call here)
    # ---------------------------------------------------------------------------

    def create_parser() -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog='comment_extractor',
            description='Extract comments from source code files.',
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        # nargs='?' instead of required positional, so the interactive loop
        # doesn't crash when a bare command with no path is typed.
        parser.add_argument('path', nargs='?', help='File or directory to scan')
        parser.add_argument('-o', '--output', default='comments_output.txt',
                             help='Output file path (default: comments_output.txt)')
        parser.add_argument('-f', '--format', choices=['txt', 'json', 'md'],
                             default='txt', help='Output format (default: txt)')
        parser.add_argument('-e', '--extensions',
                             help='Comma-separated list of extensions/filenames to '
                                  'include (e.g. .py,.js,.html,Dockerfile)')
        parser.add_argument('--min-length', type=int, default=0,
                             help='Minimum comment text length to include')
        parser.add_argument('--exclude-dirs',
                             default='.git,.svn,.hg,node_modules,__pycache__,'
                                     'venv,env,.venv,dist,build,target,out,.idea,.vscode',
                             help='Comma-separated directory names to exclude')
        parser.add_argument('--split-by-language', action='store_true',
                             help='Write one output file per language '
                                  '(based on -o as prefix)')
        parser.add_argument('--stats', action='store_true',
                             help='Print stats to stderr')
        parser.add_argument('-v', '--verbose', action='store_true',
                             help='Verbose output')
        return parser

    # ---------------------------------------------------------------------------
    # Runs one already-parsed set of args (used by both direct calls and the loop)
    # ---------------------------------------------------------------------------

    def run_from_args(parsed_args):
        if not parsed_args.path:
            print("[!] No path provided. Usage: <path> [-o out] [-f txt|json|md] ...")
            return

        if not os.path.exists(parsed_args.path):
            print(f"[!] Error: path not found: {parsed_args.path}", file=sys.stderr)
            return

        extensions = None
        if parsed_args.extensions:
            extensions = [e.strip().lower() for e in parsed_args.extensions.split(',')
                          if e.strip()]
        exclude_dirs = [d.strip() for d in parsed_args.exclude_dirs.split(',') if d.strip()]

        if parsed_args.verbose:
            print(f"[*] Scanning: {parsed_args.path}", file=sys.stderr)
            if extensions:
                print(f"[*] Filter extensions: {extensions}", file=sys.stderr)

        results = []
        files_scanned = 0
        files_with_comments = 0
        total_comments = 0
        by_language = defaultdict(lambda: {'files': 0, 'comments': 0})

        for fp in find_files(parsed_args.path, extensions, exclude_dirs):
            files_scanned += 1
            if parsed_args.verbose:
                print(f"[*]    scanning {fp}", file=sys.stderr)
            data, err = process_file(fp, parsed_args.min_length)
            if err:
                if parsed_args.verbose and err != 'unknown language':
                    print(f"[*]    [skip] {fp}: {err}", file=sys.stderr)
                continue
            if data is None:
                continue
            results.append(data)
            if data['comment_count'] > 0:
                files_with_comments += 1
                total_comments += data['comment_count']
                by_language[data['language']]['files'] += 1
                by_language[data['language']]['comments'] += data['comment_count']

        stats = {
            'generated_at': datetime.now().isoformat(timespec='seconds'),
            'path': os.path.abspath(parsed_args.path),
            'files_scanned': files_scanned,
            'files_with_comments': files_with_comments,
            'total_comments': total_comments,
            'by_language': dict(by_language),
        }

        written = []
        if parsed_args.split_by_language:
            grouped = defaultdict(list)
            for r in results:
                if r['comments']:
                    grouped[r['language']].append(r)

            base, ext = os.path.splitext(parsed_args.output)
            if not ext:
                ext = '.txt' if parsed_args.format == 'txt' \
                    else '.json' if parsed_args.format == 'json' else '.md'

            for lang, lang_results in grouped.items():
                slug = _lang_slug(lang)
                out_path = f"{base}_{slug}{ext}"
                lang_stats = {
                    'generated_at': stats['generated_at'],
                    'path': stats['path'],
                    'files_scanned': len(lang_results),
                    'files_with_comments': len(lang_results),
                    'total_comments': sum(r['comment_count']
                                           for r in lang_results),
                    'by_language': {lang: {
                        'files': len(lang_results),
                        'comments': sum(r['comment_count']
                                         for r in lang_results),
                    }},
                }
                with open(out_path, 'w', encoding='utf-8') as f:
                    f.write(render(parsed_args.format, lang_results, lang_stats))
                written.append(out_path)
        else:
            with open(parsed_args.output, 'w', encoding='utf-8') as f:
                f.write(render(parsed_args.format, results, stats))
            written.append(parsed_args.output)

        if parsed_args.stats or parsed_args.verbose:
            print("", file=sys.stderr)
            print(f"[OK] Scanned {files_scanned} files — found "
                  f"{total_comments} comments in {files_with_comments} files.",
                  file=sys.stderr)
            for p in written:
                print(f"[OK] Output written: {p}", file=sys.stderr)
            if by_language:
                print("", file=sys.stderr)
                print("[-] By language:", file=sys.stderr)
                for lang, s in sorted(by_language.items(),
                                       key=lambda x: -x[1]['comments']):
                    print(f"    {lang:<45} {s['files']:>4} files / "
                          f"{s['comments']:>5} comments", file=sys.stderr)

    # ---------------------------------------------------------------------------
    # Interactive loop — same shape as LinkFinder's
    # ---------------------------------------------------------------------------

    def run_interactive_loop(initial_input=None):
        parser = create_parser()
        print("\n[-] Comment Extractor interactive mode")
        print("[-] Type 'help' for usage or 'exit' to quit.")
        print("[-] Examples:")
        print("[-]  ./src -f md -o report.md")
        print("[-]  ./app.py --min-length 5 --stats")

        while True:
            if initial_input is not None:
                command = str(initial_input).strip()
                initial_input = None
                print(f"[-] comment-extractor> {command}")
            else:
                try:
                    command = input("comment-extractor> ").strip()
                except KeyboardInterrupt:
                    print("\n[!] Goodbye!")
                    break
                except EOFError:
                    print("\n[!] Goodbye!")
                    break

            if not command:
                continue

            if command.lower() in {'exit', 'quit'}:
                print("[-] Exiting Comment Extractor.")
                break

            if command.lower() in {'help', '?'}:
                parser.print_help()
                continue

            try:
                tokens = shlex.split(command)
            except ValueError as exc:
                print(f"[!] Error Invalid input: {exc}")
                continue

            try:
                parsed_args = parser.parse_args(tokens)
            except SystemExit:
                continue

            run_from_args(parsed_args)

    # ---------------------------------------------------------------------------
    # Entry point — mirrors LinkFinder's main(args)
    # ---------------------------------------------------------------------------

    def main(args=None):
        if args is None:
            run_interactive_loop()
            return

        if isinstance(args, str):
            run_interactive_loop(initial_input=args)
            return

        run_from_args(args)

    main(args)