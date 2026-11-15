"""Lexical analysis of JavaScript and TypeScript without a parser.

The Python standard library has no JavaScript parser and this project takes no
dependencies, so this module does careful lexing instead of parsing. It knows
how to skip strings, template literals (including nested ``${}``), regular
expression literals and comments, which is what pattern-based checks need in
order not to fire inside a comment or a string.

Limits: this is heuristic. Unusual formatting, JSX text containing quote
characters, or exotic syntax can fool it. Every check built on it must report
confidence ``likely`` at most, unless the matched pattern is unambiguous on its
own.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

_REGEX_PREV_CHARS = set("(,=:[!&|?{};+-*%~^\n")
_REGEX_PREV_WORDS = ("return", "typeof", "case", "in", "of", "do", "else", "void", "throw", "new", "delete", "await", "yield")


class Lexed(NamedTuple):
    code: str        # comments and string contents blanked, same length as the source
    nocomment: str   # only comments blanked, same length as the source
    strings: List[Tuple[int, int, str]]   # (start, end, value) of string literals, quotes excluded
    comments: List[Tuple[int, int, str]]  # (start, end, text)


def _blank(chunk: str) -> str:
    return "".join("\n" if c == "\n" else " " for c in chunk)


def lex(text: str) -> Lexed:
    """Tokenise enough of JS/TS to separate code from comments and strings."""
    n = len(text)
    code: List[str] = []
    nocomment: List[str] = []
    strings: List[Tuple[int, int, str]] = []
    comments: List[Tuple[int, int, str]] = []
    i = 0
    last_sig = "\n"      # last significant (non-space) character of code
    last_word = ""
    template_depth: List[int] = []  # brace depth at which each open template's ${ } closes
    brace = 0

    def emit(chunk: str, as_code: bool, keep_nc: bool = True) -> None:
        code.append(chunk if as_code else _blank(chunk))
        nocomment.append(chunk if keep_nc else _blank(chunk))

    def read_template(start: int) -> int:
        """Read template text from ``start`` (just after ` or }) up to ${ or the closing `."""
        nonlocal brace
        j = start
        buf_start = start
        while j < n:
            c = text[j]
            if c == "\\":
                j += 2
                continue
            if c == "`":
                strings.append((buf_start, j, text[buf_start:j]))
                emit(text[buf_start:j], False)
                emit("`", True)
                return j + 1
            if c == "$" and j + 1 < n and text[j + 1] == "{":
                strings.append((buf_start, j, text[buf_start:j]))
                emit(text[buf_start:j], False)
                emit("${", True)
                brace += 1
                template_depth.append(brace)
                return j + 2
            j += 1
        emit(text[buf_start:n], False)
        return n

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            comments.append((i, j, text[i:j]))
            emit(text[i:j], False, False)
            i = j
            continue
        if c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            comments.append((i, j, text[i:j]))
            emit(text[i:j], False, False)
            i = j
            continue
        if c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j, n)
            closed = j < n and text[j] == c
            emit(c, True)
            strings.append((i + 1, j, text[i + 1:j]))
            emit(text[i + 1:j], False)
            if closed:
                emit(c, True)
                j += 1
            i = j
            last_sig = c
            last_word = ""
            continue
        if c == "`":
            emit("`", True)
            i = read_template(i + 1)
            last_sig = "`"
            last_word = ""
            continue
        if c == "/" and (last_sig in _REGEX_PREV_CHARS or last_word in _REGEX_PREV_WORDS) and last_sig != "<" and nxt not in ("", " ", "\n", ">", "="):
            j = i + 1
            in_class = False
            ok = False
            while j < n and text[j] != "\n":
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "[":
                    in_class = True
                elif ch == "]":
                    in_class = False
                elif ch == "/" and not in_class:
                    ok = True
                    break
                j += 1
            if ok:
                k = j + 1
                while k < n and text[k].isalpha():
                    k += 1
                emit("/", True)
                emit(text[i + 1:j], False)
                emit(text[j:k], True)
                i = k
                last_sig = "/"
                last_word = ""
                continue
        if c == "{":
            brace += 1
        elif c == "}":
            if template_depth and template_depth[-1] == brace:
                template_depth.pop()
                brace -= 1
                emit("}", True)
                i = read_template(i + 1)
                last_sig = "`"
                last_word = ""
                continue
            brace -= 1
        emit(c, True)
        if c.isalnum() or c in "_$":
            last_word = last_word + c if (last_sig.isalnum() or last_sig in "_$") and text[i - 1:i] == last_sig else c
            last_sig = c
        elif not c.isspace():
            last_sig = c
            last_word = ""
        elif c == "\n" and last_sig not in ")]}" and not (last_sig.isalnum() or last_sig in "_$\"'`"):
            pass
        i += 1
    return Lexed("".join(code), "".join(nocomment), strings, comments)


_LEX_CACHE: Dict[int, Tuple[str, Lexed]] = {}


def lexed(text: str) -> Lexed:
    """Cached ``lex``. The cache is keyed by object identity and checked by equality."""
    key = id(text)
    hit = _LEX_CACHE.get(key)
    if hit is not None and hit[0] is text:
        return hit[1]
    result = lex(text)
    if len(_LEX_CACHE) > 4000:
        _LEX_CACHE.clear()
    _LEX_CACHE[key] = (text, result)
    return result


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def match_close(code: str, open_idx: int) -> int:
    """Index of the bracket matching the one at ``open_idx`` in lexed code, or -1."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    opener = code[open_idx]
    closer = pairs.get(opener)
    if closer is None:
        return -1
    depth = 0
    for j in range(open_idx, len(code)):
        ch = code[j]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return j
    return -1


class Import(NamedTuple):
    spec: str
    names: Tuple[str, ...]
    default: Optional[str]
    namespace: Optional[str]
    line: int
    dynamic: bool


_IMPORT_RE = re.compile(
    r"\bimport\s+(?:type\s+)?(?:(?P<default>[A-Za-z_$][\w$]*)\s*,?\s*)?(?:\*\s+as\s+(?P<ns>[A-Za-z_$][\w$]*)\s*)?(?:\{(?P<names>[^}]*)\}\s*)?"
    r"(?:from\s*)?[\"'](?P<spec>[^\"']+)[\"']"
)
_REQUIRE_RE = re.compile(r"(?:(?:const|let|var)\s+(?:(?P<name>[A-Za-z_$][\w$]*)|\{(?P<names>[^}]*)\})\s*=\s*)?(?:await\s+)?(?P<kind>require|import)\(\s*[\"'](?P<spec>[^\"']+)[\"']\s*\)")
_EXPORT_FROM_RE = re.compile(r"\bexport\s+(?:\*|\{[^}]*\})\s*from\s*[\"'](?P<spec>[^\"']+)[\"']")


def _names(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return ()
    out = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        part = re.sub(r"^type\s+", "", part)
        out.append(re.split(r"\s+as\s+|\s*:\s*", part)[-1].strip())
    return tuple(out)


def find_imports(text: str) -> List[Import]:
    """ES imports, dynamic imports and require calls, with specifiers and local names."""
    src = lexed(text).nocomment
    out: List[Import] = []
    for m in _IMPORT_RE.finditer(src):
        out.append(Import(m.group("spec"), _names(m.group("names")), m.group("default"), m.group("ns"), line_of(src, m.start()), False))
    for m in _REQUIRE_RE.finditer(src):
        out.append(Import(m.group("spec"), _names(m.group("names")), m.group("name"), None, line_of(src, m.start()), m.group("kind") == "import"))
    for m in _EXPORT_FROM_RE.finditer(src):
        out.append(Import(m.group("spec"), (), None, None, line_of(src, m.start()), False))
    seen = set()
    uniq = []
    for imp in sorted(out, key=lambda x: (x.line, x.spec)):
        key = (imp.line, imp.spec, imp.default, imp.names)
        if key not in seen:
            seen.add(key)
            uniq.append(imp)
    return uniq


def import_specs(text: str) -> List[str]:
    return [i.spec for i in find_imports(text)]


def package_of(spec: str) -> Optional[str]:
    """npm package name for an import specifier, or None for relative, alias and built-in imports."""
    if not spec or spec.startswith((".", "/", "@/", "~/", "#", "node:", "bun:", "virtual:", "http:", "https:", "npm:", "jsr:", "$")):
        return None
    parts = spec.split("/")
    if spec.startswith("@"):
        return "/".join(parts[:2]) if len(parts) >= 2 else None
    return parts[0]


class Export(NamedTuple):
    name: str
    kind: str   # function | const | class | default | list
    line: int
    offset: int


_EXPORT_RE = re.compile(
    r"\bexport\s+(?:(?P<default>default)\s+)?(?:(?P<async>async)\s+)?(?:(?P<kind>function\*?|const|let|var|class)\s+(?P<name>[A-Za-z_$][\w$]*)?|\{(?P<list>[^}]*)\})?"
)


def find_exports(text: str) -> List[Export]:
    """Exported names, including Next.js route method exports and default exports."""
    code = lexed(text).code
    out: List[Export] = []
    for m in _EXPORT_RE.finditer(code):
        line = line_of(code, m.start())
        if m.group("list") is not None:
            for nm in _names(m.group("list")):
                out.append(Export(nm, "list", line, m.start()))
            continue
        kind = (m.group("kind") or "").rstrip("*")
        name = m.group("name")
        if m.group("default"):
            out.append(Export(name or "default", "default", line, m.start()))
        elif name:
            out.append(Export(name, "function" if kind == "function" else kind, line, m.start()))
    if re.search(r"\bmodule\.exports\s*=", code):
        m2 = re.search(r"\bmodule\.exports\s*=", code)
        out.append(Export("default", "default", line_of(code, m2.start()), m2.start()))
    return out


class Func(NamedTuple):
    name: str
    start_line: int
    end_line: int
    start: int       # offset of the declaration
    body_start: int  # offset of the opening brace (or expression start)
    end: int         # offset just past the body
    exported: bool
    is_async: bool


_FUNC_DECL_RE = re.compile(
    r"(?P<export>\bexport\s+(?:default\s+)?)?(?P<async>\basync\s+)?\bfunction\s*\*?\s*(?P<name>[A-Za-z_$][\w$]*)?\s*(?:<[^>(]*>)?\s*\("
)
_ARROW_DECL_RE = re.compile(
    r"(?P<export>\bexport\s+)?\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?::\s*[^=]+?)?=\s*(?:[A-Za-z_$][\w$.]*\(\s*)*(?P<async>async\s+)?(?:function\s*\*?\s*[\w$]*\s*)?(?:<[^>(]*>\s*)?(?P<paren>\(|[A-Za-z_$][\w$]*\s*=>)"
)
_METHOD_RE = re.compile(r"(?m)^[ \t]*(?:(?:public|private|protected|static|async|override)\s+)*(?P<name>[A-Za-z_$][\w$]*)\s*(?:<[^>(]*>)?\s*\((?P<args>[^)]*)\)\s*(?::\s*[^{;=]+)?\{")
_KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "with", "do", "else", "try", "new", "typeof", "await", "super"}
_TYPE_PREV = set(":|&<,(=")


def _body_open(code: str, after_params: int) -> int:
    """Find the opening brace of a function body, skipping TypeScript return-type braces."""
    j = after_params
    n = len(code)
    while j < n:
        ch = code[j]
        if ch == "{":
            k = j - 1
            while k >= 0 and code[k].isspace():
                k -= 1
            prev = code[k] if k >= 0 else ""
            if prev in _TYPE_PREV and not (prev == "=" and False) and code[k - 1:k + 1] != "=>":
                close = match_close(code, j)
                if close == -1:
                    return -1
                j = close + 1
                continue
            return j
        if ch in ";":
            return -1
        if ch == "=" and code[j:j + 2] == "=>":
            j += 2
            while j < n and code[j].isspace():
                j += 1
            return j if j < n else -1
        j += 1
    return -1


def find_functions(text: str) -> List[Func]:
    """Approximate function spans: declarations, arrow functions bound to names, and methods."""
    code = lexed(text).code
    out: List[Func] = []
    seen_starts = set()

    def add(name: str, start: int, paren_idx: int, exported: bool, is_async: bool) -> None:
        if code[paren_idx] == "(":
            close = match_close(code, paren_idx)
            if close == -1:
                return
            after = close + 1
        else:
            after = paren_idx
        body = _body_open(code, after)
        if body == -1:
            return
        if code[body] == "{":
            end = match_close(code, body)
            if end == -1:
                return
            end += 1
        else:
            end = body
            depth = 0
            while end < len(code):
                ch = code[end]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    if depth == 0:
                        break
                    depth -= 1
                elif ch in ";\n" and depth == 0 and ch == ";":
                    break
                elif ch == "\n" and depth == 0 and code[end + 1:end + 2] in ("\n", "") :
                    break
                end += 1
        if body in seen_starts:
            return
        seen_starts.add(body)
        out.append(Func(name, line_of(code, start), line_of(code, max(start, end - 1)), start, body, end, exported, is_async))

    for m in _FUNC_DECL_RE.finditer(code):
        add(m.group("name") or "default", m.start(), m.end() - 1, bool(m.group("export")), bool(m.group("async")))
    for m in _ARROW_DECL_RE.finditer(code):
        paren = m.start("paren")
        add(m.group("name"), m.start(), paren if code[paren] == "(" else m.end("paren") - 2, bool(m.group("export")), bool(m.group("async")))
    for m in _METHOD_RE.finditer(code):
        if m.group("name") in _KEYWORDS:
            continue
        brace = m.end() - 1
        if brace in seen_starts:
            continue
        end = match_close(code, brace)
        if end == -1:
            continue
        seen_starts.add(brace)
        out.append(Func(m.group("name"), line_of(code, m.start()), line_of(code, end), m.start(), brace, end + 1, False, "async" in m.group(0).split("(")[0]))
    out.sort(key=lambda f: f.start)
    return out


def enclosing_function(funcs: Sequence[Func], offset: int) -> Optional[Func]:
    best: Optional[Func] = None
    for f in funcs:
        if f.start <= offset < f.end and (best is None or f.start >= best.start):
            best = f
    return best


_DIRECTIVE_HEAD = r"\s*(?:(?:/\*[\s\S]*?\*/|//[^\n]*\n)\s*)*"


def has_directive(text: str, directive: str) -> bool:
    """True when the file starts with the directive ("use client" or "use server")."""
    return bool(re.match(_DIRECTIVE_HEAD + r"(?:[\"'][^\"'\n]*[\"'];?\s*)*?[\"']" + re.escape(directive) + r"[\"']", text))


def functions_with_directive(text: str, directive: str) -> List[Func]:
    """Functions whose body starts with the directive (inline server actions)."""
    out = []
    for f in find_functions(text):
        body = text[f.body_start:f.end]
        if re.match(r"\{\s*[\"']" + re.escape(directive) + r"[\"']", body):
            out.append(f)
    return out


class Call(NamedTuple):
    name: str
    line: int
    start: int
    end: int
    args: str   # argument text from the comment-free source, parentheses excluded


def find_calls(text: str, names: Sequence[str]) -> List[Call]:
    """Call sites of the given identifiers or dotted member chains, with their argument text.

    A name may end with ``.*`` to match any trailing member, for example ``stripe.*``.
    """
    lx = lexed(text)
    code, src = lx.code, lx.nocomment
    out: List[Call] = []
    for name in names:
        if name.endswith(".*"):
            pat = r"(?<![\w$.])" + re.escape(name[:-2]) + r"(?:\??\.[\w$]+)+\s*\("
        else:
            pat = r"(?<![\w$])" + re.escape(name).replace(r"\.", r"\s*\??\.\s*") + r"\s*(?:<[^>()]*>)?\s*\("
        for m in re.finditer(pat, code):
            open_idx = m.end() - 1
            close = match_close(code, open_idx)
            if close == -1:
                continue
            out.append(Call(re.sub(r"\s+", "", code[m.start():open_idx]), line_of(code, m.start()), m.start(), close + 1, src[open_idx + 1:close]))
    out.sort(key=lambda c: c.start)
    return out


def string_value(token: str) -> Optional[str]:
    """Value of a simple string literal token, or None if the token is not one."""
    t = token.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'`" and "${" not in t:
        return t[1:-1]
    return None


def split_args(args: str) -> List[str]:
    """Split an argument string on top-level commas."""
    out: List[str] = []
    depth = 0
    cur: List[str] = []
    quote = ""
    i = 0
    while i < len(args):
        ch = args[i]
        if quote:
            cur.append(ch)
            if ch == "\\":
                i += 1
                if i < len(args):
                    cur.append(args[i])
            elif ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        out.append(tail)
    return out


def statement_at(code: str, offset: int) -> Tuple[int, int]:
    """Rough bounds of the statement containing ``offset``: back to the previous ; { } and forward to the next ;."""
    start = offset
    depth = 0
    while start > 0:
        ch = code[start - 1]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth == 0:
                break
            depth -= 1
        elif ch == ";" and depth == 0:
            break
        start -= 1
    end = offset
    depth = 0
    n = len(code)
    while end < n:
        ch = code[end]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == ";" and depth == 0:
            break
        end += 1
    return start, end
