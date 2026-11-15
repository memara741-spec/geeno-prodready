"""Token-level data flow for PHP: which variables carry request input, and which calls receive them.

A step up from line regexes, and still not a full PHP parser (no PHP binary is needed). Each method body is
split into statements and tokenised; assignments, ``foreach`` loops, array writes, string building and calls
between methods of the same class are followed to a fixed point. Sanitisers (casts to int, ``escapeshellarg``,
``basename`` and similar) clear taint.

What it cannot do: follow calls across classes, container-resolved services, dynamic calls (``$f($x)``),
``compact``/``extract`` or references. The scanners treat its answer as "likely", never "confirmed", unless
the source is read directly in the call.
"""
from __future__ import annotations

import re
from typing import Dict, Iterator, List, Optional, Set, Tuple

from . import phpscan

SOURCE_RE = re.compile(r"\$request\s*->|\brequest\s*\(|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\bInput::|\bRequest::(?:input|get|query|all|post)\s*\(|\$this->(?:request|validated\s*\(\s*\))|\binput\s*\(|\$request\b(?!\s*->\s*user\s*\()")
SANITISER_RE = re.compile(r"\(\s*(?:int|integer|float|double|bool|boolean)\s*\)|\b(?:intval|floatval|boolval|abs|escapeshellarg|escapeshellcmd|basename|htmlspecialchars|e|filter_var|is_numeric|ctype_digit|Str::slug|Str::uuid|count|strlen|json_encode|md5|sha1|crc32|Hash::make|bcrypt)\s*\(")
VAR_RE = re.compile(r"\$[A-Za-z_]\w*")
ASSIGN_RE = re.compile(r"^\s*(\$[A-Za-z_]\w*)\s*(?:\[[^\]]*\]\s*)*(?:\.|\+|-|\?\?)?=(?!=)\s*(.*)$", re.S)
FOREACH_RE = re.compile(r"^\s*foreach\s*\((.*?)\s+as\s+(?:(\$\w+)\s*=>\s*)?(\$\w+)\s*\)", re.S)


def statements(body: str) -> Iterator[Tuple[int, str]]:
    """(offset, text) for each statement in a method body; blocks are flattened."""
    start, depth_paren = 0, 0
    for i, ch in enumerate(body):
        if ch == "(":
            depth_paren += 1
        elif ch == ")":
            depth_paren -= 1
        elif ch in ";{}" and depth_paren <= 0:
            text = body[start:i]
            if text.strip():
                yield start, text
            start = i + 1
        elif ch == "{" and depth_paren > 0:
            pass
    tail = body[start:]
    if tail.strip():
        yield start, tail


def expr_is_tainted(expr: str, tainted: Set[str]) -> bool:
    lead = SANITISER_RE.match(expr.strip())
    if lead and lead.end() > 0:
        return False  # the whole expression is wrapped by a sanitiser or cast
    if SOURCE_RE.search(expr):
        return True
    return any(v in tainted for v in VAR_RE.findall(expr))


def tainted_vars(body: str, seed: Optional[Set[str]] = None) -> Set[str]:
    """Variables in a method body that hold request-derived data, following assignments to a fixed point."""
    tainted: Set[str] = set(seed or ())
    stmts = list(statements(body))
    for _ in range(6):
        before = len(tainted)
        for _, text in stmts:
            fe = FOREACH_RE.match(text)
            if fe and expr_is_tainted(fe.group(1), tainted):
                tainted.update(v for v in (fe.group(2), fe.group(3)) if v)
                continue
            m = ASSIGN_RE.match(text)
            if m and expr_is_tainted(m.group(2), tainted):
                tainted.add(m.group(1))
        if len(tainted) == before:
            break
    return tainted


def built_vars(body: str) -> Set[str]:
    """Variables assigned a string that mixes literals with other variables (a query being assembled)."""
    out: Set[str] = set()
    for _, text in statements(body):
        m = ASSIGN_RE.match(text)
        if not m:
            continue
        rhs = m.group(2)
        if re.search(r'"[^"]*\$[\w{]|["\']\s*\.\s*\$|\$\w+(?:->\w+|\[[^\]]*\])*\s*\.\s*["\']|\bsprintf\s*\(', rhs) or (re.search(r"\.=", text) and VAR_RE.search(rhs)):
            out.add(m.group(1))
    return out


def reaches(args: str, tainted: Set[str]) -> bool:
    return expr_is_tainted(args, tainted)


def class_taint(pf: phpscan.PhpFile) -> Dict[str, Set[str]]:
    """Per method: tainted variables, including parameters that other methods of the class pass tainted values to."""
    methods = {m["name"]: m for m in pf.methods()}
    seeds: Dict[str, Set[str]] = {n: set() for n in methods}
    result: Dict[str, Set[str]] = {}
    for _ in range(4):
        changed = False
        for name, m in methods.items():
            tv = tainted_vars(m["body"], seeds[name])
            result[name] = tv
            for call in re.finditer(r"\$this->(\w+)\s*\(", m["body"]):
                callee = methods.get(call.group(1))
                if not callee:
                    continue
                args = _args(m["body"], call.end() - 1)
                params = re.findall(r"\$\w+", callee["params"])
                parts = _split(args)
                for i, part in enumerate(parts):
                    if i < len(params) and expr_is_tainted(part, tv) and params[i] not in seeds[call.group(1)]:
                        seeds[call.group(1)].add(params[i])
                        changed = True
        if not changed:
            break
    return result


def _args(text: str, open_idx: int) -> str:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
    return text[open_idx + 1:]


def _split(args: str) -> List[str]:
    parts, depth, cur = [], 0, []
    for ch in args:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


def calls(body: str, names: str) -> Iterator[Tuple[str, str, int]]:
    """(name, args_text, offset) for calls matching the regex ``names``, e.g. ``shell_exec|exec``."""
    for m in re.finditer(r"(?:\\)?\b(%s)\s*\(" % names, body):
        yield m.group(1), _args(body, m.end() - 1), m.start()
