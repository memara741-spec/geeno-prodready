"""Small, dependency-free helpers for reading Laravel/PHP source.

This is not a PHP parser. It does three honest things: it blanks comments (and
optionally string contents) while keeping every offset, so regexes cannot match
inside comments; it finds class and method bodies by brace matching; and it
reads ``routes/*.php`` into a route inventory with the middleware each route
inherits from its enclosing groups. Anything it cannot read it skips, and the
scanners built on it say so rather than guess.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from . import walker

WRITE_VERBS = {"post", "put", "patch", "delete", "any"}
RESOURCE_ACTIONS = {
    "resource": [("get", "index", ""), ("get", "create", "/create"), ("post", "store", ""), ("get", "show", "/{id}"), ("get", "edit", "/{id}/edit"), ("put", "update", "/{id}"), ("delete", "destroy", "/{id}")],
    "apiResource": [("get", "index", ""), ("post", "store", ""), ("get", "show", "/{id}"), ("put", "update", "/{id}"), ("delete", "destroy", "/{id}")],
}


def mask(text: str) -> Tuple[str, str]:
    """Return (no_comments, no_comments_no_strings). Both keep the original length and newlines."""
    a: List[str] = []
    b: List[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/" or (c == "#" and nxt != "["):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank = " " * (j - i)
            a.append(blank)
            b.append(blank)
            i = j
        elif c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank = "".join("\n" if ch == "\n" else " " for ch in text[i:j])
            a.append(blank)
            b.append(blank)
            i = j
        elif c in ("'", '"'):
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            chunk = text[i:j]
            a.append(chunk)
            b.append(c + "".join("\n" if ch == "\n" else " " for ch in chunk[1:-1]) + (c if len(chunk) > 1 else ""))
            i = j
        else:
            a.append(c)
            b.append(c)
            i += 1
    return "".join(a), "".join(b)


def match_brace(code: str, open_idx: int) -> int:
    """Index of the brace that closes the one at open_idx in string-free code, or len(code)."""
    depth = 0
    for i in range(open_idx, len(code)):
        ch = code[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(offset, 0)) + 1


class PhpFile:
    """One PHP file with comment-masked views and cached structure."""

    def __init__(self, sf: walker.SourceFile, text: str) -> None:
        self.sf = sf
        self.rel = sf.rel
        self.raw = text
        self.code, self.bare = mask(text)
        self._methods: Optional[List[Dict[str, Any]]] = None

    def line(self, offset: int) -> int:
        return line_of(self.raw, offset)

    def line_text(self, line: int) -> str:
        lines = self.raw.splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""

    @property
    def class_name(self) -> str:
        m = re.search(r"\b(?:final\s+|abstract\s+)*(?:class|trait)\s+(\w+)", self.bare)
        return m.group(1) if m else ""

    @property
    def extends(self) -> str:
        m = re.search(r"\bclass\s+\w+\s+extends\s+([\\\w]+)", self.bare)
        return m.group(1).split("\\")[-1] if m else ""

    @property
    def traits(self) -> List[str]:
        out: List[str] = []
        m = re.search(r"\bclass\s+\w+[^{]*\{", self.bare)
        body = self.bare[m.end():] if m else self.bare
        for t in re.finditer(r"^\s*use\s+([\\\w, \n]+?)\s*[;{]", body, re.M):
            out += [x.strip().split("\\")[-1] for x in t.group(1).split(",") if x.strip()]
        return out

    def methods(self) -> List[Dict[str, Any]]:
        if self._methods is None:
            out: List[Dict[str, Any]] = []
            for m in re.finditer(r"\b(?:(public|protected|private)\s+)?(?:static\s+)?function\s+&?(\w+)\s*\(([^)]*)\)\s*(?::\s*\??[\w\\|?]+)?\s*\{", self.bare):
                open_idx = m.end() - 1
                end = match_brace(self.bare, open_idx)
                out.append({"name": m.group(2), "vis": m.group(1) or "public", "params": m.group(3), "start": m.start(), "body_start": open_idx, "end": end,
                            "body": self.code[open_idx:end + 1], "bare_body": self.bare[open_idx:end + 1], "line": self.line(m.start())})
            self._methods = out
        return self._methods

    def method_at(self, offset: int) -> Optional[Dict[str, Any]]:
        best = None
        for m in self.methods():
            if m["start"] <= offset <= m["end"] and (best is None or m["start"] > best["start"]):
                best = m
        return best

    def array_prop(self, name: str) -> Optional[List[str]]:
        """Items of ``$name = [ 'a', 'b' ];`` or None when the property is absent."""
        m = re.search(r"\$%s\s*=\s*\[(.*?)\]\s*;" % re.escape(name), self.code, re.S)
        if not m:
            return None
        return re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))


def php_files(project: walker.Project, under: Tuple[str, ...] = ()) -> List[PhpFile]:
    key = "phpfiles:" + ",".join(under)
    if key in project.cache:
        return project.cache[key]
    out: List[PhpFile] = []
    for sf in project.files:
        if sf.ext != ".php" or sf.ignored:
            continue
        if under and not any(sf.rel.startswith(u) or ("/" + u) in sf.rel for u in under):
            continue
        text = project.text(sf)
        if text:
            out.append(PhpFile(sf, text))
    project.cache[key] = out
    return out


def composer(project: walker.Project) -> Dict[str, Any]:
    """Merged ``require`` and ``require-dev`` of composer.json: {'require': {...}, 'dev': {...}}."""
    if "composer" in project.cache:
        return project.cache["composer"]
    import json
    out: Dict[str, Any] = {"require": {}, "dev": {}, "present": False}
    raw = project.read("composer.json")
    if raw:
        try:
            data = json.loads(raw)
            out = {"require": dict(data.get("require") or {}), "dev": dict(data.get("require-dev") or {}), "present": True}
        except ValueError:
            pass
    project.cache["composer"] = out
    return out


def is_laravel(project: walker.Project) -> bool:
    c = composer(project)
    return "laravel/framework" in c["require"] or "laravel/laravel" in c["require"] or (project.exists("artisan") and project.exists("composer.json"))


def laravel_major(project: walker.Project) -> Optional[int]:
    """Major version of laravel/framework from composer.lock when present, else the composer.json constraint."""
    import json
    lock = project.read("composer.lock")
    if lock:
        try:
            for p in json.loads(lock).get("packages", []):
                if p.get("name") == "laravel/framework":
                    m = re.match(r"v?(\d+)", p.get("version", ""))
                    if m:
                        return int(m.group(1))
        except ValueError:
            pass
    spec = composer(project)["require"].get("laravel/framework", "")
    nums = [int(x) for x in re.findall(r"(\d+)(?:\.[\d*x]+)*", spec)]
    return max(nums) if nums else None


def model_files(project: walker.Project) -> List[PhpFile]:
    pat = re.compile(r"\bclass\s+\w+\s+extends\s+(?:\\?[\w\\]*\\)?(\w*Model|Authenticatable|Pivot|User)\b")
    return [p for p in php_files(project) if p.rel.startswith("app/") and pat.search(p.bare)]


def model_class_names(project: walker.Project) -> Dict[str, PhpFile]:
    return {p.class_name: p for p in model_files(project) if p.class_name}


def table_of(p: PhpFile) -> str:
    m = re.search(r"\$table\s*=\s*['\"](\w+)['\"]", p.code)
    if m:
        return m.group(1)
    name = p.class_name
    snake = re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()
    if snake.endswith("y") and not snake.endswith(("ay", "ey", "oy", "uy")):
        return snake[:-1] + "ies"
    return snake + ("es" if snake.endswith(("s", "x", "ch", "sh")) else "s")


# -- routes ---------------------------------------------------------------

_ROUTE_RE = re.compile(r"Route::(get|post|put|patch|delete|any|match|resource|apiResource|view|redirect|livewire)\s*\(")
_GROUP_RE = re.compile(r"->group\s*\(\s*(?:static\s+)?(?:function|fn)\b[^{]*\{|Route::group\s*\(\s*\[[^\]]*\]\s*,\s*(?:static\s+)?function\b[^{]*\{")


def _names(chain: str) -> List[str]:
    out: List[str] = []
    for m in re.finditer(r"(?:->|::)(?:middleware|withoutMiddleware)\s*\(\s*(\[[^\]]*\]|'[^']*'|\"[^\"]*\")", chain, re.S):
        if m.group(0).lstrip("-:>").startswith("without"):
            continue
        out += re.findall(r"['\"]([\w:.,|\\\-*]+)['\"]", m.group(1))
    m = re.search(r"'middleware'\s*=>\s*(\[[^\]]*\]|'[^']*')", chain)
    if m:
        out += re.findall(r"['\"]([\w:.,|\\\-*]+)['\"]", m.group(1))
    return out


def _prefix(chain: str) -> str:
    m = re.search(r"(?:->|::)prefix\s*\(\s*['\"]([^'\"]*)['\"]", chain) or re.search(r"'prefix'\s*=>\s*['\"]([^'\"]*)['\"]", chain)
    return m.group(1).strip("/") if m else ""


def _statement_start(code: str, idx: int) -> int:
    j = idx
    while j > 0 and code[j - 1] not in ";{}":
        j -= 1
    return j


def route_inventory(project: walker.Project) -> List[Dict[str, Any]]:
    """Every route in routes/*.php with the middleware inherited from enclosing groups."""
    if "laravel_routes" in project.cache:
        return project.cache["laravel_routes"]
    items: List[Dict[str, Any]] = []
    for pf in php_files(project):
        if not re.search(r"(^|/)routes/[\w./-]+\.php$", pf.rel):
            continue
        base_prefix = "api" if pf.rel.endswith("routes/api.php") else ""
        groups: List[Tuple[int, int, List[str], str]] = []
        for g in _GROUP_RE.finditer(pf.bare):
            open_idx = g.end() - 1
            end = match_brace(pf.bare, open_idx)
            chain = pf.code[_statement_start(pf.bare, g.start()):g.end()]
            groups.append((open_idx, end, _names(chain), _prefix(chain)))
        for m in _ROUTE_RE.finditer(pf.bare):
            verb = m.group(1)
            stmt_end = pf.bare.find(";", m.end())
            stmt_end = len(pf.bare) if stmt_end < 0 else stmt_end
            # a closure body contains ';' — extend to the matching close paren of the call, then to its ';'
            depth, k = 0, m.end() - 1
            while k < len(pf.bare):
                if pf.bare[k] == "(":
                    depth += 1
                elif pf.bare[k] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            stmt_end = pf.bare.find(";", k)
            stmt_end = len(pf.bare) if stmt_end < 0 else stmt_end
            call = pf.code[m.start():k + 1]
            chain_tail = pf.code[k + 1:stmt_end]
            if verb == "match":
                vm = re.search(r"\[([^\]]*)\]", call)
                verb_list = [v.lower() for v in re.findall(r"['\"](\w+)['\"]", vm.group(1))] if vm else ["any"]
                uri_m = re.search(r"\]\s*,\s*['\"]([^'\"]*)['\"]", call)
            else:
                verb_list = [verb.lower()]
                uri_m = re.search(r"\(\s*['\"]([^'\"]*)['\"]", call)
            uri = uri_m.group(1) if uri_m else ""
            if verb in ("resource", "apiResource"):
                uri_m = re.search(r"\(\s*['\"]([^'\"]*)['\"]", call)
                uri = uri_m.group(1) if uri_m else ""
            inherited: List[str] = []
            prefix_parts: List[str] = [base_prefix] if base_prefix else []
            for (o, e, names, pre) in groups:
                if o < m.start() < e:
                    inherited += names
                    if pre:
                        prefix_parts.append(pre)
            own_chain = pf.code[_statement_start(pf.bare, m.start()):m.start()] + chain_tail
            mw = inherited + _names(own_chain)
            # the Route::middleware('x')->group(...) head is handled via groups; direct Route::middleware('x')->get() lands in own_chain
            controller, action = "", ""
            cm = re.search(r"\[\s*([\\\w]+)::class\s*,\s*['\"](\w+)['\"]\s*\]", call) or re.search(r"['\"]([\\\w]+)@(\w+)['\"]", call)
            if cm:
                controller, action = cm.group(1).split("\\")[-1], cm.group(2)
            else:
                cm = re.search(r",\s*([\\\w]+)::class\s*\)?\s*$", call.rstrip(") "))
                if cm:
                    controller, action = cm.group(1).split("\\")[-1], "__invoke"
            closure = bool(re.search(r"\b(function|fn)\b", call))
            ctrl_m = re.search(r"(?:->|::)controller\s*\(\s*([\\\w]+)::class", pf.code[_statement_start(pf.bare, m.start()):m.start()] + "")
            if not controller:
                for (o, e, names, pre) in groups:
                    if o < m.start() < e:
                        gh = pf.code[_statement_start(pf.bare, o):o]
                        gm = re.search(r"controller\s*\(\s*([\\\w]+)::class", gh)
                        if gm:
                            controller = gm.group(1).split("\\")[-1]
                            am = re.search(r",\s*['\"](\w+)['\"]\s*\)?\s*$", call.rstrip(") "))
                            action = am.group(1) if am else ""
            if ctrl_m and not controller:
                controller = ctrl_m.group(1).split("\\")[-1]
            only = None
            if verb in RESOURCE_ACTIONS:
                om = re.search(r"->only\(\s*\[([^\]]*)\]", chain_tail)
                em = re.search(r"->except\(\s*\[([^\]]*)\]", chain_tail)
                only = set(re.findall(r"['\"](\w+)['\"]", om.group(1))) if om else None
                except_ = set(re.findall(r"['\"](\w+)['\"]", em.group(1))) if em else set()
                controller = controller or (re.search(r",\s*([\\\w]+)::class", call).group(1).split("\\")[-1] if re.search(r",\s*([\\\w]+)::class", call) else "")
                for v, act, suffix in RESOURCE_ACTIONS[verb]:
                    if (only is not None and act not in only) or act in except_:
                        continue
                    items.append(_item(pf, m.start(), v, "/".join([p for p in prefix_parts + [uri.strip("/")] if p]) + suffix, mw, controller, act, False, call))
                continue
            for v in verb_list:
                items.append(_item(pf, m.start(), v, "/".join([p for p in prefix_parts + [uri.strip("/")] if p]), mw, controller, action, closure, call))
    project.cache["laravel_routes"] = items
    return items


def _item(pf: PhpFile, off: int, verb: str, uri: str, mw: List[str], controller: str, action: str, closure: bool, call: str) -> Dict[str, Any]:
    names = list(dict.fromkeys(mw))
    low = [n.lower() for n in names]
    return {
        "method": verb.upper(), "uri": "/" + uri.strip("/"), "middleware": names, "controller": controller, "action": action,
        "closure": closure, "file": pf.rel, "line": pf.line(off), "snippet": " ".join(call.split())[:160],
        "auth": any(n.startswith(("auth", "verified", "can:", "role:", "permission:", "role_or_permission:", "admin", "password.confirm")) or n in ("auth", "sanctum") for n in low),
        "throttle": any(n.startswith("throttle") or n.startswith("ratelimit") for n in low),
    }


def controller_file(project: walker.Project, name: str) -> Optional[PhpFile]:
    if not name:
        return None
    for p in php_files(project):
        if p.rel.endswith("/" + name + ".php") and "Controllers" in p.rel or (p.rel.endswith("/" + name + ".php") and "Livewire" in p.rel):
            return p
    return None
