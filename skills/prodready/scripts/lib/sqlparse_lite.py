"""A small PostgreSQL statement splitter and recogniser for migration files.

It understands just enough SQL to answer the questions the database checks
ask: which tables exist in which schema, whether row level security is on,
which policies exist and what their conditions are, which functions are
``security definer``, which views and buckets exist, and what was granted.

It is not a SQL parser. Statements it does not recognise are ignored, never an
error. Dynamic SQL inside ``do $$ ... $$`` blocks is not interpreted.
"""
from __future__ import annotations

import re
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple


class Statement(NamedTuple):
    text: str   # original text of the statement, comments removed
    line: int   # 1-based line of the first non-blank character
    end_line: int


def split(sql: str) -> List[Statement]:
    """Split on semicolons, respecting strings, quoted identifiers, dollar quotes and comments."""
    out: List[Statement] = []
    n = len(sql)
    i = 0
    buf: List[str] = []
    start_line = 1
    line = 1
    started = False

    def flush(end_line: int) -> None:
        nonlocal buf, started
        text = "".join(buf).strip()
        if text:
            out.append(Statement(text, start_line, end_line))
        buf = []
        started = False

    while i < n:
        c = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        if c == "-" and nxt == "-":
            j = sql.find("\n", i)
            j = n if j == -1 else j
            i = j
            continue
        if c == "/" and nxt == "*":
            j = sql.find("*/", i + 2)
            j = n if j == -1 else j + 2
            line += sql.count("\n", i, j)
            buf.append(" ")
            i = j
            continue
        if not started and not c.isspace():
            started = True
            start_line = line
        if c == "'" or c == '"':
            j = i + 1
            while j < n:
                if sql[j] == c:
                    if j + 1 < n and sql[j + 1] == c:
                        j += 2
                        continue
                    break
                j += 1
            j = min(j + 1, n)
            buf.append(sql[i:j])
            line += sql.count("\n", i, j)
            i = j
            continue
        if c == "$":
            m = re.match(r"\$[A-Za-z_]*\$", sql[i:])
            if m:
                tag = m.group(0)
                j = sql.find(tag, i + len(tag))
                j = n if j == -1 else j + len(tag)
                buf.append(sql[i:j])
                line += sql.count("\n", i, j)
                i = j
                continue
        if c == ";":
            flush(line)
            i += 1
            continue
        if c == "\n":
            line += 1
        buf.append(c)
        i += 1
    flush(line)
    return out


_IDENT = r"(?:\"[^\"]+\"|[A-Za-z_][\w$]*)"
_QNAME = r"(?:(?P<schema>" + _IDENT + r")\s*\.\s*)?(?P<name>" + _IDENT + r")"


def unquote(ident: Optional[str]) -> str:
    if not ident:
        return ""
    ident = ident.strip()
    if ident.startswith('"') and ident.endswith('"'):
        return ident[1:-1]
    return ident.lower()


def qualify(schema: Optional[str], name: str, default_schema: str = "public") -> str:
    return "%s.%s" % (unquote(schema) or default_schema, unquote(name))


def _balanced(text: str, open_idx: int) -> int:
    """Index of the parenthesis closing the one at open_idx, skipping strings. -1 if unbalanced."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "'":
            i += 1
            while i < n:
                if text[i] == "'":
                    if i + 1 < n and text[i + 1] == "'":
                        i += 2
                        continue
                    break
                i += 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _clause(text: str, keyword_re: str) -> Optional[str]:
    """Expression inside the parentheses following a keyword such as USING or WITH CHECK."""
    m = re.search(keyword_re + r"\s*\(", text, re.I)
    if not m:
        return None
    open_idx = m.end() - 1
    close = _balanced(text, open_idx)
    if close == -1:
        return text[open_idx + 1:].strip()
    return text[open_idx + 1:close].strip()


def _split_top(text: str) -> List[str]:
    out, depth, cur = [], 0, []
    in_str = False
    for ch in text:
        if in_str:
            cur.append(ch)
            if ch == "'":
                in_str = False
            continue
        if ch == "'":
            in_str = True
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


class Column(NamedTuple):
    name: str
    type: str
    references: Optional[str]
    definition: str


class Policy:
    def __init__(self, name: str, table: str, file: str, line: int, end_line: int, text: str) -> None:
        self.name = name
        self.table = table
        self.command = "all"
        self.roles: List[str] = []
        self.using: Optional[str] = None
        self.check: Optional[str] = None
        self.permissive = True
        self.file = file
        self.line = line
        self.end_line = end_line
        self.text = text

    @property
    def applies_to_public(self) -> bool:
        return not self.roles or "public" in self.roles

    def applies_to(self, role: str) -> bool:
        return self.applies_to_public or role in self.roles

    def covers(self, command: str) -> bool:
        return self.command == "all" or self.command == command


class Table:
    def __init__(self, qname: str, file: str, line: int) -> None:
        self.qname = qname
        self.schema, self.name = qname.split(".", 1)
        self.columns: Dict[str, Column] = {}
        self.rls = False
        self.rls_forced = False
        self.rls_file: Optional[str] = None
        self.rls_line: Optional[int] = None
        self.file = file
        self.line = line
        self.text = ""


class Function(NamedTuple):
    qname: str
    args: str
    security_definer: bool
    search_path: Optional[str]
    body: str
    file: str
    line: int
    text: str


class View(NamedTuple):
    qname: str
    materialized: bool
    security_invoker: bool
    body: str
    file: str
    line: int
    text: str


class Grant(NamedTuple):
    revoke: bool
    privileges: str
    object_kind: str   # table | function | schema | sequence | all-tables | all-functions | default
    target: str
    roles: Tuple[str, ...]
    file: str
    line: int
    text: str


class Index(NamedTuple):
    table: str
    columns: Tuple[str, ...]
    file: str
    line: int


class Bucket(NamedTuple):
    name: str
    public: bool
    file: str
    line: int
    text: str
    limits: bool


class Schema:
    """The folded result of applying every migration in order."""

    def __init__(self) -> None:
        self.tables: Dict[str, Table] = {}
        self.policies: List[Policy] = []
        self.functions: Dict[str, Function] = {}
        self.views: Dict[str, View] = {}
        self.grants: List[Grant] = []
        self.indexes: List[Index] = []
        self.buckets: Dict[str, Bucket] = {}
        self.realtime_tables: List[Tuple[str, str, int]] = []
        self.statements = 0

    def policies_for(self, qname: str) -> List[Policy]:
        return [p for p in self.policies if p.table == qname]

    def indexed_columns(self, qname: str) -> set:
        cols = set()
        for ix in self.indexes:
            if ix.table == qname and ix.columns:
                cols.add(ix.columns[0])
        table = self.tables.get(qname)
        if table:
            for col in table.columns.values():
                if re.search(r"(?i)\bprimary\s+key\b|\bunique\b", col.definition):
                    cols.add(col.name)
            m = re.search(r"(?i)primary\s+key\s*\(\s*([^)]+)\)", table.text)
            if m:
                cols.add(unquote(m.group(1).split(",")[0]))
        return cols


_CREATE_TABLE = re.compile(r"(?is)^create\s+(?:(?:global\s+|local\s+)?(?:temp|temporary|unlogged)\s+)?table\s+(?:if\s+not\s+exists\s+)?" + _QNAME + r"\s*\(")
_DROP_TABLE = re.compile(r"(?is)^drop\s+table\s+(?:if\s+exists\s+)?" + _QNAME)
_ALTER_RLS = re.compile(r"(?is)^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + _QNAME + r"\s+(?P<action>enable|disable|force|no\s+force)\s+row\s+level\s+security")
_ALTER_ADD_COL = re.compile(r"(?is)^alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?" + _QNAME + r"\s+add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(?P<col>" + _IDENT + r")\s+(?P<def>[^,;]+)")
_CREATE_POLICY = re.compile(r"(?is)^create\s+policy\s+(?P<pname>" + _IDENT + r")\s+on\s+" + _QNAME)
_ALTER_POLICY = re.compile(r"(?is)^alter\s+policy\s+(?P<pname>" + _IDENT + r")\s+on\s+" + _QNAME)
_DROP_POLICY = re.compile(r"(?is)^drop\s+policy\s+(?:if\s+exists\s+)?(?P<pname>" + _IDENT + r")\s+on\s+" + _QNAME)
_CREATE_FUNCTION = re.compile(r"(?is)^create\s+(?:or\s+replace\s+)?function\s+" + _QNAME + r"\s*\(")
_CREATE_VIEW = re.compile(r"(?is)^create\s+(?:or\s+replace\s+)?(?:temp(?:orary)?\s+)?(?:recursive\s+)?(?P<mat>materialized\s+)?view\s+(?:if\s+not\s+exists\s+)?" + _QNAME)
_CREATE_INDEX = re.compile(r"(?is)^create\s+(?:unique\s+)?index\s+(?:concurrently\s+)?(?:if\s+not\s+exists\s+)?(?:" + _IDENT + r"\s+)?on\s+(?:only\s+)?" + _QNAME + r"\s*(?:using\s+\w+\s*)?\((?P<cols>[^)]*)\)")
_GRANT = re.compile(r"(?is)^(?P<verb>grant|revoke)\s+(?P<privs>.+?)\s+on\s+(?P<obj>.+?)\s+(?:to|from)\s+(?P<roles>.+?)(?:\s+with\s+grant\s+option|\s+cascade|\s+restrict)?$")
_DEFAULT_PRIVS = re.compile(r"(?is)^alter\s+default\s+privileges\s+(?:for\s+role\s+\S+\s+)?(?:in\s+schema\s+(?P<schema>\S+)\s+)?grant\s+(?P<privs>.+?)\s+on\s+(?P<obj>tables|functions|sequences|routines)\s+to\s+(?P<roles>.+)$")
_PUBLICATION = re.compile(r"(?is)^alter\s+publication\s+(?P<pub>" + _IDENT + r")\s+add\s+table\s+(?P<tables>.+)$")
_BUCKET_INSERT = re.compile(r"(?is)^insert\s+into\s+storage\.buckets\s*\((?P<cols>[^)]*)\)\s*values\s*(?P<values>.+)$")
_BUCKET_CALL = re.compile(r"(?is)storage\.create_?bucket\s*\(\s*'(?P<name>[^']+)'(?P<rest>[^;]*)")
_BUCKET_UPDATE = re.compile(r"(?is)^update\s+storage\.buckets\s+set\s+(?P<set>.+?)\s+where\s+(?P<where>.+)$")


def _parse_columns(body: str) -> Dict[str, Column]:
    cols: Dict[str, Column] = {}
    for part in _split_top(body):
        if re.match(r"(?i)\s*(constraint|primary\s+key|foreign\s+key|unique|check|exclude|like)\b", part):
            continue
        m = re.match(r"\s*(" + _IDENT + r")\s+(.*)$", part, re.S)
        if not m:
            continue
        name = unquote(m.group(1))
        rest = m.group(2).strip()
        tm = re.match(r"(?i)((?:double\s+precision|character\s+varying|timestamp(?:\s*\(\d+\))?\s+with(?:out)?\s+time\s+zone|time\s+with(?:out)?\s+time\s+zone|[A-Za-z_][\w.]*)(?:\s*\([^)]*\))?(?:\[\])?)", rest)
        ctype = re.sub(r"\s+", " ", tm.group(1).lower()) if tm else ""
        rm = re.search(r"(?i)\breferences\s+(" + _IDENT + r"(?:\s*\.\s*" + _IDENT + r")?)", rest)
        ref = re.sub(r"\s+", "", rm.group(1)).replace('"', "").lower() if rm else None
        cols[name] = Column(name, ctype, ref, re.sub(r"\s+", " ", rest))
    return cols


def _roles(raw: str) -> Tuple[str, ...]:
    return tuple(unquote(r) for r in re.split(r"\s*,\s*", raw.strip()) if r.strip())


def _apply_policy_clauses(pol: Policy, text: str, creating: bool) -> None:
    head = re.split(r"(?i)\busing\s*\(|\bwith\s+check\s*\(", text, maxsplit=1)[0]
    if creating:
        m = re.search(r"(?i)\bas\s+(permissive|restrictive)\b", head)
        if m:
            pol.permissive = m.group(1).lower() == "permissive"
        m = re.search(r"(?i)\bfor\s+(all|select|insert|update|delete)\b", head)
        if m:
            pol.command = m.group(1).lower()
    m = re.search(r"(?i)\bto\s+(.+?)\s*$", head.strip())
    if m:
        roles = _roles(m.group(1))
        if roles:
            pol.roles = list(roles)
    using = _clause(text, r"\busing")
    check = _clause(text, r"\bwith\s+check")
    if using is not None:
        pol.using = using
    if check is not None:
        pol.check = check


def apply_statement(schema: Schema, stmt: Statement, file: str) -> None:
    text = stmt.text
    flat = re.sub(r"\s+", " ", text).strip()
    schema.statements += 1

    m = _CREATE_TABLE.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        if qname in schema.tables and re.search(r"(?i)if\s+not\s+exists", text[: m.end()]):
            return
        open_idx = m.end() - 1
        close = _balanced(text, open_idx)
        body = text[open_idx + 1: close if close != -1 else len(text)]
        table = Table(qname, file, stmt.line)
        table.columns = _parse_columns(body)
        table.text = flat
        schema.tables[qname] = table
        return
    m = _DROP_TABLE.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        schema.tables.pop(qname, None)
        schema.policies = [p for p in schema.policies if p.table != qname]
        return
    m = _ALTER_RLS.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        table = schema.tables.get(qname)
        if table is None:
            table = Table(qname, file, stmt.line)
            table.text = "(table defined outside the scanned migrations)"
            schema.tables[qname] = table
        action = re.sub(r"\s+", " ", m.group("action").lower())
        if action == "enable":
            table.rls = True
        elif action == "disable":
            table.rls = False
        elif action == "force":
            table.rls_forced = True
        else:
            table.rls_forced = False
        table.rls_file, table.rls_line = file, stmt.line
        return
    m = _ALTER_ADD_COL.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        table = schema.tables.get(qname)
        if table is not None:
            cols = _parse_columns(unquote(m.group("col")) + " " + m.group("def"))
            table.columns.update(cols)
        return
    m = _CREATE_POLICY.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        pol = Policy(unquote(m.group("pname")), qname, file, stmt.line, stmt.end_line, flat)
        _apply_policy_clauses(pol, text[m.end():], True)
        schema.policies = [p for p in schema.policies if not (p.table == qname and p.name == pol.name)]
        schema.policies.append(pol)
        return
    m = _ALTER_POLICY.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        name = unquote(m.group("pname"))
        for pol in schema.policies:
            if pol.table == qname and pol.name == name:
                rest = text[m.end():]
                rm = re.search(r"(?i)\brename\s+to\s+(" + _IDENT + ")", rest)
                if rm:
                    pol.name = unquote(rm.group(1))
                else:
                    tm = re.search(r"(?is)^\s*to\s+(.+?)(?=\s+using\s*\(|\s+with\s+check\s*\(|$)", rest)
                    if tm:
                        pol.roles = list(_roles(tm.group(1)))
                    using = _clause(rest, r"\busing")
                    check = _clause(rest, r"\bwith\s+check")
                    if using is not None:
                        pol.using = using
                    if check is not None:
                        pol.check = check
                pol.file, pol.line, pol.end_line, pol.text = file, stmt.line, stmt.end_line, flat
        return
    m = _DROP_POLICY.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        name = unquote(m.group("pname"))
        schema.policies = [p for p in schema.policies if not (p.table == qname and p.name == name)]
        return
    m = _CREATE_FUNCTION.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        open_idx = m.end() - 1
        close = _balanced(text, open_idx)
        args = text[open_idx + 1: close] if close != -1 else ""
        after = text[close + 1:] if close != -1 else ""
        body_m = re.search(r"(\$[A-Za-z_]*\$)([\s\S]*?)\1", after)
        body = body_m.group(2) if body_m else ""
        header = after.replace(body_m.group(0), " ") if body_m else after
        sp = re.search(r"(?i)\bset\s+search_path\s*(?:=|to)\s*([^\n;]+?)(?=\s+(?:as|language|security|stable|volatile|immutable|returns|set)\b|\s*$)", header)
        schema.functions[qname] = Function(
            qname, re.sub(r"\s+", " ", args), bool(re.search(r"(?i)\bsecurity\s+definer\b", header)),
            sp.group(1).strip() if sp else None, body, file, stmt.line, flat,
        )
        return
    m = _CREATE_VIEW.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        rest = text[m.end():]
        opts = re.match(r"(?is)\s*(?:\([^)]*\)\s*)?with\s*\(([^)]*)\)", rest)
        invoker = bool(opts and re.search(r"(?i)security_invoker\s*=\s*(true|on|1)|security_invoker\s*(?:,|$)", opts.group(1)))
        body_m = re.search(r"(?is)\bas\b(.*)$", rest)
        schema.views[qname] = View(qname, bool(m.group("mat")), invoker, body_m.group(1) if body_m else "", file, stmt.line, flat)
        return
    m = re.match(r"(?is)^alter\s+view\s+(?:if\s+exists\s+)?" + _QNAME + r"\s+set\s*\(([^)]*)\)", text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        view = schema.views.get(qname)
        if view and re.search(r"(?i)security_invoker\s*=\s*(true|on|1)", m.group(3)):
            schema.views[qname] = view._replace(security_invoker=True)
        return
    m = _CREATE_INDEX.match(text)
    if m:
        qname = qualify(m.group("schema"), m.group("name"))
        cols = tuple(unquote(re.sub(r"(?i)\s+(asc|desc|nulls\s+\w+)\b.*$", "", c.strip())) for c in m.group("cols").split(",") if c.strip())
        schema.indexes.append(Index(qname, cols, file, stmt.line))
        return
    m = _DEFAULT_PRIVS.match(flat)
    if m:
        schema.grants.append(Grant(False, m.group("privs").lower(), "default", "%s:%s" % (unquote(m.group("schema")) or "*", m.group("obj").lower()), _roles(m.group("roles")), file, stmt.line, flat))
        return
    m = _GRANT.match(flat)
    if m:
        obj = m.group("obj").strip()
        low = obj.lower()
        if low.startswith("all tables in schema"):
            kind, target = "all-tables", low.split("schema", 1)[1].strip()
        elif low.startswith("all functions in schema") or low.startswith("all routines in schema"):
            kind, target = "all-functions", low.split("schema", 1)[1].strip()
        elif low.startswith("all sequences in schema"):
            kind, target = "all-sequences", low.split("schema", 1)[1].strip()
        elif low.startswith("function") or low.startswith("routine") or low.startswith("procedure"):
            fn = re.sub(r"(?i)^(function|routine|procedure)\s+", "", obj)
            fn = fn.split("(")[0].strip()
            parts = fn.split(".")
            kind, target = "function", qualify(parts[0] if len(parts) > 1 else None, parts[-1])
        elif low.startswith("schema"):
            kind, target = "schema", low.split("schema", 1)[1].strip()
        elif low.startswith("sequence"):
            kind, target = "sequence", low
        else:
            tbl = re.sub(r"(?i)^table\s+", "", obj).split(",")[0].strip()
            parts = tbl.split(".")
            kind, target = "table", qualify(parts[0] if len(parts) > 1 else None, parts[-1])
        schema.grants.append(Grant(m.group("verb").lower() == "revoke", m.group("privs").lower(), kind, target, _roles(m.group("roles")), file, stmt.line, flat))
        return
    m = _PUBLICATION.match(flat)
    if m and unquote(m.group("pub")) == "supabase_realtime":
        for t in m.group("tables").split(","):
            parts = t.strip().split(".")
            if parts and parts[-1]:
                schema.realtime_tables.append((qualify(parts[0] if len(parts) > 1 else None, parts[-1]), file, stmt.line))
        return
    m = _BUCKET_INSERT.match(text)
    if m:
        cols = [unquote(c) for c in m.group("cols").split(",")]
        for row in re.finditer(r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)", m.group("values")):
            vals = _split_top(row.group(1))
            rec = dict(zip(cols, vals))
            name = (rec.get("id") or rec.get("name") or "").strip().strip("'")
            if name:
                public = (rec.get("public") or "false").strip().lower() in ("true", "'true'", "t", "1")
                limits = "file_size_limit" in rec or "allowed_mime_types" in rec
                schema.buckets[name] = Bucket(name, public, file, stmt.line, flat, limits)
        return
    m = _BUCKET_CALL.search(text)
    if m:
        rest = m.group("rest")
        public = bool(re.search(r"(?i)public\s*(?:=>|:=|:)\s*true", rest))
        schema.buckets[m.group("name")] = Bucket(m.group("name"), public, file, stmt.line, flat, bool(re.search(r"(?i)file_size_limit|allowed_mime_types", rest)))
        return
    m = _BUCKET_UPDATE.match(flat)
    if m:
        nm = re.search(r"(?i)\b(?:id|name)\s*=\s*'([^']+)'", m.group("where"))
        pub = re.search(r"(?i)\bpublic\s*=\s*(true|false)", m.group("set"))
        if nm and pub and nm.group(1) in schema.buckets:
            schema.buckets[nm.group(1)] = schema.buckets[nm.group(1)]._replace(public=pub.group(1).lower() == "true", file=file, line=stmt.line, text=flat)
        return


def migration_sort_key(path: str) -> Tuple[int, str, str]:
    """Order files by their numeric or timestamp prefix, then by name. Seeds and schema dumps go last."""
    name = path.rsplit("/", 1)[-1]
    m = re.match(r"(\d+)", name)
    late = 1 if re.search(r"(^|/)seed", path) else 0
    return (late, m.group(1).zfill(20) if m else "9" * 20, path)


def apply(files: Sequence[Tuple[str, str]]) -> Schema:
    """Fold (path, sql text) pairs, in migration order, into a final schema state."""
    schema = Schema()
    for path, text in sorted(files, key=lambda f: migration_sort_key(f[0])):
        for stmt in split(text):
            try:
                apply_statement(schema, stmt, path)
            except Exception:  # a malformed statement must never stop the scan
                continue
    return schema


def normalise_expr(expr: Optional[str]) -> str:
    """Lower-case, single-spaced expression with redundant outer parentheses removed."""
    if expr is None:
        return ""
    e = re.sub(r"\s+", " ", expr.strip().lower())
    while e.startswith("(") and _balanced(e, 0) == len(e) - 1:
        e = e[1:-1].strip()
    return e
