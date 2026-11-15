"""Central registry of patterns and name lists used by the scanners.

Every secret pattern carries a positive and a negative example; the unit tests
run them all. Examples are assembled by concatenation so that this file never
contains a complete key-shaped literal (which would trip repository secret
scanners on the tool itself).

Key formats were last checked on 2026-11-13. Formats confirmed against vendor
documentation that day: Supabase (sb_publishable_/sb_secret_ and legacy JWT
keys), Stripe (sk_/rk_/pk_/whsec_). The remaining formats come from published
vendor conventions and are marked "unverified" in
references/owner-actions/rotate-keys.md until a maintainer re-confirms them.

What this module deliberately does not do: it never decides severity from
entropy alone, and it never validates a key against a provider.
"""
from __future__ import annotations

import base64
import dataclasses
import json
import math
import re
from typing import Dict, List, Optional, Pattern, Tuple


def _j(*parts: str) -> str:
    return "".join(parts)


@dataclasses.dataclass(frozen=True)
class SecretPattern:
    id: str
    provider: str
    kind: str  # secret | publishable | webhook-secret | token | url | private-key | generic
    public: bool
    regex: Pattern[str]
    description: str
    positive: Tuple[str, ...]
    negative: Tuple[str, ...]
    severity: str = "critical"
    group: int = 0
    ai: bool = False
    generic: bool = False
    min_entropy: float = 0.0


_FILL = "Fx9aQz7k"

SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        "private-key", "pem", "private-key", False,
        re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----(?:[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----)?"),
        "PEM private key block",
        (_j("-----BEGIN ", "PRIVATE KEY-----\nMIIfake\n-----END ", "PRIVATE KEY-----"),),
        ("-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----"),
    ),
    SecretPattern(
        "stripe-secret", "stripe", "secret", False,
        re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{20,}"),
        "Stripe secret key (Clerk secret keys share this prefix)",
        (_j("sk_", "live_", _FILL * 4), _j("sk_", "test_", _FILL * 4)),
        ("sk_live_", "pk_live_abcdefghijklmnopqrstuvwx", "task_live_update"),
    ),
    SecretPattern(
        "stripe-restricted", "stripe", "secret", False,
        re.compile(r"\brk_(?:live|test)_[0-9a-zA-Z]{20,}"),
        "Stripe restricted key",
        (_j("rk_", "live_", _FILL * 4),),
        ("rk_live_short",),
    ),
    SecretPattern(
        "stripe-webhook", "stripe", "webhook-secret", False,
        re.compile(r"\bwhsec_[0-9a-zA-Z+/=]{24,}"),
        "Stripe webhook signing secret",
        (_j("wh", "sec_", _FILL * 4),),
        ("whsec_...", "whsec_xxx"),
    ),
    SecretPattern(
        "stripe-publishable", "stripe", "publishable", True,
        re.compile(r"\bpk_(?:live|test)_[0-9a-zA-Z$._-]{20,}"),
        "Stripe or Clerk publishable key (public by design)",
        (_j("pk_", "live_", _FILL * 4),),
        ("pk_live_short",),
        severity="info",
    ),
    SecretPattern(
        "anthropic", "anthropic", "secret", False,
        re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}"),
        "Anthropic API key",
        (_j("sk-", "ant-", "api03-", _FILL * 5),),
        ("sk-ant-", "sk-ant-api03-short"),
        ai=True,
    ),
    SecretPattern(
        "openrouter", "openrouter", "secret", False,
        re.compile(r"\bsk-or-v1-[a-f0-9]{32,}"),
        "OpenRouter API key",
        (_j("sk-", "or-v1-", "0a1b2c3d" * 8),),
        ("sk-or-v1-zzzz",),
        ai=True,
    ),
    SecretPattern(
        "openai", "openai", "secret", False,
        re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}"),
        "OpenAI project, service account or admin key",
        (_j("sk-", "proj-", _FILL * 5),),
        ("sk-proj-", "sk-project"),
        ai=True,
    ),
    SecretPattern(
        "openai-legacy", "openai", "secret", False,
        re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}"),
        "OpenAI legacy user key",
        (_j("sk-", "A1b2C3d4E5" * 2, "T3Blbk", "FJ", "A1b2C3d4E5" * 2),),
        (_j("sk-short", "T3Blbk", "FJ", "short"),),
        ai=True,
    ),
    SecretPattern(
        "generic-sk", "ai-provider", "secret", False,
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{32,}(?![A-Za-z0-9_-])"),
        "Generic sk- prefixed API key (several AI providers use this shape)",
        (_j("sk-", "a1B2c3D4" * 5),),
        ("sk-abc", "task-1234567890123456789012345678901234"),
        ai=True, generic=True, min_entropy=3.0,
    ),
    SecretPattern(
        "groq", "groq", "secret", False,
        re.compile(r"\bgsk_[A-Za-z0-9]{40,}"),
        "Groq API key",
        (_j("gs", "k_", _FILL * 6),),
        ("gsk_short",),
        ai=True,
    ),
    SecretPattern(
        "replicate", "replicate", "token", False,
        re.compile(r"\br8_[A-Za-z0-9]{30,}"),
        "Replicate API token",
        (_j("r", "8_", _FILL * 5),),
        ("r8_short",),
        ai=True,
    ),
    SecretPattern(
        "huggingface", "huggingface", "token", False,
        re.compile(r"\bhf_[A-Za-z0-9]{30,}"),
        "Hugging Face access token",
        (_j("h", "f_", _FILL * 5),),
        ("hf_short",),
        ai=True,
    ),
    SecretPattern(
        "xai", "xai", "secret", False,
        re.compile(r"\bxai-[A-Za-z0-9]{40,}"),
        "xAI API key",
        (_j("xa", "i-", _FILL * 6),),
        ("xai-short",),
        ai=True,
    ),
    SecretPattern(
        "elevenlabs", "elevenlabs", "secret", False,
        re.compile(r"\bsk_[a-f0-9]{40,}\b"),
        "ElevenLabs API key",
        (_j("sk", "_", "0a1b2c3d" * 6),),
        ("sk_live_abc", "sk_0a1b"),
        ai=True,
    ),
    SecretPattern(
        "supabase-secret", "supabase", "secret", False,
        re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}"),
        "Supabase secret key (bypasses row level security)",
        (_j("sb_", "secret_", _FILL * 4),),
        ("sb_secret_", "sb_secret_short"),
    ),
    SecretPattern(
        "supabase-publishable", "supabase", "publishable", True,
        re.compile(r"\bsb_publishable_[A-Za-z0-9_-]{20,}"),
        "Supabase publishable key (public by design)",
        (_j("sb_", "publishable_", _FILL * 4),),
        ("sb_publishable_",),
        severity="info",
    ),
    SecretPattern(
        "jwt", "jwt", "token", False,
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
        "JWT-shaped string (Supabase legacy keys are JWTs; the role claim decides)",
        (_j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJyb2xlIjoic2VydmljZV9yb2xlIn0", ".", "c2lnbmF0dXJlZmFrZQ"),),
        ("eyJ.eyJ.sig", "eyJhbGciOiJIUzI1NiJ9"),
        severity="high",
    ),
    SecretPattern(
        "google-api-key", "google", "api-key", True,
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "Google API key (Firebase web and Maps keys are public by design; Gemini keys are secret)",
        (_j("AI", "za", "Sy" + "A1b2C3d4E5f" * 3),),
        ("AIzaShort",),
        severity="info",
    ),
    SecretPattern(
        "aws-access-key-id", "aws", "access-key-id", False,
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "AWS access key ID",
        (_j("AK", "IA", "Q7XK2M9P4R6T8V1Z"),),
        ("AKIA1234", "AKIAIOSFODNN7EXAMPLE"),
        severity="high",
    ),
    SecretPattern(
        "aws-secret", "aws", "secret", False,
        re.compile(r"(?i)aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
        "AWS secret access key",
        (_j("AWS_SECRET_ACCESS_KEY=", "Fx9aQz7kLm3p" * 3, "Ab1/"),),
        ("AWS_SECRET_ACCESS_KEY=", "aws_secret_access_key = os.environ['X']"),
        group=1,
    ),
    SecretPattern(
        "google-oauth-secret", "google", "client-secret", False,
        re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}"),
        "Google OAuth client secret",
        (_j("GOC", "SPX-", _FILL * 4),),
        ("GOCSPX-short",),
    ),
    SecretPattern(
        "github-token", "github", "token", False,
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{50,}"),
        "GitHub token (classic, OAuth, app or fine-grained)",
        (_j("gh", "p_", _FILL * 5), _j("github_", "pat_", _FILL * 8)),
        ("ghp_short", "github_pat_short"),
    ),
    SecretPattern(
        "gitlab-token", "gitlab", "token", False,
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
        "GitLab personal access token",
        (_j("gl", "pat-", _FILL * 3),),
        ("glpat-short",),
    ),
    SecretPattern(
        "slack-token", "slack", "token", False,
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}"),
        "Slack token",
        (_j("xo", "xb-", "123456789012-", _FILL * 3),),
        ("xoxb-short",),
    ),
    SecretPattern(
        "slack-webhook", "slack", "webhook-url", False,
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{16,}"),
        "Slack incoming webhook URL",
        (_j("https://hooks.slack", ".com/services/", "T01ABCDEF/", "B01ABCDEF/", _FILL * 3),),
        ("https://hooks.slack.com/services/",),
        severity="high",
    ),
    SecretPattern(
        "discord-webhook", "discord", "webhook-url", False,
        re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{10,}/[A-Za-z0-9_-]{30,}"),
        "Discord webhook URL",
        (_j("https://discord", ".com/api/webhooks/", "123456789012345678/", _FILL * 6),),
        ("https://discord.com/api/webhooks/",),
        severity="high",
    ),
    SecretPattern(
        "discord-bot-token", "discord", "token", False,
        re.compile(r"\b[MNO][A-Za-z\d_-]{23,25}\.[A-Za-z\d_-]{6}\.[A-Za-z\d_-]{27,}"),
        "Discord bot token",
        (_j("M", "Tk4NjIyNDgzNDcxOTI1MjQ4", ".", "Xf9aQz", ".", _FILL * 4),),
        ("Module.exports.something",),
    ),
    SecretPattern(
        "twilio-api-key", "twilio", "secret", False,
        re.compile(r"\bSK[0-9a-f]{32}\b"),
        "Twilio API key SID",
        (_j("S", "K", "0a1b2c3d" * 4),),
        ("SK1234",),
        severity="high",
    ),
    SecretPattern(
        "sendgrid", "sendgrid", "secret", False,
        re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
        "SendGrid API key",
        (_j("S", "G.", _FILL * 3, ".", _FILL * 5),),
        ("SG.short.short",),
    ),
    SecretPattern(
        "resend", "resend", "secret", False,
        re.compile(r"\bre_[A-Za-z0-9]{6,}_[A-Za-z0-9]{16,}\b"),
        "Resend API key",
        (_j("r", "e_", "Fx9aQz7k", "_", _FILL * 3),),
        ("re_render_component_tree", "re_short"),
        min_entropy=3.0,
    ),
    SecretPattern(
        "mailgun", "mailgun", "secret", False,
        re.compile(r"\bkey-[0-9a-f]{32}\b"),
        "Mailgun API key",
        (_j("ke", "y-", "0a1b2c3d" * 4),),
        ("key-short",),
    ),
    SecretPattern(
        "database-url", "database", "url", False,
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:@/'\"`]+:([^\s@/'\"`]{3,})@([^\s'\"`/?]+)"),
        "Database or broker URL with an embedded password",
        (_j("postgresql://app:", "Fx9aQz7kLm3p", "@db.fakeproject.supabase.co:5432/postgres"),),
        ("postgresql://localhost:5432/app", "postgres://user@host/db"),
        group=1,
    ),
    SecretPattern(
        "generic-assignment", "generic", "generic", False,
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:password|passwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
            r"private[_-]?key|client[_-]?secret)[A-Za-z0-9_]*)[\"']?\s*[:=]\s*[\"'`]([^\"'`\s]{12,})[\"'`]"
        ),
        "Secret-named assignment with a high-entropy literal",
        (_j("apiKey = \"", "q7Xk2M9pR4t8V1zLw3Ns", "\""),),
        ("apiKey = process.env.API_KEY", "password = \"changeme-please\"", "secret: \"\""),
        severity="high", group=2, generic=True, min_entropy=3.5,
    ),
]

PATTERNS_BY_ID: Dict[str, SecretPattern] = {p.id: p for p in SECRET_PATTERNS}

# Values that vendors publish in documentation, and local-development defaults.
VENDOR_EXAMPLES = {
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    _j("sk_test_", "4eC39HqLyjWDarjtT1zdp7dc"),
    _j("sk_test_", "BQokikJOvBiI2HlWgH4olfQ2"),
    _j("pk_test_", "TYooMQauvdEDq54NiTphI7jx"),
}

_PLACEHOLDER_WORDS = (
    "your", "example", "changeme", "change-me", "change_me", "placeholder", "xxxx", "dummy",
    "sample", "insert", "replace", "todo", "redacted", "<", ">", "...", "${", "{{", "****",
    "foobar", "abcdef123", "notreal", "not-real", "not_real",
)

LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "db", "postgres", "mysql", "mongo", "redis")


def is_placeholder(value: str) -> bool:
    """True for values that are obviously not real credentials."""
    v = value.strip().strip("\"'`")
    if not v or v in VENDOR_EXAMPLES:
        return True
    low = v.lower()
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    core = re.sub(r"^[a-z]{1,12}[_-](?:live|test|secret|publishable|proj|ant|or)?[_-]?", "", low)
    if core and len(set(core)) <= 2:
        return True
    if low in ("password", "secret", "postgres", "root", "admin", "test", "pass", "user"):
        return True
    return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(value))
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def decode_jwt_payload(token: str) -> Optional[dict]:
    """Decode a JWT payload without verifying it. Returns None if not decodable."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    seg = parts[1]
    seg += "=" * (-len(seg) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(seg.encode("ascii")).decode("utf-8", "replace"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def classify_jwt(token: str) -> str:
    """Return supabase-anon, supabase-service-role, supabase-demo, or jwt."""
    payload = decode_jwt_payload(token) or {}
    role = str(payload.get("role", ""))
    iss = str(payload.get("iss", ""))
    if iss == "supabase-demo":
        return "supabase-demo"
    if role == "service_role":
        return "supabase-service-role"
    if role == "anon":
        return "supabase-anon"
    return "jwt"


@dataclasses.dataclass
class SecretMatch:
    pattern: SecretPattern
    value: str
    start: int
    end: int
    line: int
    name: str = ""          # variable name for generic assignments
    label: str = ""         # refined kind, e.g. supabase-service-role
    public: bool = False


_GOOGLE_AI_NAME = re.compile(r"(?i)gemini|google_?ai|generative|palm|genai|google_api_key")
_ENV_LOOKUP = re.compile(r"process\.env|import\.meta\.env|os\.environ|getenv|Deno\.env")


def find_secrets(text: str) -> List[SecretMatch]:
    """All credential-shaped values in text, most specific pattern first, no overlaps."""
    out: List[SecretMatch] = []
    taken: List[Tuple[int, int]] = []
    for pat in SECRET_PATTERNS:
        for m in pat.regex.finditer(text):
            g = pat.group
            value = m.group(g)
            start, end = m.span(g)
            if any(start < e and s < end for s, e in taken):
                continue
            if pat.id != "private-key" and is_placeholder(value):
                continue
            if pat.min_entropy and shannon_entropy(value) < pat.min_entropy:
                continue
            match = SecretMatch(pat, value, start, end, text.count("\n", 0, start) + 1, public=pat.public)
            if pat.id == "generic-assignment":
                match.name = m.group(1)
                if _ENV_LOOKUP.search(value) or re.match(r"^[A-Z0-9_]+$", value) or "/" in value and " " in value:
                    continue
                if re.search(r"(?i)public|publishable|anon|example|placeholder|label|title|message|name$|id$|url$|path$|regex|pattern|prefix|field|header|param", match.name):
                    continue
            if pat.id == "database-url":
                host = m.group(2).split(":")[0].lower()
                if host in LOCAL_HOSTS or value.startswith("$") or value.startswith("["):
                    continue
            if pat.id == "jwt":
                match.label = classify_jwt(value)
                if match.label == "supabase-demo":
                    continue
                if match.label == "supabase-anon":
                    match.public = True
            if pat.id == "google-api-key":
                ctx = text[max(0, start - 120):start]
                line_start = text.rfind("\n", 0, start) + 1
                if _GOOGLE_AI_NAME.search(text[line_start:start]) or _GOOGLE_AI_NAME.search(ctx.splitlines()[-1] if ctx.splitlines() else ""):
                    match.public = False
                    match.label = "google-ai"
            taken.append((start, end))
            out.append(match)
    out.sort(key=lambda s: s.start)
    return out


# --- Environment variables -------------------------------------------------

PUBLIC_ENV_PREFIXES: Dict[str, Tuple[str, ...]] = {
    "nextjs": ("NEXT_PUBLIC_",),
    "vite": ("VITE_",),
    "cra": ("REACT_APP_",),
    "expo": ("EXPO_PUBLIC_",),
    "sveltekit": ("PUBLIC_",),
    "astro": ("PUBLIC_",),
    "nuxt": ("NUXT_PUBLIC_",),
    "gatsby": ("GATSBY_",),
}
ALL_PUBLIC_PREFIXES: Tuple[str, ...] = tuple(sorted({p for v in PUBLIC_ENV_PREFIXES.values() for p in v}, key=len, reverse=True))

SECRET_NAME_RE = re.compile(
    r"(?i)(SECRET|SERVICE_?ROLE|PRIVATE|ADMIN|PASSWORD|PASSWD|DATABASE_URL|DB_URL|JWT|"
    r"OPENAI|ANTHROPIC|CLAUDE|GEMINI|GROQ|REPLICATE|ELEVENLABS|MISTRAL|COHERE|OPENROUTER|DEEPSEEK|XAI_|"
    r"HUGGINGFACE|HF_TOKEN|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|AUTH_TOKEN|ACCESS_TOKEN|WEBHOOK_SECRET)"
)
PUBLIC_NAME_RE = re.compile(r"(?i)(PUBLISHABLE|ANON|PUBLIC_KEY|_URL$|SITE_KEY|CLIENT_ID|PROJECT_ID|MEASUREMENT_ID|APP_ID|SENDER_ID|BUCKET|DOMAIN)")
AI_NAME_RE = re.compile(r"(?i)(OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GENERATIVE|GROQ|REPLICATE|ELEVENLABS|MISTRAL|COHERE|OPENROUTER|DEEPSEEK|XAI_|HUGGINGFACE|HF_TOKEN|PERPLEXITY|TOGETHER|FIREWORKS)")


def public_prefix(name: str) -> Optional[str]:
    for p in ALL_PUBLIC_PREFIXES:
        if name.startswith(p):
            return p
    return None


def is_secret_name(name: str) -> bool:
    """A variable name that suggests a private credential."""
    if not SECRET_NAME_RE.search(name):
        return False
    if re.search(r"(?i)PUBLISHABLE|ANON_KEY|PUBLIC_KEY", name):
        return False
    return True


ENV_READ_RE = re.compile(
    r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]|"
    r"import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)|Deno\.env\.get\(\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']|"
    r"Bun\.env\.([A-Za-z_][A-Za-z0-9_]*)|os\.environ\[\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]|"
    r"os\.environ\.get\(\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']|os\.getenv\(\s*[\"']([A-Za-z_][A-Za-z0-9_]*)[\"']|"
    r"\benv\(\s*[\"']([A-Z][A-Z0-9_]*)[\"']"
)
ENV_BUILTINS = {
    "NODE_ENV", "MODE", "DEV", "PROD", "SSR", "BASE_URL", "PORT", "HOST", "CI", "VERCEL", "VERCEL_ENV", "VERCEL_URL",
    "NETLIFY", "TZ", "PATH", "HOME", "PWD", "NEXT_RUNTIME", "NEXT_PHASE", "npm_package_version", "DEBUG",
}

# --- Authentication signals ------------------------------------------------

AUTH_CALL_RE = re.compile(
    r"auth\.getUser\(|auth\.getClaims\(|auth\.getSession\(|getServerSession\(|unstable_getServerSession\(|"
    r"(?<![.\w])auth\(\s*\)|auth\.protect\(|currentUser\(|getAuth\(|getToken\(\s*\{|"
    r"verifyIdToken\(|verifySessionCookie\(|validateSession\(|validateRequest\(|auth\.api\.getSession\(|"
    r"\bgetSession\(|getKindeServerSession\(|req\.isAuthenticated\(|passport\.authenticate\(|\breq\.user\b|\brequest\.user\b|"
    r"jwt\.verify\(|jwtVerify\(|"
    r"\b(?:require|verify|ensure|assert|authenticate|protect|check)[A-Za-z_]*(?:Auth|User|Session|Token|Admin|Login|Jwt|JWT)[A-Za-z_]*\(|"
    r"\bget(?:Current|Session|Auth|Server|Signed|LoggedIn|Authenticated)[A-Za-z_]*(?:User|Session|Auth)[A-Za-z_]*\(|"
    r"\bgetUser\(\s*\)|\bwithAuth\(|\bisAuthenticated\b|\bauthenticate\(|\bctx\.(?:user|session|auth)\b|\bcontext\.auth\b|"
    r"\brequest\.auth\b|\blocals\.(?:user|session|safeGetSession|getSession|auth)\b|\bevent\.context\.(?:user|auth)\b|"
    r"getUserSession\(|requireUserSession\(|serverSupabaseUser\(|"
    r"@login_required|@jwt_required|@permission_required|Depends\(\s*(?:get_current_\w+|require_\w+|verify_\w+|auth\w*)|"
    r"\bcurrent_user\b|permission_classes|IsAuthenticated|LoginRequiredMixin|get_jwt_identity\("
)

SESSION_IDENTITY_RE = re.compile(
    r"\b(?:user|session\??\.user|currentUser|authUser|claims|req\.user|request\.user|ctx\.user|ctx\.session\??\.user|"
    r"locals\.user|context\.auth|request\.auth|auth|token|decoded|payload|me|viewer|current_user)\??\.(?:id|uid|sub|userId|user_id|orgId|"
    r"org_id|organizationId|organization_id|tenantId|tenant_id|teamId|team_id|email|_id)\b|\buserId\b(?=[^:]*\bauth\()|"
    r"\bauth\.uid\(\)|\bget_jwt_identity\(|\bsession\.userId\b|\borgId\b|\buid\b(?=\s*[,})])"
)

RATE_LIMIT_RE = re.compile(r"(?i)rate[_-]?limit|ratelimit|limiter|throttle|slowDown|@upstash/ratelimit|express-brute|flask_limiter|slowapi|django_ratelimit")

VALIDATION_RE = re.compile(
    r"\.safeParse\(|\.parse\(\s*(?:body|data|json|input|payload|await|req|request|form|params|query|search|Object)|\.parseAsync\(|"
    r"\bz\.object\(|\bv\.object\(|\byup\.|\bJoi\.|\.validate\(|\bvalidate[A-Z]\w*\(|\bajv\b|class-validator|zodResolver|"
    r"\bt\.Object\(|typeof\s+\w+(?:\.\w+)*\s*[!=]==?\s*[\"'](?:string|number|boolean)|BaseModel|pydantic|serializer\.is_valid|"
    r"Number\.isInteger\(|Array\.isArray\("
)

# --- Privileged clients ----------------------------------------------------

PRIVILEGED_CLIENT_RES: Dict[str, Pattern[str]] = {
    "supabase-service-role": re.compile(
        r"SERVICE_ROLE|SUPABASE_SECRET_KEY|SUPABASE_SERVICE_KEY|sb_secret_|supabaseAdmin|adminClient|createAdminClient|"
        r"createServiceClient|createServiceRoleClient|serviceClient|service_role"
    ),
    "prisma": re.compile(r"\b(?:prisma|db|tx)\.\w+\.(?:findMany|findUnique|findFirst|findUniqueOrThrow|findFirstOrThrow|create|createMany|update|updateMany|upsert|delete|deleteMany|count|aggregate)\(|\$queryRaw|\$executeRaw"),
    "drizzle": re.compile(r"\bdb\.(?:select|insert|update|delete)\(|\bdb\.query\.\w+\.(?:findMany|findFirst)\("),
    "mongoose": re.compile(r"\b[A-Z]\w*\.(?:find|findOne|findById|findByIdAndUpdate|findOneAndUpdate|findByIdAndDelete|findOneAndDelete|create|insertMany|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate)\(|\.collection\(\s*[\"']"),
    "sql": re.compile(r"\b(?:pool|client|conn|connection|db|pg|sql|knex|sequelize|cursor|cur|database)\.(?:query|execute|raw|run|all|get|prepare)\(|\bsql`"),
    "firebase-admin": re.compile(r"\badmin\.(?:firestore|database|auth|storage)\(\)|\bgetFirestore\(\)|\badminDb\b|\bfirestore\(\)\.collection\(|\bdb\.collection\("),
    "stripe": re.compile(r"\bstripe\.\w+(?:\.\w+)*\.(?:create|update|retrieve|list|del|cancel|confirm|capture)\("),
    "sqlalchemy": re.compile(r"\bsession\.(?:query|add|execute|delete|commit)\(|\bdb\.session\.|\.objects\.(?:filter|get|all|create|update|delete)\("),
}

LLM_CALL_RE = re.compile(
    r"\.chat\.completions\.create\(|\.responses\.create\(|\.completions\.create\(|\.messages\.create\(|\.messages\.stream\(|"
    r"\b(?:generateText|streamText|generateObject|streamObject|embed|embedMany)\(|\.generateContent\(|\.generateContentStream\(|"
    r"\.images\.generate\(|\.audio\.(?:speech|transcriptions)\.create\(|\breplicate\.run\(|\.textToSpeech\.|"
    r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.replicate\.com|"
    r"api\.elevenlabs\.io|api\.mistral\.ai|api\.cohere\.(?:ai|com)|openrouter\.ai/api|api\.x\.ai|api\.deepseek\.com|"
    r"api\.together\.xyz|api\.perplexity\.ai|api-inference\.huggingface\.co|ChatOpenAI\(|ChatAnthropic\("
)
LLM_HOST_RE = re.compile(
    r"api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.replicate\.com|"
    r"api\.elevenlabs\.io|api\.mistral\.ai|api\.cohere\.(?:ai|com)|openrouter\.ai/api|api\.x\.ai|api\.deepseek\.com|"
    r"api\.together\.xyz|api\.perplexity\.ai|api-inference\.huggingface\.co"
)
LLM_SDK_PACKAGES: Dict[str, str] = {
    "openai": "openai", "@anthropic-ai/sdk": "anthropic", "@google/generative-ai": "google-ai", "@google/genai": "google-ai",
    "groq-sdk": "groq", "replicate": "replicate", "elevenlabs": "elevenlabs", "@elevenlabs/elevenlabs-js": "elevenlabs",
    "@mistralai/mistralai": "mistral", "cohere-ai": "cohere", "ai": "vercel-ai-sdk", "@ai-sdk/openai": "openai",
    "@ai-sdk/anthropic": "anthropic", "@ai-sdk/google": "google-ai", "langchain": "langchain", "@langchain/openai": "openai",
    "@langchain/anthropic": "anthropic", "@langchain/core": "langchain", "llamaindex": "llamaindex", "together-ai": "together",
    "@openrouter/ai-sdk-provider": "openrouter", "anthropic": "anthropic", "google-generativeai": "google-ai",
    "google-genai": "google-ai", "groq": "groq", "mistralai": "mistral", "cohere": "cohere",
}

MESSAGE_SEND_RE = re.compile(
    r"\.emails\.send\(|sgMail\.send\(|\.sendMail\(|\.messages\.create\(\s*\{[^}]*\b(?:to|from)\b|mailgun\.messages|"
    r"postmark\w*\.sendEmail\(|\bsendEmail\(|\bsendSms\(|\bsendSMS\(|\bsend_mail\(|\bsendgrid\b.*\.send\(|ses\.send\(|SendEmailCommand|"
    r"twilio\w*\.messages\.create\(|client\.messages\.create\(\s*\{\s*(?:body|to|from)"
)

WEBHOOK_VERIFY_RE = re.compile(
    r"constructEvent(?:Async)?\(|webhooks\.verify\(|\.verify\(\s*(?:payload|body|rawBody|raw|text)|\bWebhook\(|svix|verifyWebhook\(|"
    r"verifySignature\(|validateRequest\(|validateWebhook\w*\(|validateEvent\(|timingSafeEqual\(|compare_digest\(|x-hub-signature|"
    r"unmarshal\(|verifyKey\(|construct_event\(|verify_signature\(|parse_event_notification\(|parseEventNotification\("
)

# --- Request input ---------------------------------------------------------

INPUT_SOURCE_RE = re.compile(
    r"\b(?:req|request|ctx\.req|c\.req|event|context\.request)\.(?:body|query|params|headers|cookies)\b|"
    r"await\s+(?:req|request|c\.req|event\.request|context\.request)\.(?:json|formData|text)\(\)|"
    r"\b(?:req|request)\.(?:nextUrl\.)?searchParams|new\s+URL\(\s*(?:req|request)\.url\s*\)\.searchParams|searchParams\.get\(|"
    r"\bparams\.\w+|\breadBody\(|\bgetQuery\(|\bgetRouterParam\(|\bformData\.get\(|"
    r"\brequest\.(?:args|form|json|get_json\(\)|values|GET|POST|data|query_params)\b"
)
WHOLE_BODY_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*(?::\s*[\w<>\[\], |]+)?=\s*(?:await\s+(?:req|request|c\.req|event\.request)\.(?:json|formData)\(\)|"
    r"(?:req|request)\.body\b(?!\.)|await\s+readBody\(\w+\)|JSON\.parse\(\s*(?:event\.body|req\.body|body)[^)]*\))"
)
DESTRUCTURE_INPUT_RE = re.compile(
    r"(?:const|let|var)\s*\{([^}]*)\}\s*(?::\s*[^=]+)?=\s*(?:await\s+(?:req|request|c\.req|event\.request)\.(?:json|formData)\(\)|"
    r"(?:req|request)\.(?:body|query|params)\b|await\s+readBody\(\w+\)|JSON\.parse\(\s*(?:event\.body|req\.body)[^)]*\)|"
    r"(?:await\s+)?(?:ctx\.)?params\b|getQuery\(\w+\)|(?:body|json|data|payload|input)\b(?!\.))"
)
DIRECT_INPUT_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(\w+)\s*(?::\s*[\w<>\[\] |]+)?=\s*(?:(?:req|request)\.(?:body|query|params|headers)(?:\.|\[\s*[\"'])\w+|"
    r"(?:\w+\.)?searchParams\.get\(|(?:await\s+)?params\.\w+|(?:body|json|data|payload|input)\.\w+|formData\.get\(|"
    r"request\.(?:args|form|json|values|GET|POST|data)(?:\.get\(|\[))"
)
IDENTITY_FIELD_RE = re.compile(r"^(?:userId|user_id|uid|ownerId|owner_id|authorId|author_id|accountId|account_id|memberId|profileId|profile_id)$")
ROLE_FIELD_RE = re.compile(r"^(?:role|isAdmin|is_admin|admin|plan|tier|credits|permissions)$")
ID_FIELD_RE = re.compile(r"(?i)^(?:id|\w+Id|\w+_id|slug|uuid)$")

HTML_SANITIZER_RE = re.compile(r"(?i)DOMPurify|sanitize|purify|escapeHtml|xss\(|he\.encode|JSON\.stringify\(")
MODEL_OUTPUT_NAME_RE = re.compile(r"(?i)\b(?:completion|answer|reply|aiText|aiResponse|generated|assistant|llm|modelOutput|summary)\w*|\b(?:m|msg|message)\.content\b|\bresult\.text\b|\bresponse\.text\b|\bdata\.(?:text|answer|reply|output|completion)\b|\boutput\b")
LLM_CLIENT_HINT_RE = re.compile(r"useChat\(|useCompletion\(|/api/(?:chat|ai|generate|completion|ask)|role\s*===?\s*[\"']assistant[\"']|\bassistant\b")


def is_llm_output_sink(file_text: str, expr: str) -> bool:
    """Whether an HTML sink expression is likely to carry model output."""
    return bool(LLM_CLIENT_HINT_RE.search(file_text) and MODEL_OUTPUT_NAME_RE.search(expr))


SENSITIVE_COLUMN_RE = re.compile(
    r"(?i)^(?:e?mail|email_address|phone|phone_number|mobile|address|street|dob|date_of_birth|birth_?date|ssn|national_id|passport\w*|"
    r"\w*token\w*|\w*secret\w*|password\w*|card\w*|iban|salary|income|diagnosis|medical\w*|location|lat|lng|latitude|longitude|"
    r"ip|ip_address|stripe_customer_id|customer_id|full_name|id_document\w*|tax_id)$"
)
OWNER_COLUMN_RE = re.compile(r"(?i)^(?:user_id|owner_id|owner|author_id|created_by|profile_id|account_id|org_id|organization_id|tenant_id|team_id|workspace_id|member_id|uid|sender_id|recipient_id|buyer_id|seller_id|customer_id)$")
