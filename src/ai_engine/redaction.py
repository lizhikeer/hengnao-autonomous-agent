"""结果与轨迹共享的密码文案脱敏；调用方应在截断前使用。"""

import re

_URL_USERINFO = re.compile(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s?#]*@")
_PASSWORD = re.compile(
    r'''(?i)((?:"(?:password|passwd|pwd)"|'(?:password|passwd|pwd)'|\b(?:password|passwd|pwd))\s*[:=]\s*)("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^&;,}\s]+)'''
)


def redact_text(value: str) -> str:
    def mask(match):
        secret = match.group(2)
        quote = secret[0] if secret[0] in {'"', "'"} else ""
        return match.group(1) + quote + "***" + quote

    value = _URL_USERINFO.sub(r"\1", value)
    return _PASSWORD.sub(mask, value)
