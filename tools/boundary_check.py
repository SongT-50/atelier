#!/usr/bin/env python3
"""경계 검사 — 이 저장소는 공개된다. 나가면 안 되는 것이 섞였는지 본다.

    python tools/boundary_check.py              # 이 저장소를 검사한다
    python tools/boundary_check.py <경로>...    # 반입 후보를 미리 검사한다
    python tools/boundary_check.py --mutate     # 대조군에 이빨이 있는지 본다
    python tools/boundary_check.py --history    # 지웠던 것까지 — 히스토리 전체

두 번째 형태가 규칙 1의 동어반복을 피하는 쪽이다. 자기가 만든 표본만으로는
검사가 살아 있음을 증명하지 못한다 — **아직 정제되지 않은 실제 대상**에 돌려
잡히는지 봐야 한다.

돌아가는 순서:

  1) 대조군 자가시험
       양성 — 반드시 잡혀야 하는 표본
       음성 — 잡히면 안 되는 표본
     하나라도 어긋나면 본 검사를 **하지 않고** 즉시 종료한다(코드 2).
     ⇒ 산출이 「0건」일 때 그것이 진짜 부재인지 계측기가 죽은 건지
        가르지 못하면, 이 검사로 얻은 값은 전부 무의미하기 때문이다.

  2) 본 검사
       추적 파일의 내용 · 파일 경로 그 자체 · 커밋 메시지 전체
     새는 길은 본문만이 아니다.

종료 코드
    0   깨끗함 (대조군 통과 + 위반 0건)
    1   위반 발견
    2   검사기 고장 — 대조군을 못 맞혔다. 이때의 「0건」은 근거가 아니다.

⚠️ 이 검사가 증명하지 못하는 것은 tools/README.md 「반증자」 절에 적어 두었다.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# 본 검사에서 제외할 경로. 비워 둔다 — 검사기 자신도 검사 대상이다.
# (양성 표본을 파일에 리터럴로 적지 않고 런타임에 조립하는 이유가 이것이다.
#  샘플을 파일에 적어 두면 그 파일을 검사에서 빼야 하고, 그러면 그 파일에
#  진짜 비밀이 들어가도 영원히 못 잡는다.)
EXCLUDE_PREFIXES: tuple[str, ...] = ()

MAX_BYTES = 2_000_000  # 이보다 큰 파일은 읽지 않고 보고만 한다

# 적발 수를 그대로 「위험 N건」으로 읽는 것이 이 도구의 가장 흔한 오용이다.
# 만든 쪽이 그 오용을 저질렀다(2026-08-21). 그래서 세는 자리가 아니라
# **읽는 자리**에 붙인다.
CITE_WARNING = """
⚠️ 이 수는 「위험 N건」이 아니다. 인용하기 전에 두 질문을 갈라라.
     ① 이 문자열이 그 패턴이 **잡겠다고 선언한 것**이 맞나
     ② 그것이 **실제로 나가면 안 되는 것**인가
   ②를 가르는 것은 낱말이 아니라 **출처와 소유**다 —
     · 이미 공개된 출처(공개 API · 법령 · 표준 용어)에서 왔으면 그건 누출이 아니다
     · 내 것이면 공개는 선택이다. **남의 것이면 선택이 아니다.**
   출처를 안 보고 낱말만 세면 수천 건이 나오고, 그중 대부분이 아무것도 아니다."""


# ─────────────────────────────────────────────────────────────
# 런타임 신원 — 저장소에 적지 않는다
# ─────────────────────────────────────────────────────────────
def runtime_identity() -> list[str]:
    """이 머신의 사용자명·홈 디렉토리명을 실행 시점에 얻는다.

    이 값들을 소스에 하드코딩하면 검사기 자신이 경계를 위반한다.
    그래서 파일에는 안 남기고 매 실행마다 환경에서 읽는다.
    """
    found: set[str] = set()
    for v in (os.environ.get("USERNAME"), os.environ.get("USER"), Path.home().name):
        # 3자 미만은 오탐이 너무 많아 버린다 (안 본 것이 아니라 못 보는 것)
        if v and len(v) >= 3:
            found.add(v)
    return sorted(found)


# ─────────────────────────────────────────────────────────────
# 거부 조건(veto) — 「같은 줄에 무엇이 있나」로는 못 가르는 것
# ─────────────────────────────────────────────────────────────
# 문맥 조건(ctx)은 줄 전체를 보지만 **매치가 어디에 있는지**는 못 본다.
# URL 안쪽인지 아닌지가 딱 그 경우다. 한 번도 안 본 저장소 5곳에 돌려서
# 나온 오탐 34건 중 28건이 여기였다(2026-08-18).
#
# ⚠️ 좁히는 것은 공짜가 아니다. 무엇을 못 잡게 되는지 tools/README.md 에 적었다.

# 한 덩어리를 끊는 문자들. 따옴표를 소스에 직접 적지 않는다 —
# 이 파일도 검사 대상이라 escape 가 꼬이면 검사기 자신이 안 돌아간다.
_BREAK_CHARS = "/ 	" + chr(34) + chr(39)


def _has_break(seg: str, extra: str = "") -> bool:
    """조각 안에 덩어리를 끊는 문자가 있나."""
    return any(c in _BREAK_CHARS + extra for c in seg)


def _after_scheme(line: str, start: int) -> str | None:
    """매치 앞에 `scheme://` 가 있으면 그 뒤부터 매치 직전까지를 낸다."""
    i = line.rfind("://", 0, start)
    return None if i < 0 else line[i + 3 : start]


def veto_url_path(line: str, m: re.Match[str]) -> bool:
    """`http://host/home/...` 의 첫 경로 조각을 홈 디렉토리로 읽는 것을 막는다.

    호스트 부분이 **비어 있지 않을 것**을 요구한다. 그래서 `file:///home/사용자명`
    은 그대로 잡힌다(비면 호스트가 없다는 뜻이고, 그건 진짜 로컬 경로다).
    """
    seg = _after_scheme(line, m.start())
    return seg is not None and len(seg) > 0 and not _has_break(seg)


def veto_email_noise(line: str, m: re.Match[str]) -> bool:
    """이메일 모양이지만 연락처가 아닌 둘을 막는다.

    - `scheme://user:pass@host` 의 userinfo — 매치 앞에 `/ ? #` 가 없을 때만.
      그래서 `https://site/?email=...` 같은 **질의 문자열 속 진짜 주소는 남는다.**
    - `git@host:` 형태의 SSH 원격 주소.
    """
    seg = _after_scheme(line, m.start())
    if seg is not None and not _has_break(seg, extra="?#"):
        return True
    return m.group(0).startswith("git@") and line[m.end() : m.end() + 1] == ":"


# 패턴 id → 거부 조건. 여기 없는 패턴은 거부 조건이 없다.
VETOES = {
    "abs-path-nix": veto_url_path,
    "email": veto_email_noise,
}


# ─────────────────────────────────────────────────────────────
# 패턴
# ─────────────────────────────────────────────────────────────
def build_patterns() -> list[tuple[str, re.Pattern[str], str, re.Pattern[str] | None]]:
    """(패턴 id, 정규식, 무엇을 막는가, 같은 줄에 요구되는 문맥) 목록.

    문맥 조건은 오탐을 줄이려고 붙인다. 붙이는 순간 **못 잡는 경우가 생긴다** —
    무엇을 못 잡게 되는지는 tools/README.md 에 적었다.
    """
    ctx_phone = r"(?i)(?:전화|연락|휴대|핸드폰|폰번|담당자|phone|tel\b|mobile|contact)"

    pats: list[tuple[str, str, str, str | None]] = [
        # ── 개발 머신의 절대 경로 ──
        ("abs-path-win", r"[A-Za-z]:[\\/](?:Users|사용자)[\\/][^\\/\s\"']+", "윈도 홈 절대경로", None),
        ("abs-path-nix", r"/(?:home|Users)/[A-Za-z0-9._-]+", "유닉스 홈 절대경로", None),
        # ── 비밀 ──
        ("private-key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "개인키 블록", None),
        ("aws-key", r"AKIA[0-9A-Z]{16}", "AWS 액세스 키", None),
        ("github-token", r"gh[pousr]_[A-Za-z0-9]{30,}", "GitHub 토큰", None),
        ("slack-token", r"xox[abprs]-[A-Za-z0-9-]{10,}", "Slack 토큰", None),
        (
            "keylike-assign",
            r"(?i)\b(?:service_?key|api_?key|access_?token|auth_?token|client_?secret|password|passwd)\b"
            # 뒤에 여는 괄호가 오면 비밀이 아니라 호출이다 — `password = get_auth_from_url(...)`
            r"\s*[=:]\s*[\"']?[A-Za-z0-9/+_%-]{16,}(?![A-Za-z0-9/+_%-]*\()",
            "키·토큰·비밀번호 대입",
            None,
        ),
        # ── 개인 식별 정보 ──
        (
            "email",
            # 면제: 문서용 example.* / 회신 불가 주소(개인 연락처가 아니다)
            # 왼쪽은 \b 로 부족하다 — no-reply 의 하이픈 앞에도 경계가 있어서
            # 거기서 시작하면 -reply@… 로 면제를 우회한다(음성 대조군이 잡아냈다).
            # 도메인 쪽 noreply 도 면제한다 — GitHub 은 12345+name@users.noreply.github.com 형태다.
            # 로컬파트는 영숫자로 시작한다 — 이렇게 안 좁히면 diff 의 "+@mcp.tool()" 같은
            # 데코레이터를 이메일로 읽는다(실제 대상에서 나온 오탐).
            r"(?<![A-Za-z0-9._%+-])(?!no-?reply@)"
            r"[A-Za-z0-9][A-Za-z0-9._%+-]*@"
            r"(?!example\.(?:com|org|net)\b)"
            r"(?![A-Za-z0-9.-]*\bno-?reply\b)"
            r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            "이메일 주소",
            None,
        ),
        # 구분자가 있으면 그것만으로 충분히 특징적이다
        ("kr-phone", r"\b01[016789][-. ]\d{3,4}[-. ]\d{4}\b", "휴대전화 번호", None),
        # 구분자가 없는 11자리는 데이터 값과 구별이 안 된다 → 같은 줄의 문맥을 요구한다
        ("kr-phone-plain", r"\b01[016789]\d{7,8}\b", "휴대전화 번호(구분자 없음)", ctx_phone),
        ("kr-rrn", r"\b\d{6}-[1-4]\d{6}\b", "주민등록번호 형식", None),
        # ── 내부 망 ──
        (
            "private-ip",
            # 옥텟을 0-255 로 묶는다. \d{1,3} 이면 192.168.1.999 같은
            # **IP 가 아닌 것**까지 사설 IP 로 읽는다(실제 대상에서 나온 오탐).
            r"(?<![\d.])(?:10\.O\.O\.O"
            r"|172\.(?:1[6-9]|2\d|3[01])\.O\.O"
            r"|192\.168\.O\.O)(?![\d.])".replace("O", r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"),
            "사설 IP",
            None,
        ),
        # 앞의 (?<!...) 는 .env.local 같은 파일명을, 뒤의 (?!...) 는 settings.local.json 을 뺀다.
        # 둘 다 실제 대상에서 나온 오탐이다 — 대가로 api.internal.example.com 류를 놓친다.
        (
            "internal-host",
            r"(?<![.\w-])[a-z0-9][a-z0-9-]{2,}\.(?:local|internal|intranet|corp|lan)\b(?!\.[a-z])",
            "내부 호스트명",
            None,
        ),
    ]
    out = [(pid, re.compile(rx), why, re.compile(ctx) if ctx else None) for pid, rx, why, ctx in pats]

    # 런타임 신원 — 소스에 없고 실행할 때 붙는다
    for name in runtime_identity():
        out.append(
            (
                "machine-identity",
                re.compile(r"\b" + re.escape(name) + r"\b", re.IGNORECASE),
                "이 머신의 사용자명·홈 디렉토리명",
                None,
            )
        )
    return out


def line_hits(line: str, patterns):
    """한 줄에서 걸린 것들을 낸다. 문맥 조건이 붙은 패턴은 그 조건을 먼저 본다."""
    for pid, rx, why, ctx in patterns:
        if ctx is not None and not ctx.search(line):
            continue
        veto = VETOES.get(pid)
        for m in rx.finditer(line):
            if veto is not None and veto(line, m):
                continue
            yield pid, why, m


# ─────────────────────────────────────────────────────────────
# 대조군 — 본 검사보다 먼저 돌린다
# ─────────────────────────────────────────────────────────────
def control_samples() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    """(양성, 음성) 표본. 둘 다 (기대 패턴 id 또는 '', 문자열).

    표본을 리터럴로 적지 않고 조각으로 조립한다. 두 가지 이유:
      - 파일에 완성된 형태로 남으면 검사기 자신이 자기 표본에 걸린다
      - 검사기를 검사 대상에서 빼는 예외를 만들지 않아도 된다
    """
    home = Path.home()
    user = home.name

    positive = [
        ("abs-path-win", "설정 파일 위치: " + f"C:\\Users\\{user}\\project\\conf.ini"),
        ("abs-path-nix", "로그 경로 /home/" + user + "/app/run.log"),
        ("private-key", "-----BEGIN" + " RSA PRIVATE " + "KEY-----"),
        ("aws-key", "AKIA" + "ABCDEFGHIJKLMNOP"),
        ("github-token", "gh" + "p_" + "A" * 36),
        ("slack-token", "xox" + "b-" + "1234567890" + "-abcdefghij"),
        ("keylike-assign", "service" + "Key=" + "Zm9vYmFyYmF6cXV4MTIzNDU2"),
        ("email", "담당 " + "hong" + "@" + "somecompany" + ".co.kr"),
        ("kr-phone", "연락 " + "010-" + "1234-" + "5678"),
        ("kr-phone-plain", "담당자 " + "010" + "12345678"),  # 문맥 단어가 있을 때만
        ("kr-rrn", "확인 " + "900101-" + "1234567"),
        ("private-ip", "내부 서버 " + "192.168." + "0.42"),
        ("internal-host", "접속 " + "db-master" + ".internal"),
        ("machine-identity", "빌드한 사람: " + user),
        # ↓ 아래 둘은 **좁히기의 대가를 감시하는** 표본이다. URL 안쪽을 빼면서
        #   같이 빠지면 안 되는 것들 — 빠지는 순간 대조군이 죽는다.
        ("abs-path-nix", "설정 " + "file:///home/" + user + "/secret.txt"),
        ("email", "https://site.example/?" + "email=" + "hong" + "@" + "somecompany" + ".co.kr"),
        # ↓ **경계값** 표본. 자릿수 하한을 한 칸만 올려도 이것들이 빠진다 —
        #   그 변이를 대조군이 알아채게 하려고 일부러 최소 길이로 둔다.
        ("slack-token", "알림 " + "xox" + "a-" + "0123456789"),        # 접두 뒤 딱 10자
        ("github-token", "토큰 " + "gh" + "o_" + "B" * 30),            # 딱 30자
        ("kr-phone-plain", "연락 " + "010" + "1234567"),               # 010 뒤 딱 7자리
        ("email", "메일 " + "a" + "@" + "bb" + ".io"),                 # TLD 딱 2자
        ("internal-host", "접속 " + "abc" + ".local"),                 # 앞머리 딱 3자
    ]

    negative = [
        ("", "상대 경로 ./data/price_index.json 을 읽는다"),
        ("", "출처: https://www.data.go.kr/ 공개 API"),
        ("", "문의는 maintainer@example.com 으로"),
        ("", "2025년 지수 144.4, 2024년 155.2, 전년비 -6.7%"),
        ("", "공개 DNS 8.8.8.8 과 1.1.1.1 은 사설 대역이 아니다"),
        ("", "버전 10.15.7 macOS 에서 확인"),
        ("", "품목 32개, 기준연도 2018, 관측 104 개월"),
        ("", "사과 +10.47pt, 배 +3.2pt 기여"),
        ("", "docs/local/setup.md 를 보라"),
        # ↓ 아래 넷은 **실제 대상에 돌려서 발견한 오탐**이다. 우리가 상상해 넣은 게 아니라,
        #   정제 안 된 산출 디렉토리에 검사기를 돌렸을 때 kr-phone 이 물량·가격 숫자열을
        #   전화번호로 읽었다. 음성 대조군이 없었으면 이 과잉 검사를 못 봤을 것이다.
        ("", '{"qty":[19910000,1996123456,17920000],"unit":"kg"}'),
        ("", '{"code":"0100234567","name":"품목코드"}'),
        ("", "물량 01991234567 kg 누계"),
        ("", "일련번호 9001011234567 은 개인정보가 아니다"),
        # ↓ git trailer 는 매 커밋에 붙고 표현을 바꿀 수 없다. noreply 는 개인 연락처가 아니다.
        ("", "Co-Authored-By: Someone <noreply@example-host.com>"),
        ("", "알림 발신: no-reply@github.com"),
        # ↓ 실제 대상(공개 저장소 27곳의 커밋 메시지)에서 나온 오탐. 파일명이지 호스트명이 아니다.
        ("", "cp .env.example .env.local 만으로 바로 실행 가능하도록"),
        ("", "settings.local.json 을 편집한다"),
        # ↓ git 작성자 필드의 표준 형태. 계정을 가리키지 개인 연락처가 아니다.
        ("", "Author: 12345678+someone@users.noreply.github.com"),
        # ↓ diff 를 검사할 때 나온다. 앞의 +/- 는 diff 표시이고 뒤는 데코레이터다.
        ("", "+@mcp.tool()"),
        ("", "-@app.route('/api/v1')"),
        # ↓ 아래 다섯은 **한 번도 안 본 제3자 저장소 5곳**에 돌려서 나온 오탐이다
        #   (2026-08-18, 적발 912건 중 34건). 우리가 상상해 넣은 것이 아니다.
        ("", "문서 http://semanticweb.example.ac.kr/home/index.php/HanNanum 을 본다"),
        ("", "git clone git@github.com:someone/repo.git"),
        ("", "접속 http://user:pass@complex.url.example/path"),
        ("", "username, password = get_auth_from_url(proxy)"),
        ("", "대역 192.168.1.999/24 는 IP 가 아니다"),
        # ↓ **경계 바로 바깥** 표본. 패턴이 한 칸만 느슨해지면 이것들이 걸린다 —
        #   미묘한 약화를 알아채는 것은 이런 표본뿐이다(2026-08-22 변이 시험에서 나온 사각지대).
        ("", "키는 " + "AKIA" + "abcdefghijklmnop"),      # 소문자 — AWS 키 형식이 아니다
        ("", "값 " + "gh" + "p_" + "A" * 29),             # 29자 — 한 자 모자란다
        ("", "값 " + "xox" + "b-" + "123456789"),         # 9자 — 한 자 모자란다
        ("", "코드 " + "900101-" + "5234567"),            # 뒷자리 첫 숫자 5 — 주민번호 형식이 아니다
        ("", "값 " + "a" + "@" + "b" + ".c"),             # TLD 1자 — 주소가 아니다
        ("", "대역 10.999.0.1 과 172.300.0.1"),           # 옥텟 초과
        ("", "값 ab.local 은 앞머리가 짧다"),              # 2자 — 일부러 안 본다
    ]
    # 머신 신원은 런타임 값이라 여기서 만든다.
    # 낱말 경계가 빠지면 **다른 낱말 속의 같은 글자**까지 잡는다 — 그것을 알아채려는 표본.
    negative.append(("", "값 " + user + "electronics 는 다른 낱말이다"))

    return positive, negative


def run_controls(patterns) -> list[str]:
    """대조군을 돌린다. 어긋난 것들의 설명을 돌려준다(비었으면 통과)."""
    failures: list[str] = []
    positive, negative = control_samples()

    for expect_id, text in positive:
        hit_ids = {pid for pid, _why, _m in line_hits(text, patterns)}
        if expect_id not in hit_ids:
            failures.append(f"양성 대조군 놓침 [{expect_id}] — 이 표본이 안 잡힌다: {mask_all(text, patterns)}")

    for _, text in negative:
        hits = list(line_hits(text, patterns))
        if hits:
            names = ", ".join(f"{pid}→{m.group(0)}" for pid, _why, m in hits)
            failures.append(f"음성 대조군 오탐 — 걸리면 안 되는 것이 걸렸다 ({names}): {text}")

    return failures


def mutants(src: str):
    """정규식을 **미묘하게** 바꾼 것들을 낸다. (무엇을 바꿨나, 바뀐 정규식)

    통째 제거는 거친 변이다 — 실제 고장은 이렇게 온다:
    자릿수 하나가 밀리고, 앞뒤 조건 하나가 빠지고, 문자 종류가 넓어진다.
    ### 그런 변이를 대조군이 알아채지 못하면, 그 자리에는 **대조군이 없는 것과 같다.**
    """
    out: list[tuple[str, str]] = []

    # ① 자릿수 하한을 한 칸씩 민다 — 낮추면 오탐이 늘고, 높이면 놓친다
    for m in re.finditer(r"\{(\d+),(\d*)\}", src):
        lo, hi = int(m.group(1)), m.group(2)
        for new_lo, tag in ((lo - 1, "낮춤"), (lo + 1, "높임")):
            if new_lo < 1:
                continue
            out.append((f"하한 {lo}→{new_lo} ({tag})",
                        src[: m.start()] + "{%d,%s}" % (new_lo, hi) + src[m.end():]))

    # ② 앞뒤 조건(lookaround)을 하나씩 뺀다 — 오탐을 줄이려고 붙인 것들이다
    for m in re.finditer(r"\(\?<?[=!](?:[^()]|\([^()]*\))*\)", src):
        out.append((f"앞뒤 조건 제거 {m.group(0)[:18]}…", src[: m.start()] + src[m.end():]))

    # ③ 낱말 경계를 하나씩 뺀다
    for m in re.finditer(r"\\b", src):
        out.append(("낱말 경계 제거", src[: m.start()] + src[m.end():]))

    # ④ 문자 종류를 넓힌다 — 좁혀 둔 것을 아무 글자나 받게
    for m in re.finditer(r"\[[^\]]{2,}\]", src):
        out.append((f"문자 종류 넓힘 {m.group(0)[:14]}…", src[: m.start()] + "." + src[m.end():]))

    # ⑤ 갈래(|)를 하나씩 뺀다 — 여러 형태를 받는 패턴에서 한 형태를 잃는다
    depth = 0
    bars = []
    for i, ch in enumerate(src):
        if ch == "\\":
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "|" and depth == 0:
            bars.append(i)
    if bars:
        cuts = [-1] + bars + [len(src)]
        for k in range(len(cuts) - 1):
            piece = "|".join(src[cuts[j] + 1: cuts[j + 1]] for j in range(len(cuts) - 1) if j != k)
            out.append((f"갈래 {k + 1} 제거", piece))
    return out


def corpus_lines(extra_roots: list[str] | None = None) -> list[str]:
    """차이를 재볼 실제 글줄. 이 저장소의 추적 파일 + 대조군 표본 전부.

    좁다. 그래서 여기서 *"차이 없음"* 은 **「이 글에서 차이가 안 났다」** 까지만 말한다.
    """
    out: list[str] = []
    for rel in tracked_files():
        p = REPO / rel
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_BYTES or b"\x00" in raw:
            continue
        out += raw.decode("utf-8", errors="replace").splitlines()
    pos, neg = control_samples()
    out += [t for _, t in pos] + [t for _, t in neg]

    # 글이 좁으면 「등가」 판정이 부풀려진다 — 안 달라진 게 아니라 **달라질 글이 없던 것**이다.
    # 그래서 밖의 글을 넣을 수 있게 한다: --mutate <경로>...
    for rel, p in external_files(extra_roots or []):
        try:
            raw = p.read_bytes()
        except OSError:
            continue
        if len(raw) > MAX_BYTES or b"\x00" in raw:
            continue
        out += raw.decode("utf-8", errors="replace").splitlines()
    return out


def differs(a: re.Pattern[str], b: re.Pattern[str], lines: list[str]) -> bool:
    """두 정규식이 이 글에서 **한 번이라도 다르게 굴면** True."""
    for ln in lines:
        ma, mb = a.search(ln), b.search(ln)
        if (ma is None) != (mb is None):
            return True
        if ma is not None and mb is not None and ma.group(0) != mb.group(0):
            return True
    return False


def run_deep_mutation(patterns, extra_roots: list[str] | None = None):
    """미묘한 변이를 만들어, **대조군이 알아채는지** 본다.

    돌려주는 것: 대조군이 **못 알아챈** 변이 목록 = 그 자리의 사각지대.
    """
    silent = []
    equivalent = []
    tried = 0
    lines = corpus_lines(extra_roots)
    for i, (pid, rx, why, ctx) in enumerate(patterns):
        for what, src in mutants(rx.pattern):
            try:
                new = re.compile(src)
            except re.error:
                continue
            if new.pattern == rx.pattern:
                continue
            tried += 1
            mutated = list(patterns)
            mutated[i] = (pid, new, why, ctx)
            if run_controls(mutated):
                continue                       # 대조군이 알아챘다
            # 대조군이 조용했다. 그런데 **정말 달라지긴 하나?**
            # 어떤 글에서도 차이가 없으면 그건 사각지대가 아니라 **등가 변이**다 —
            # 대조군을 아무리 늘려도 못 잡는다. 둘을 섞으면 수치가 부풀려진다.
            (equivalent if not differs(rx, new, lines) else silent).append((pid, what))
    return silent, equivalent, tried


def run_mutation_test(patterns) -> list[str]:
    """패턴을 하나씩 빼 보고 **대조군이 그것을 잡는지** 본다.

    대조군이 **있다**는 것과 대조군에 **이빨이 있다**는 것은 다른 문장이다.
    양성 표본이 어떤 패턴을 못 덮고 있으면, 그 패턴은 죽어도 아무도 모른다 —
    그러면 그 패턴에 대해서는 대조군이 없는 것과 같다.

    ⚠️ 이것이 증명하지 못하는 것: 여기서 하는 변이는 **통째 제거**라는 거친 변이다.
       정규식을 미묘하게 약화시키는 변이(예: 자릿수 하나 줄이기)는 **안 본다.**
       그러니 이 시험의 통과는 *"대조군이 완전하다"* 가 아니라
       *"패턴이 통째로 사라지면 안다"* 까지만 말한다.
    """
    silent = []
    for i, entry in enumerate(patterns):
        pid = entry[0]
        rest = [p for j, p in enumerate(patterns) if j != i]
        if not any(pid in f for f in run_controls(rest)):
            silent.append(pid)
    return silent


# ─────────────────────────────────────────────────────────────
# 본 검사
# ─────────────────────────────────────────────────────────────
def mask(s: str) -> str:
    """찾은 것을 통째로 다시 찍으면 그 자체가 새는 길이다."""
    s = s.replace("\n", " ")
    return s[:4] + "*" * max(0, min(len(s) - 4, 20)) if len(s) > 4 else "*" * len(s)


def mask_all(text: str, patterns) -> str:
    for _pid, rx, _why, _ctx in patterns:
        text = rx.sub(lambda m: mask(m.group(0)), text)
    return text


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace"
    ).stdout


def tracked_files() -> list[str]:
    out = git("ls-files").splitlines()
    return [f for f in out if f and not f.startswith(EXCLUDE_PREFIXES)]


def staged_files() -> list[str]:
    """이번 커밋으로 들어오거나 바뀌는 파일(삭제 제외)."""
    out = git("diff", "--cached", "--name-only", "--diff-filter=ACMR").splitlines()
    return [f for f in out if f and not f.startswith(EXCLUDE_PREFIXES)]


def read_index(path: str) -> bytes | None:
    """워킹트리가 아니라 **인덱스**에서 읽는다.

    add 뒤에 파일을 또 고치면 워킹트리와 커밋될 내용이 달라진다.
    커밋되는 것은 인덱스 쪽이므로 그쪽을 봐야 한다.
    """
    r = subprocess.run(["git", "show", f":{path}"], cwd=REPO, capture_output=True)
    return r.stdout if r.returncode == 0 else None


def scan_text(where: str, text: str, patterns) -> list[str]:
    found = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pid, why, m in line_hits(line, patterns):
            found.append(f"  {where}:{lineno}  [{pid}] {why} → {mask(m.group(0))}")
    return found


def external_files(roots: list[str]) -> list[tuple[str, Path]]:
    """저장소 밖의 반입 후보를 모은다. (표시이름, 실제경로)"""
    out: list[tuple[str, Path]] = []
    for r in roots:
        p = Path(r).resolve()
        if p.is_file():
            out.append((p.name, p))
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and not any(
                    part in {".git", "__pycache__", "node_modules", ".venv", "venv"} for part in f.parts
                ):
                    out.append((str(f.relative_to(p)), f))
    return out


# ─────────────────────────────────────────────────────────────
# 히스토리 — 지금 파일이 아니라 **지웠던 것까지**
# ─────────────────────────────────────────────────────────────
# git 에서 「지운다」는 것은 최신 상태에서 빼는 것이지 없애는 것이 아니다.
# 워킹트리만 검사하면 **clone 한 번이면 누구나 꺼내는 것**을 못 본다.
#
# `git log -p` 로 훑으면 같은 내용이 커밋 수만큼 반복돼 큰 저장소에서 안 끝난다.
# 여기서는 **blob 을 sha 로 묶어 한 번씩만** 본다 — 같은 내용은 sha 가 같다.


def history_blobs() -> list[tuple[str, str]]:
    """(blob sha, 그 sha 가 처음 보인 경로). 트리·커밋 객체는 뺀다."""
    listing = git("rev-list", "--objects", "--all")
    cand: dict[str, str] = {}
    for line in listing.splitlines():
        sha, _, path = line.partition(" ")
        if path and len(sha) == 40:
            cand.setdefault(sha, path)
    if not cand:
        return []

    # 타입·크기를 한 번에 물어본다(객체마다 프로세스를 띄우지 않는다).
    shas = list(cand)
    chk = subprocess.run(
        ["git", "cat-file", "--batch-check"], cwd=REPO,
        input="\n".join(shas), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    out: list[tuple[str, str]] = []
    for line in chk.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob":
            out.append((parts[0], cand.get(parts[0], "?")))
    return out


def read_blobs(shas: list[str]) -> dict[str, bytes]:
    """blob 여러 개를 한 번에 읽는다. git cat-file --batch 형식을 그대로 판다."""
    if not shas:
        return {}
    r = subprocess.run(
        ["git", "cat-file", "--batch"], cwd=REPO,
        input=("\n".join(shas) + "\n").encode(), capture_output=True,
    )
    data, i, got = r.stdout, 0, {}
    while i < len(data):
        nl = data.find(b"\n", i)
        if nl < 0:
            break
        header = data[i:nl].split()
        i = nl + 1
        if len(header) != 3:
            continue
        sha, size = header[0].decode(), int(header[2])
        got[sha] = data[i : i + size]
        i += size + 1  # 내용 뒤의 개행
    return got


def scan_history(patterns) -> tuple[list[str], list[str], int]:
    """(위반, 안 읽은 것, 본 blob 수)"""
    blobs = history_blobs()
    violations: list[str] = []
    skipped: list[str] = []
    contents = read_blobs([sha for sha, _ in blobs])
    for sha, path in blobs:
        raw = contents.get(sha)
        if raw is None:
            skipped.append(f"{path}@{sha[:8]} (못 읽음)")
            continue
        if len(raw) > MAX_BYTES:
            skipped.append(f"{path}@{sha[:8]} (>{MAX_BYTES // 1000}KB)")
            continue
        if b"\x00" in raw:
            skipped.append(f"{path}@{sha[:8]} (바이너리)")
            continue
        # 경로도 샌다. 지금은 없어진 경로까지 본다.
        violations += scan_text(f"(옛 경로) {path}@{sha[:8]}", path, patterns)
        violations += scan_text(
            f"{path}@{sha[:8]}", raw.decode("utf-8", errors="replace"), patterns
        )
    return violations, skipped, len(blobs)


def main(argv: list[str]) -> int:
    argv = list(argv)
    msg_file = None
    if "--message" in argv:
        i = argv.index("--message")
        msg_file = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i : i + 2]
    staged = "--staged" in argv
    mutate = "--mutate" in argv
    history = "--history" in argv
    argv = [a for a in argv if a not in ("--staged", "--mutate", "--history")]

    # 모르는 플래그를 **경로로 읽지 않는다.** 오타 하나가 「대상 0개 → 위반 0건」이 되어
    # 그대로 「깨끗함」으로 읽힌다. 실제로 이 자리에서 한 번 그렇게 나왔다(2026-08-21).
    unknown = [a for a in argv if a.startswith("-")]
    if unknown:
        print(f"✗ 모르는 옵션: {' '.join(unknown)}")
        print("  여기서 「0건」이 나오면 그건 부재가 아니라 **아무것도 안 본 것**이다.")
        return 2

    patterns = build_patterns()
    ident = runtime_identity()

    print("경계 검사")
    print(f"  패턴 {len(patterns)}종 (그중 런타임 신원 {len(ident)}건 — 소스에는 없음)")

    # ── 1) 대조군 먼저 ──
    failures = run_controls(patterns)
    pos, neg = control_samples()
    if failures:
        print(f"\n✗ 대조군 실패 — 검사기가 죽었다 (양성 {len(pos)} · 음성 {len(neg)})")
        for f in failures:
            print(f"  {f}")
        print("\n본 검사를 돌리지 않았다. 여기서 나온 「0건」은 근거가 아니다.")
        return 2
    print(f"  대조군 통과 — 양성 {len(pos)}/{len(pos)} 잡음 · 음성 {len(neg)}/{len(neg)} 조용")

    # ── 1-b) 대조군에 이빨이 있나 (요청했을 때만) ──
    if mutate:
        silent = run_mutation_test(patterns)
        print()
        print(f"변이 시험 — 패턴을 하나씩 제거해 대조군이 비명을 지르는지 본다 (분모 {len(patterns)})")
        if silent:
            print(f"  ✗ 죽여도 조용한 패턴 {len(silent)}종: {', '.join(silent)}")
            print("    이 패턴들은 양성 대조군이 안 덮는다 — 있으나 마나다.")
            return 2
        print(f"  ✓ {len(patterns)}/{len(patterns)} 전부 잡힘")

        # ── 미묘한 변이 ──
        deep, equiv, tried = run_deep_mutation(patterns, argv)
        print(f"    (차이를 잰 글 — 이 저장소" + (f" + 밖의 {len(argv)}곳" if argv else "") + ")")
        print(f"\n  미묘한 변이 — 자릿수·앞뒤 조건·문자 종류·갈래를 한 칸씩 (분모 {tried})")
        caught = tried - len(deep) - len(equiv)
        print(f"    대조군이 알아챈 것 {caught} · 등가로 보이는 것 {len(equiv)} · "
              f"### 사각지대 {len(deep)}")
        if equiv:
            print("      (등가 = 이 글에서 원본과 **한 번도 다르게 안 군** 변이. "
                  "대조군을 늘려도 못 잡는다)")
        if not deep:
            print("    ✓ 사각지대 0건")
            return 0
        by_pid: dict[str, list[str]] = {}
        for pid, what in deep:
            by_pid.setdefault(pid, []).append(what)
        print(f"    ✗ 사각지대 {len(deep)}건 / {tried}  — 실제로 달라지는데 대조군이 조용하다")
        for pid, whats in sorted(by_pid.items(), key=lambda x: -len(x[1])):
            head = " · ".join(sorted(set(whats))[:3])
            more = f" 외 {len(whats) - 3}" if len(whats) > 3 else ""
            print(f"      [{pid}] {len(whats)}건 — {head}{more}")
        print("\n    이 자리들은 **패턴이 약해져도 아무도 모른다.**")
        if not argv:
            print("    ⚠️ 「등가」 판정을 **이 저장소의 글로만** 쟀다 — 좁으면 사각지대가 **과소평가**된다.")
            print("       밖의 글을 더해라: python tools/boundary_check.py --mutate <경로>...")
        else:
            print("    ⚠️ 「등가」는 **여기까지의 글에서** 안 달라졌다는 뜻이다. 더 넓히면 또 늘 수 있다.")
        print("    ⚠️ 이것은 실패가 아니라 **측정값**이다 — 종료 코드를 올리지 않는다.")
        print("       대조군을 늘려 줄이는 것이 맞고, 0 이 되어야 하는 값은 아니다.")
        return 0

    # ── 2) 본 검사 ──
    violations: list[str] = []
    skipped: list[str] = []

    if history:
        violations, skipped, n_blobs = scan_history(patterns)
        msgs = git("log", "--all", "--format=%H%n%B%n---")
        violations += scan_text("(커밋 메시지 전체)", msgs, patterns)
        who = "\n".join(sorted({x for x in git("log", "--all", "--format=%ae%n%ce%n%an%n%cn").splitlines() if x}))
        violations += scan_text("(커밋 작성자 전체)", who, patterns)
        n_commits = len(git("log", "--all", "--format=%H").splitlines())
        print(f"  본 검사 [히스토리 전체 — 지웠던 것까지] — 고유 blob {n_blobs}개 · 커밋 {n_commits}개")
        if skipped:
            print(f"  안 읽은 blob {len(skipped)}개   ← 「깨끗함」이 아니라 「안 봤음」이다")
        if violations:
            print(f"\n✗ 위반 {len(violations)}건")
            for v in violations:
                print(v)
            print("\n⚠️ 히스토리에서 나온 것은 **워킹트리에서 지워도 안 없어진다.**")
            print(CITE_WARNING)
            return 1
        print(f"\n✓ 위반 0건 / blob {n_blobs} · 커밋 {n_commits}  (분모를 함께 읽을 것)")
        return 0

    if msg_file:
        targets: list[tuple[str, Path | None]] = []
        mode = "커밋 메시지"
    elif argv:
        targets = external_files(argv)
        mode = f"반입 후보 {len(argv)}곳"
    elif staged:
        # p=None → 워킹트리가 아니라 인덱스에서 읽는다
        targets = [(rel, None) for rel in staged_files()]
        mode = "스테이지된 변경(인덱스)"
    else:
        targets = [(rel, REPO / rel) for rel in tracked_files()]
        mode = "이 저장소(추적 파일)"

    for rel, p in targets:
        violations += scan_text(f"(경로) {rel}", rel, patterns)  # 경로 문자열 자체도 샌다

        if p is None:
            raw = read_index(rel)
            if raw is None:
                continue
        else:
            if not p.exists():
                continue
            raw = p.read_bytes()
        if len(raw) > MAX_BYTES:
            skipped.append(f"{rel} (>{MAX_BYTES // 1000}KB)")
            continue
        if b"\x00" in raw:
            skipped.append(f"{rel} (바이너리)")
            continue
        violations += scan_text(rel, raw.decode("utf-8", errors="replace"), patterns)

    n_commits = 0
    if msg_file:
        text = Path(msg_file).read_text(encoding="utf-8", errors="replace")
        body = "\n".join(ln for ln in text.splitlines() if not ln.startswith("#"))
        violations += scan_text("(커밋 메시지)", body, patterns)
        n_commits = 1
    elif not argv and not staged:
        msgs = git("log", "--format=%H%n%B%n---")
        violations += scan_text("(커밋 메시지)", msgs, patterns)
        n_commits = len(git("log", "--format=%H").splitlines())

    # ── 커밋 작성자 ──
    # 본문도 메시지도 아닌 **메타데이터**로 샌다. 이 경로를 안 보다가 개인 이메일을
    # 공개 저장소로 내보낸 적이 있다(2026-08-14). git log 로 누구나 읽을 수 있다.
    who_n = 0
    if staged:
        who = "\n".join(x for x in (git("config", "user.email"), git("config", "user.name")) if x.strip())
        if who.strip():
            violations += scan_text("(git config — 앞으로 만들 커밋의 작성자)", who, patterns)
            who_n = 1
    elif not argv and not msg_file:
        who = "\n".join(sorted({x for x in git("log", "--format=%ae%n%ce%n%an%n%cn").splitlines() if x}))
        if who:
            violations += scan_text("(커밋 작성자)", who, patterns)
            who_n = len(who.splitlines())

    print(f"  본 검사 [{mode}] — 파일 {len(targets)}개 · 커밋 메시지 {n_commits}개 · 작성자 {who_n}종")
    if skipped:
        print(f"  안 읽은 파일 {len(skipped)}개: {', '.join(skipped)}   ← 이건 「깨끗함」이 아니라 「안 봤음」이다")

    if violations:
        print(f"\n✗ 위반 {len(violations)}건")
        for v in violations:
            print(v)
        print(CITE_WARNING)
        return 1

    print(f"\n✓ 위반 0건 / 파일 {len(targets)} · 커밋 {n_commits}  (분모를 함께 읽을 것)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
