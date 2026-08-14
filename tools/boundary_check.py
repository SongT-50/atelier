#!/usr/bin/env python3
"""경계 검사 — 이 저장소는 공개된다. 나가면 안 되는 것이 섞였는지 본다.

    python tools/boundary_check.py              # 이 저장소를 검사한다
    python tools/boundary_check.py <경로>...    # 반입 후보를 미리 검사한다

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
            r"\s*[=:]\s*[\"']?[A-Za-z0-9/+_%-]{16,}",
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
            r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])",
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
        for m in rx.finditer(line):
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
    ]
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


def main(argv: list[str]) -> int:
    argv = list(argv)
    msg_file = None
    if "--message" in argv:
        i = argv.index("--message")
        msg_file = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i : i + 2]
    staged = "--staged" in argv
    argv = [a for a in argv if a != "--staged"]

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

    # ── 2) 본 검사 ──
    violations: list[str] = []
    skipped: list[str] = []

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
        return 1

    print(f"\n✓ 위반 0건 / 파일 {len(targets)} · 커밋 {n_commits}  (분모를 함께 읽을 것)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
