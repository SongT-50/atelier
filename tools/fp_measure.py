#!/usr/bin/env python3
"""오탐률 측정 — 적발 하나하나를 판정해서 센다.

    python tools/fp_measure.py <저장소경로>...

경계 검사(`boundary_check.py`)는 「몇 건 걸렸나」까지만 말한다. 그 수는 오탐률이
아니다. **걸린 것 하나하나가 그 패턴이 잡겠다고 선언한 대상이 맞는지** 판정해야
비율이 나온다. 이 파일이 그 판정을 코드로 고정한다 — 손으로 세면 재현이 안 된다.

두 가지를 **따로** 센다. 섞으면 둘 다 못 읽는다.

    (A) 패턴 오탐   매치한 문자열이 그 패턴이 선언한 대상이 **아니다**
    (B) 위반 여부   패턴은 맞았으나, 그 저장소가 **일부러 공개한 것**인가

(B) 때문에 「오탐률」과 「위반 적중률」은 다른 값이 된다. 실측에서 진양성의
약 3분의 1이 문서·테스트용 예시였다. 오탐률만 인용하면 그 부담이 안 보인다.

⚠️ 이 판정 규칙이 증명하지 못하는 것

  - 규칙을 **측정 대상을 보고** 만들었다. 그러니 여기서 나온 비율은
    **그 대상에서의 비율**까지만 말한다. 새 대상에는 새 오탐 유형이 있을 수 있다.
  - **위음성(놓친 것)은 못 잰다.** 정답지가 없다.
    *"오탐이 적다"* 는 *"잘 잡는다"* 가 **아니다.**
  - 돌린 쪽과 판정한 쪽이 같다. 생성자와 검증자가 안 나뉘었다.

재현에 대하여 — 이 스크립트는 **현재** 패턴으로 잰다. tools/README.md 에 적힌
**3.7%** 는 좁히기 **전** 값이라, 재현하려면 그 직전 커밋의 검사기로 돌려야 한다.
지금 돌리면 같은 대상에서 훨씬 낮게 나오는데, 그 값은 **같은 데이터로 잰 것이라
인용하지 않는다**(이유는 tools/README.md).
"""

from __future__ import annotations

import collections
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import boundary_check as bc  # noqa: E402

# 연락처가 아니라 「자리표시자」인 이메일. 실측 대상에서 나온 것들이다.
# 완성된 형태로 적지 않고 조각으로 조립한다 — 그대로 적으면 이 파일이
# 경계 검사에 걸린다(실제로 걸렸다). 검사를 약화시키는 대신 파일을 고친다.
PLACEHOLDER = {
    "your" + "@" + "email.com",
    "joe.smith" + "@" + "email.com",
    "LL" + "@" + "li.org",
    "EMAIL" + "@" + "ADDRESS",
}

FP, OK_PUBLIC, REAL = "오탐", "진양성·위반아님", "진양성·실제"


def classify(pid: str, s: str, line: str, start: int) -> tuple[str, str]:
    """적발 하나를 판정한다. → (분류, 사유)"""
    before = line[:start]
    in_url = bool(re.search(r"[a-z][a-z0-9+.-]*://\S*$", before))

    if pid == "abs-path-nix":
        if in_url:
            return FP, "URL 경로를 홈 디렉토리로 읽음"
        if re.search(r"/home/(app|nginx|www|node|user)\b", s):
            return OK_PUBLIC, "컨테이너 내부 경로"
        return REAL, "개발 머신 사용자명 포함"

    if pid == "email":
        if in_url:
            return FP, "URL 의 user:pass@host"
        if s.startswith("git@") and "git " in line:
            return FP, "SSH 원격 주소"
        if s in PLACEHOLDER:
            return OK_PUBLIC, "자리표시자"
        return REAL, "실제 연락처 형태"

    if pid == "private-ip":
        if any(int(o) > 255 for o in re.findall(r"\d+", s)):
            return FP, "옥텟 255 초과 — IP 가 아님"
        return OK_PUBLIC, "문서·테스트용 예시 주소"

    if pid == "internal-host":
        if re.search(r"\b(threading|asyncio|contextvars)\.$", before) or s.split(".")[0] in {
            "threading",
            "asyncio",
        }:
            return FP, "파이썬 모듈 속성 접근"
        return OK_PUBLIC, "설정상 가짜 호스트"

    if pid == "keylike-assign":
        if re.search(r"=\s*[A-Za-z_][A-Za-z0-9_]*\s*\(", line[start:]):
            return FP, "함수 호출 대입 — 비밀이 아님"
        return REAL, "키 형태 대입"

    if pid == "private-key":
        return OK_PUBLIC, "테스트 픽스처 인증서"

    return REAL, "(미분류 — 사람이 봐야 한다)"


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2

    patterns = bc.build_patterns()
    if bc.run_controls(patterns):
        print("✗ 대조군 실패 — 검사기가 죽었다. 여기서 나올 비율은 근거가 아니다.")
        return 2

    grand: collections.Counter[str] = collections.Counter()
    reasons: collections.Counter[tuple[str, str, str]] = collections.Counter()
    print(f"{'대상':30s} {'파일':>6s} {'줄':>8s} {'적발':>6s} {'오탐':>6s} {'공개의도':>8s} {'실제':>6s}")

    for root in argv:
        cnt: collections.Counter[str] = collections.Counter()
        files = lines = 0
        for _rel, p in bc.external_files([root]):
            raw = p.read_bytes()
            if len(raw) > bc.MAX_BYTES or b"\x00" in raw:
                continue
            files += 1
            for ln in raw.decode("utf-8", errors="replace").splitlines():
                lines += 1
                for pid, _why, m in bc.line_hits(ln, patterns):
                    k, why = classify(pid, m.group(0), ln, m.start())
                    cnt[k] += 1
                    grand[k] += 1
                    reasons[(pid, k, why)] += 1
        print(
            f"{Path(root).name[:30]:30s} {files:6d} {lines:8d} {sum(cnt.values()):6d} "
            f"{cnt[FP]:6d} {cnt[OK_PUBLIC]:8d} {cnt[REAL]:6d}"
        )

    total = sum(grand.values())
    if not total:
        print("\n적발 0건 — 분모가 0이라 비율을 낼 수 없다. 「오탐률 0%」가 아니다.")
        return 0

    print(f"\n적발 {total}건 — 오탐 {grand[FP]} ({grand[FP] / total:.1%})")
    print(f"  진양성 {total - grand[FP]}건 중")
    print(f"    실제 개인정보·머신정보 {grand[REAL]}건")
    print(f"    패턴은 맞았으나 공개 의도 {grand[OK_PUBLIC]}건  ← 반입 선별기로 쓸 때의 부담")
    print("\n[사유별]")
    for (pid, k, why), c in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"  {c:6d}  {k:14s} {pid:15s} {why}")
    print("\n⚠️ 놓친 것(위음성)은 안 쟀다 — 정답지가 없다. 이 비율은 「잘 잡는다」가 아니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
