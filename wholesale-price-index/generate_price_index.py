"""도매 가격지수 (Laspeyres) 생성 — data/price_trend.json → data/price_index.json.

공개된 도매시장 거래 자료(공공데이터포털 데이터셋 `15141809`)를 물량가중 정합한
price_trend.json 을 입력으로, **공통 바스켓 품목의 도매가격지수**를 단일 지수로 만든다.

🔴 **부르는 이름 주의**
  · ~~'도매 체감물가'~~ 라 부르지 않는다. ### **이것은 공통 바스켓 품목의 도매가격지수**이고
    소비자 체감물가도 전체 농산물 물가도 아니다. 바스켓은 **전체 도매거래의 부분집합**이다.
  · ~~'전수 정산'~~ + ~~'표본 오차 없음'~~ 도 안 쓴다. ### **전수 수집과 모집단 대표성은 다른 문제**다.
    입력은 **월별 최대 7일 표본**이다(price_trend.json 의 `sampling` 을 볼 것).
  · 권리 표기 = **「이용허락범위 제한 없음」**(포털 원문 그대로). ~~공공누리 제0유형~~ 은 **없는 이름**이다.
  · ### ⚠️ 이 낱말들은 **caveats 와 stdout 을 통해 밖으로 나간다.** 여기서 고쳐야 사본이 안 생긴다.

방식 = 표준 Laspeyres: 지수_t = Σ(p_t·q0) / Σ(p0·q0) · 100  (q0=기준기간 물량 고정 → 가격 이중반영 없음).
  · annual: 기준연도=100, **공통 바스켓**(품목 수는 산출물 `basket_size` 를 볼 것 — ### 여기 숫자를
    박지 않는다. 한때 *"31품목"* 이라 박혀 있었고 실제는 32였다), 연간 시계열.
  · monthly: 기준월=100, 전년동월(YoY) 변화율 동반(월간은 계절 포함 → 전월대비 대신 YoY 권장).

caveat: 공통 바스켓(전체 도매 아님) / 단일 기준기간(rolling rebase는 v2) / 월간 비계절조정
  / 품목 안 품종·등급·산지 구성 변화가 평균가에 섞인다.
exit 0 = 정상 생성. --json 으로 stdout 미리보기.
"""
import sys, os, json
from datetime import datetime, timezone, timedelta

sys.stdout.reconfigure(encoding="utf-8")
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")
SRC = os.path.join(DATA, "price_trend.json")
OUT = os.path.join(DATA, "price_index.json")
KST = timezone(timedelta(hours=9))


def dump_atomic(obj, path, **kw):
    """임시 파일에 쓰고 교체 — 쓰다 죽어도 잘린 파일이 남지 않는다.

    (원본은 같은 일을 하는 별도 모듈을 썼다. 저장소를 자립시키려고 여기 인라인했다.
     회귀 시험 8건은 build() 만 검증하므로 이 교체는 시험 결과에 영향이 없다.)
    """
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, **kw)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def laspeyres(products, records_key, key_of, base_key, period_keys):
    """Σ(p_t·q0)/Σ(p0·q0)·100. 기준기간 물량 q0 고정. 반환=(series, basket_size).

    products[name][records_key] = [{avg_price, volume, ...}]. key_of(rec)->period key.
    바스켓 = base_key에 avg_price>0·volume>0 보유한 품목(가격 비율 정의 가능).
    """
    basket = {}
    for name, v in products.items():
        recs = {key_of(r): r for r in v.get(records_key, [])}
        b = recs.get(base_key)
        if b and b.get("avg_price") and b.get("volume"):
            basket[name] = recs
    series = []
    for pk in period_keys:
        num = den = 0.0
        n = 0
        for recs in basket.values():
            b = recs[base_key]
            cur = recs.get(pk)
            if not cur or not cur.get("avg_price"):
                continue
            num += cur["avg_price"] * b["volume"]
            den += b["avg_price"] * b["volume"]
            n += 1
        if den:
            series.append({"period": pk, "index": round(num / den * 100, 1), "n_products": n})
    return series, len(basket)


def _with_change(series):
    """직전 기간 대비 변화율 부여(시퀀스 순서 기준)."""
    for i, s in enumerate(series):
        s["change_pct"] = None if i == 0 else round((s["index"] / series[i - 1]["index"] - 1) * 100, 1)
    return series


def contributors(products, base_year, target_year):
    """Laspeyres 기여도 분해 — 각 품목이 (지수_t - 100)에 기여한 %p.

    기여_i = (p_t,i - p0,i)·q0,i / Σ(p0·q0) · 100.  Σ기여 = 지수_t - 100 (정확 분해).
    = '지수 변화를 어느 품목이 얼마나 끌어올렸/내렸나'(우리 미시 데이터 강점).
    """
    den = 0.0
    for v in products.values():
        ym = {r["year"]: r for r in v.get("yearly", [])}
        b = ym.get(base_year)
        if b and b.get("avg_price") and b.get("volume"):
            den += b["avg_price"] * b["volume"]
    rows = []
    if not den:
        return rows
    for name, v in products.items():
        ym = {r["year"]: r for r in v.get("yearly", [])}
        b, t = ym.get(base_year), ym.get(target_year)
        if not (b and b.get("avg_price") and b.get("volume") and t and t.get("avg_price")):
            continue
        contrib = (t["avg_price"] - b["avg_price"]) * b["volume"] / den * 100
        rows.append({
            "product": name,
            "contribution_pt": round(contrib, 2),
            "price_change_pct": round((t["avg_price"] / b["avg_price"] - 1) * 100, 1),
            "base_price": b["avg_price"],
            "latest_price": t["avg_price"],
        })
    rows.sort(key=lambda x: x["contribution_pt"], reverse=True)
    return rows


def build(src=SRC):
    with open(src, encoding="utf-8") as f:
        pt = json.load(f)
    products = pt["products"]

    # ── 연간 (2018=100) ──
    all_years = sorted({r["year"] for v in products.values() for r in v.get("yearly", [])})
    base_year = all_years[0]
    cur_year = datetime.now(KST).year
    annual, basket_n = laspeyres(products, "yearly", lambda r: r["year"], base_year, all_years)
    annual = _with_change(annual)
    for s in annual:
        s["year"] = s.pop("period")
        s["is_partial"] = (s["year"] == cur_year)

    # ── 월간 (기준월=100) + 전년동월(YoY) ──
    mkey = lambda r: f"{r['year']}-{r['month']:02d}"
    all_months = sorted({mkey(r) for v in products.values() for r in v.get("monthly_recent", [])})
    monthly, m_basket_n = ([], 0)
    if all_months:
        base_month = all_months[0]
        monthly, m_basket_n = laspeyres(products, "monthly_recent", mkey, base_month, all_months)
        monthly = _with_change(monthly)
        idx_by_period = {s["period"]: s["index"] for s in monthly}
        for s in monthly:
            y, m = s["period"].split("-")
            prev = f"{int(y) - 1}-{m}"  # 전년 동월
            s["year"], s["month"] = int(y), int(m)
            s.pop("period")
            base_prev = idx_by_period.get(prev)
            s["yoy_pct"] = None if not base_prev else round((s["index"] / base_prev - 1) * 100, 1)

    latest = annual[-1] if annual else {}

    # ── 진행 중(반기) 연도 계절 정직화 ──
    # 반기(H1)만의 지수를 전체연도 지수들과 나란히 비교하면 계절 착시(농산물 상반기 가격이
    # 전체연도보다 구조적으로 높음 — 완전연도 실측 +8~12%). 그래서 ① 대표값은 최근
    # '완전연도'로 잡고 ② 반기값은 '같은 기간(전년 동월들) 대비' YoY로 정직 해석한다.
    last_complete = next((a for a in reversed(annual) if not a.get("is_partial")), latest)
    partial = None
    if latest.get("is_partial") and latest.get("year"):
        py = latest["year"]
        cur_months = sorted({r["month"] for v in products.values()
                             for r in v.get("monthly_recent", []) if r["year"] == py})

        def _same_period_index(year, months):
            """base_year(전체연도 q0·p0) 대비, year의 해당 월들 물량가중가 Laspeyres 지수."""
            num = den = 0.0
            for v in products.values():
                ym = {r["year"]: r for r in v.get("yearly", [])}
                b = ym.get(base_year)
                if not (b and b.get("avg_price") and b.get("volume")):
                    continue
                recs = [r for r in v.get("monthly_recent", [])
                        if r["year"] == year and r["month"] in months and r.get("avg_price") and r.get("volume")]
                if not recs:
                    continue
                vnum = sum(r["avg_price"] * r["volume"] for r in recs)
                vden = sum(r["volume"] for r in recs)
                if not vden:
                    continue
                num += (vnum / vden) * b["volume"]
                den += b["avg_price"] * b["volume"]
            return round(num / den * 100, 1) if den else None

        cur_idx = _same_period_index(py, cur_months) if cur_months else None
        prev_idx = _same_period_index(py - 1, cur_months) if cur_months else None
        partial = {
            "year": py,
            "months": cur_months,
            "index": latest.get("index"),                 # 반기 지수(전체연도 기준, 계절 높음)
            "prev_same_period_index": prev_idx,           # 전년 같은 기간 지수
            "same_period_yoy": (round((cur_idx / prev_idx - 1) * 100, 1)
                                if (cur_idx and prev_idx) else None),  # 정직한 전년동기 대비
        }

    # ── 품목별 기여도 (기준연도 → 최근 완전연도) ──
    # 헤드라인 대표값을 완전연도로 잡으므로 기여도도 같은 완전연도 기준(합≈완전연도 지수-100)으로 정합.
    contrib_year = last_complete.get("year") if annual else None
    contrib_rows = contributors(products, base_year, contrib_year) if annual else []
    contrib_block = {
        "target_year": contrib_year,
        "is_partial": False,
        "sum_check_pt": round(sum(r["contribution_pt"] for r in contrib_rows), 1),  # ≈ 완전연도 index-100
        "top_up": contrib_rows[:5],
        "top_down": list(reversed(contrib_rows[-5:])) if len(contrib_rows) >= 5 else [],
    }

    out = {
        "generated": datetime.now(KST).strftime("%Y-%m-%d %H:%M"),
        "method": "Laspeyres (기준기간 물량 q0 가중 고정)",
        "base_year": base_year,
        "basket_size": basket_n,
        "data_range": pt.get("data_range"),
        "headline": {
            # 대표값 = 최근 완전연도 (반기 계절 착시 회피)
            "complete_year": last_complete.get("year"),
            "complete_index": last_complete.get("index"),
            "vs_base_pct": None if not last_complete else round(last_complete["index"] - 100, 1),
            # 최신(반기 잠정) — 별도 표기 + 전년동기 대비
            "latest_year": latest.get("year"),
            "latest_index": latest.get("index"),
            "is_partial": latest.get("is_partial"),
            "partial": partial,
        },
        "annual": annual,
        "monthly": monthly,
        "monthly_basket_size": m_basket_n,
        "contributors": contrib_block,
        "caveats": [
            f"주요 {basket_n}품목 공통 바스켓 — 전체 도매 거래의 부분집합(대표 품목 한정)",
            f"단일 기준연도({base_year}=100) — 5년 rolling rebase는 후속(v2)",
            "진행 중 연도(반기)는 계절적으로 전체연도보다 높음(완전연도 실측 +8~12%) → 대표값은 최근 완전연도로, 반기는 '전년 같은 기간 대비'로 해석",
            "월간 지수는 비계절조정 → 전월대비보다 전년동월(YoY) 비교 권장",
            "입력 avg_price는 물량가중 원/kg — 품목간 단위는 지수 비율로 무차원",
            "입력은 월별 최대 7일 표본 — 전수가 아니며 표본 오차는 재지 않았다",
        ],
    }
    return out


def main():
    out = build()
    if "--json" in sys.argv:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return
    dump_atomic(out, OUT, ensure_ascii=False, indent=2)
    h = out["headline"]
    print(f"✅ price_index.json 생성 | 바스켓 {out['basket_size']}품목 | "
          f"{out['base_year']}=100 → 지수(완전연도 {h['complete_year']}):{h['complete_index']} "
          f"(기준대비 {h['vs_base_pct']:+})")
    p = h.get("partial")
    if p:
        yoy = p.get("same_period_yoy")
        yoy_s = f"{yoy:+.1f}%" if yoy is not None else "—"
        print(f"   {p['year']} 반기 잠정 지수 {p['index']} | 전년 같은기간 대비 {yoy_s}")
    print(f"   연간 {len(out['annual'])}점 / 월간 {len(out['monthly'])}점")


if __name__ == "__main__":
    main()
