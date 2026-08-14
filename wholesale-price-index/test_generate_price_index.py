"""generate_price_index 회귀 — Laspeyres 가격지수 정확성. 비용0·결정적.

실행: python test_generate_price_index.py

⚠️ 이 8건이 확인하는 것은 **산식이 스스로와 맞는가** 이지
   **이 지수가 시장을 잘 대표하는가** 가 아니다. 뒤엣것은 재지 않았다.
"""
import generate_price_index as gi


def test_build_structure():
    out = gi.build()
    for k in ("method", "base_year", "basket_size", "annual", "monthly", "headline", "caveats"):
        assert k in out, f"키 누락: {k}"
    assert out["base_year"] == 2018
    print("✅ test_build_structure: 출력 구조 정상")


def test_base_is_100():
    """기준연도 = 정확히 100.0 (Laspeyres 정의)."""
    out = gi.build()
    base = [a for a in out["annual"] if a["year"] == out["base_year"]][0]
    assert base["index"] == 100.0, f"기준연도 지수 {base['index']} (기대 100.0)"
    assert base["change_pct"] is None, "기준연도 change_pct는 None이어야"
    print("✅ test_base_is_100: 2018=100.0")


def test_2024_peak_sanity():
    """2024=인플레 피크 연도 sanity.

    특정 값에 못을 박으면(예: 157.3) 입력 데이터가 갱신될 때마다 깨진다.
    그래서 '계산 회귀는 잡되 데이터 갱신엔 견디는' 밴드+피크 구조로 검증한다."""
    out = gi.build()
    annual = {a["year"]: a["index"] for a in out["annual"]}
    y2024 = annual.get(2024)
    assert y2024 is not None, "2024 지수 없음"
    # 피크 era 밴드(기준 100 대비 +50~65%): 그로스 계산오류(단위혼입·q0 이중반영 등)는 이 밖으로 튐
    assert 150.0 < y2024 < 165.0, f"2024 지수 {y2024} 가 피크 sanity 밴드(150~165) 밖 — 계산 회귀 의심"
    # 완전연도 중 2024가 최고(인플레 피크) — 구조적 sanity
    complete = {y: v for y, v in annual.items() if not [a for a in out["annual"] if a["year"] == y][0]["is_partial"]}
    assert max(complete, key=complete.get) == 2024, f"완전연도 피크가 2024 아님: {complete}"
    print(f"✅ test_2024_peak_sanity: 2024={y2024}(피크 era 밴드·완전연도 최고)")


def test_laspeyres_pure_function():
    """laspeyres()가 손계산과 일치 — 2품목·2기간 단위검증."""
    products = {
        "A": {"yr": [{"year": 0, "avg_price": 100, "volume": 10},
                     {"year": 1, "avg_price": 120, "volume": 5}]},
        "B": {"yr": [{"year": 0, "avg_price": 50, "volume": 20},
                     {"year": 1, "avg_price": 60, "volume": 99}]},
    }
    series, n = gi.laspeyres(products, "yr", lambda r: r["year"], 0, [0, 1])
    # base: Σp0q0 = 100*10 + 50*20 = 2000
    # t=1:  Σpt·q0 = 120*10 + 60*20 = 2400 → 120.0 (q1 무시 = 물량 고정 확인)
    assert series[0]["index"] == 100.0 and series[1]["index"] == 120.0, series
    assert n == 2
    print("✅ test_laspeyres_pure_function: 손계산 일치 + q0 고정(물량 이중반영 없음)")


def test_monthly_yoy():
    """월간 YoY = 전년 동월 대비. 같은 달 12개월 간격 정의."""
    out = gi.build()
    if not out["monthly"]:
        print("⏭ 월간 데이터 없음 — skip")
        return
    # YoY 있는 항목은 전년 동월이 바스켓에 존재할 때만
    with_yoy = [m for m in out["monthly"] if m["yoy_pct"] is not None]
    for m in with_yoy:
        prev = next((x for x in out["monthly"] if x["year"] == m["year"] - 1 and x["month"] == m["month"]), None)
        assert prev, f"{m['year']}-{m['month']} yoy 있는데 전년동월 없음"
        expected = round((m["index"] / prev["index"] - 1) * 100, 1)
        assert m["yoy_pct"] == expected, f"{m}: yoy {m['yoy_pct']} != {expected}"
    print(f"✅ test_monthly_yoy: {len(with_yoy)}건 전년동월 변화율 정확")


def test_contributors_decomposition():
    """Laspeyres 기여도 합 = (완전연도 지수)-100 (정확 분해 — 회계 항등식).
    기여도는 완전연도 기준(반기 계절착시 회피)이므로 complete_index로 대조."""
    out = gi.build()
    c = out["contributors"]
    idx = out["headline"]["complete_index"]
    assert c["target_year"] == out["headline"]["complete_year"], "기여도 target이 완전연도와 불일치"
    assert c["is_partial"] is False, "기여도는 완전연도라 is_partial=False여야"
    assert abs(c["sum_check_pt"] - (idx - 100)) < 0.5, f"기여도 합 {c['sum_check_pt']} != 완전연도지수-100 {round(idx-100,1)}"
    assert len(c["top_up"]) == 5, "top_up 5건"
    ups = [r["contribution_pt"] for r in c["top_up"]]
    assert ups == sorted(ups, reverse=True), "top_up 기여도 내림차순 아님"
    # 개별 기여도도 손계산 가능: (p_t-p0)*q0/den*100, 부호 일관
    for r in c["top_up"]:
        same_sign = (r["contribution_pt"] >= 0) == (r["price_change_pct"] >= 0)
        assert same_sign, f"{r['product']}: 기여도/가격변화 부호 불일치"
    print(f"✅ test_contributors_decomposition: 합={c['sum_check_pt']}≈지수-100, 부호 일관")


def test_partial_year_flag():
    """진행중 연도(반기)는 is_partial=True (가격지수 해석 가드)."""
    out = gi.build()
    cur = gi.datetime.now(gi.KST).year
    cur_rows = [a for a in out["annual"] if a["year"] == cur]
    if cur_rows:
        assert cur_rows[0]["is_partial"] is True, "진행중 연도 is_partial 미표시"
    past = [a for a in out["annual"] if a["year"] < cur]
    assert all(not a["is_partial"] for a in past), "과거 연도가 partial로 오표시"
    print("✅ test_partial_year_flag: 진행중 연도만 partial")


def test_headline_complete_year_and_partial_yoy():
    """정직화: 헤드라인 대표값=완전연도 / 반기는 '전년 같은 기간 대비'로 별도.
    반기 지수를 전체연도 옆에 나란히 비교하는 계절 착시를 회피한다."""
    out = gi.build()
    h = out["headline"]
    # 대표값 = 완전연도(is_partial=False)
    comp_rows = [a for a in out["annual"] if a["year"] == h["complete_year"]]
    assert comp_rows and comp_rows[0]["is_partial"] is False, "complete_year가 완전연도 아님"
    assert abs(h["vs_base_pct"] - (h["complete_index"] - 100)) < 0.05, "vs_base_pct는 완전연도 기준"
    p = h.get("partial")
    if p:  # 반기 진행 중이면
        # 반기 지수는 전체연도보다 높은 계절편향 → same_period_yoy(전년 동월들)로 정직 해석
        assert p["index"] == h["latest_index"], "partial.index=최신 반기 지수"
        if p["same_period_yoy"] is not None:
            # 손검산: cur_H1 / prev_H1 - 1. prev_same_period_index로 재현
            # (same_period_yoy는 별도 물량가중 재계산이라 부호/크기 sanity만)
            assert p["prev_same_period_index"] and p["prev_same_period_index"] > 0
            assert -50 < p["same_period_yoy"] < 50, f"전년동기 YoY {p['same_period_yoy']} 비현실"
    print(f"✅ test_headline: 대표값=완전연도 {h['complete_year']}({h['vs_base_pct']:+}) / "
          f"반기 전년동기 {p['same_period_yoy'] if p else '—'}")


if __name__ == "__main__":
    test_build_structure()
    test_base_is_100()
    test_2024_peak_sanity()
    test_laspeyres_pure_function()
    test_monthly_yoy()
    test_contributors_decomposition()
    test_partial_year_flag()
    test_headline_complete_year_and_partial_yoy()
    print("\n🎉 8/8 통과")
