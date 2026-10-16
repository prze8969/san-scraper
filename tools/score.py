"""Scorer for PS 02 Salvage.

Evaluates salvage outputs against the 7 reference JSONs in kit/expected_outputs:
- Status matching
- Metadata key matching
- Records matching on specified match_on keys (field-by-field)
- Damage matching (supports any_of and lossy)
"""

from __future__ import annotations
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from src.cli import run_salvage


def score_all(samples_dir: Path, expected_dir: Path) -> int:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir)
        print(f"[*] Running salvage on {samples_dir} -> {out_path} ...")
        exit_code = run_salvage(str(samples_dir), str(out_path), quiet=True)
        if exit_code != 0:
            print(f"[!] Salvage returned non-zero exit code: {exit_code}")

        reference_files = sorted(expected_dir.glob("*.json"))
        if not reference_files:
            print(f"[!] No reference files found in {expected_dir}")
            return 1

        print(f"[*] Scoring {len(reference_files)} reference files ...\n")
        print(f"{'SAMPLE':<12} {'FORMAT':<12} {'STATUS':<8} {'META':<12} {'RECORDS':<16} {'DAMAGE':<12} {'RESULT'}")
        print(f"{'-'*12} {'-'*12} {'-'*8} {'-'*12} {'-'*16} {'-'*12} {'-'*8}")

        total_checks = 0
        passed_checks = 0

        for exp_file in reference_files:
            with open(exp_file, "r", encoding="utf-8") as f:
                exp_data = json.load(f)

            sample_name = exp_data.get("file", exp_file.stem)
            actual_file = out_path / f"{sample_name}.json"

            if not actual_file.exists():
                print(f"{sample_name:<12} {'MISSING':<12} {'FAIL':<8} {'FAIL':<12} {'FAIL':<16} {'FAIL':<12} FAIL (No output)")
                total_checks += 4
                continue

            with open(actual_file, "r", encoding="utf-8") as f:
                act_data = json.load(f)

            # 1. Format check
            exp_format = exp_data.get("format")
            act_format = act_data.get("format")
            format_ok = (exp_format == act_format)

            # 2. Status check
            exp_status = exp_data.get("status")
            act_status = act_data.get("status")
            status_ok = (exp_status == act_status)
            total_checks += 1
            if status_ok:
                passed_checks += 1

            # 3. Metadata check
            exp_meta = exp_data.get("metadata", {})
            act_meta = act_data.get("metadata", {})
            meta_passed = 0
            meta_total = len(exp_meta)
            for mk, mv in exp_meta.items():
                if mk in act_meta and act_meta[mk] == mv:
                    meta_passed += 1
            total_checks += meta_total
            passed_checks += meta_passed
            meta_str = f"{meta_passed}/{meta_total}"

            # 4. Records check via match_on
            match_keys = exp_data.get("match_on", [])
            exp_records = exp_data.get("records", [])
            act_records = act_data.get("records", [])

            # Index actual records by match_on tuple
            def get_rec_key(rec: dict[str, Any]) -> tuple:
                return tuple(rec.get(k) for k in match_keys)

            act_rec_map = {get_rec_key(r): r for r in act_records if None not in get_rec_key(r)}
            rec_fields_matched = 0
            rec_fields_total = 0

            for er in exp_records:
                ek = get_rec_key(er)
                rec_fields_total += len(er)
                if ek in act_rec_map:
                    ar = act_rec_map[ek]
                    for rk, rv in er.items():
                        if rk in ar and ar[rk] == rv:
                            rec_fields_matched += 1

            total_checks += rec_fields_total
            passed_checks += rec_fields_matched
            rec_str = f"{rec_fields_matched}/{rec_fields_total}"

            # 5. Damage check
            exp_damage = exp_data.get("expected_damage", [])
            act_damage = act_data.get("damage", [])
            damage_ok = True
            damage_total = len(exp_damage)
            damage_matched = 0

            if damage_total == 0:
                damage_total = 1
                if len(act_damage) == 0:
                    damage_matched = 1
                else:
                    damage_matched = 0
            else:
                for ed in exp_damage:
                    allowed_kinds = ed.get("any_of", [])
                    exp_lossy = ed.get("lossy")
                    matched_this = False
                    for ad in act_damage:
                        if ad.get("kind") in allowed_kinds:
                            if exp_lossy is None or ad.get("lossy") == exp_lossy:
                                matched_this = True
                                break
                    if matched_this:
                        damage_matched += 1

            total_checks += damage_total
            passed_checks += damage_matched
            dam_str = f"{damage_matched}/{damage_total}"

            overall_sample_pass = (status_ok and meta_passed == meta_total and rec_fields_matched == rec_fields_total and damage_matched == damage_total)
            res_str = "PASS" if overall_sample_pass else "FAIL"

            print(f"{sample_name:<12} {act_format:<12} {('OK' if status_ok else 'FAIL'):<8} {meta_str:<12} {rec_str:<16} {dam_str:<12} {res_str}")

        print(f"\n========================================================")
        score_pct = (passed_checks / total_checks * 100) if total_checks else 0.0
        print(f" SCORER TOTALS: {passed_checks} / {total_checks} points ({score_pct:.1f}%)")
        print(f"========================================================\n")

    return 0


def main() -> None:
    samples_dir = Path("kit/samples")
    expected_dir = Path("kit/expected_outputs")
    if not samples_dir.exists() or not expected_dir.exists():
        print(f"Error: Missing kit directories at {samples_dir} or {expected_dir}")
        sys.exit(1)
    score_all(samples_dir, expected_dir)


if __name__ == "__main__":
    main()
