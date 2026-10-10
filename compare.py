
from typing import List
from rule import Rule


def find_gaps(csm_list: List[Rule], fmc_list: List[Rule]) -> List[Rule]:
    fmc_list_sig = set()

    for rule in fmc_list:
        sig = (
            frozenset(rule.source_objects),
            frozenset(rule.destination_objects),
            frozenset(rule.destination_services),
        )
        fmc_list_sig.add(sig)

    gaps = []

    for rule in csm_list:
        sig = (
            frozenset(rule.source_objects),
            frozenset(rule.destination_objects),
            frozenset(rule.destination_services),
        )
        if sig not in fmc_list_sig:
            gaps.append(rule)

    return gaps


def main():
    import csm
    import fmc

    fmc_policy_name = input("Enter FMC Policy Name: ")
    csm_policy_name = input("Enter CSM Policy Name: ")

    print("Comparing CSM and FMC policies...")

    try:
        fmc_rules = fmc.policy_rules(
            fmc.policy_uuid_by_name(fmc_policy_name)
        )
        csm_rules = csm.PolicyRules(
            csm.getPolicy(csm_policy_name)
        )

        print(f"FMC amount of rules: {len(fmc_rules)}")
        print(f"CSM amount of rules: {len(csm_rules)}")

        gaps = find_gaps(csm_rules, fmc_rules)

        print(f"Gaps number: {len(gaps)}")

        for rule in gaps:
            print(rule)

    finally:
        csm.logout()


if __name__ == "__main__":
    main()
