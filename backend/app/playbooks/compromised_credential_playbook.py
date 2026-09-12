"""
SentinelAI - Compromised Identity & Credential Abuse Playbook
"""

from dataclasses import dataclass
from typing import Dict, List, Any

@dataclass
class IdentityPlaybookStep:
    step_id: str
    action_name: str
    target: str
    command_dry_run: str

IDENTITY_PLAYBOOK_STEPS: List[IdentityPlaybookStep] = [
    IdentityPlaybookStep(
        step_id="ID-SEC-101",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #1",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_1' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-102",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #2",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_2' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-103",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #3",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_3' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-104",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #4",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_4' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-105",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #5",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_5' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-106",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #6",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_6' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-107",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #7",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_7' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-108",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #8",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_8' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-109",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #9",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_9' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-110",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #10",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_10' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-111",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #11",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_11' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-112",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #12",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_12' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-113",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #13",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_13' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-114",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #14",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_14' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-115",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #15",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_15' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-116",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #16",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_16' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-117",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #17",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_17' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-118",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #18",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_18' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-119",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #19",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_19' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-120",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #20",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_20' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-121",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #21",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_21' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-122",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #22",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_22' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-123",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #23",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_23' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-124",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #24",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_24' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-125",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #25",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_25' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-126",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #26",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_26' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-127",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #27",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_27' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-128",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #28",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_28' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-129",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #29",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_29' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-130",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #30",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_30' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-131",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #31",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_31' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-132",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #32",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_32' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-133",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #33",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_33' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-134",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #34",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_34' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-135",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #35",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_35' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-136",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #36",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_36' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-137",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #37",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_37' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-138",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #38",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_38' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-139",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #39",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_39' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-140",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #40",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_40' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-141",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #41",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_41' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-142",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #42",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_42' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-143",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #43",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_43' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-144",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #44",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_44' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-145",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #45",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_45' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-146",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #46",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_46' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-147",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #47",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_47' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-148",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #48",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_48' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-149",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #49",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_49' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-150",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #50",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_50' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-151",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #51",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_51' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-152",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #52",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_52' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-153",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #53",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_53' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-154",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #54",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_54' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-155",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #55",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_55' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-156",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #56",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_56' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-157",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #57",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_57' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-158",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #58",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_58' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-159",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #59",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_59' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-160",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #60",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_60' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-161",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #61",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_61' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-162",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #62",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_62' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-163",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #63",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_63' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-164",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #64",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_64' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-165",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #65",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_65' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-166",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #66",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_66' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-167",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #67",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_67' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-168",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #68",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_68' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-169",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #69",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_69' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-170",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #70",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_70' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-171",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #71",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_71' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-172",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #72",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_72' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-173",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #73",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_73' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-174",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #74",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_74' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-175",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #75",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_75' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-176",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #76",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_76' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-177",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #77",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_77' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-178",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #78",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_78' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-179",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #79",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_79' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-180",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #80",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_80' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-181",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #81",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_81' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-182",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #82",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_82' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-183",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #83",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_83' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-184",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #84",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_84' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-185",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #85",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_85' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-186",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #86",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_86' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-187",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #87",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_87' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-188",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #88",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_88' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-189",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #89",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_89' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-190",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #90",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_90' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-191",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #91",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_91' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-192",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #92",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_92' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-193",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #93",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_93' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-194",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #94",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_94' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-195",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #95",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_95' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-196",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #96",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_96' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-197",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #97",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_97' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-198",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #98",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_98' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-199",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #99",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_99' -Force"
    ),
    IdentityPlaybookStep(
        step_id="ID-SEC-200",
        action_name="Revoke Kerberos TGT & Invalidate Refresh Tokens #100",
        target="Active Directory / Azure AD",
        command_dry_run="Revoke-ADSession -User 'user_100' -Force"
    ),
]
def get_identity_playbook() -> List[IdentityPlaybookStep]: return IDENTITY_PLAYBOOK_STEPS
