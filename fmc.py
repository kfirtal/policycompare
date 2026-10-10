# -*- coding: utf-8 -*-
import time, json, urllib3, requests
from rule import Rule  # המחלקה קיימת אצלך

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# פרמטרי התחברות
FMC_HOST = "<REDACTED_FMC_HOST>"
FMC_USER = ""
FMC_PASS = ""
POLICY_NAME = "<REDACTED_POLICY_NAME>"
AUTH_URL = f"https://{FMC_HOST}/api/fmc_platform/v1/auth/generatetoken"

# פוקוס על מהירות הקריאות (429)
CALLS_PER_SECOND = 1  # בקשה לשנייה – נמנע ממגבלת ה-API
SLEEP_TIME = 0.5

print("Enter FMC username")
FMC_USER = input()
print("Enter FMC password")
FMC_PASS = input()
session = requests.session()


def safe_get(url, **kwargs):
    """קריאה ל-API עם טיפול במצב 429 ו-retry."""
    for attempt in range(5):  # עד 5 ניסיונות
        resp = session.get(url, **kwargs, verify=False)
        if resp.status_code == 429:  # קריאה מוגזמת
            wait = int(resp.headers.get('Retry-After', 2))
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp
    raise Exception(f"Too many 429 responses from {url}")


def safe_post(url, **kwargs):
    """POST עם טיפול באותו האופן – לא קיים בקוד שלנו, רק אם נצטרך."""
    for attempt in range(5):
        resp = session.post(url, **kwargs, verify=False)
        if resp.status_code == 429:
            wait = int(resp.headers.get('Retry-After', 2))
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp
    raise Exception(f"Too many 429 responses from {url}")


# קבלת Token
time.sleep(SLEEP_TIME)
auth_resp = safe_post(AUTH_URL, auth=(FMC_USER, FMC_PASS))
token = auth_resp.headers["X-auth-access-token"]
domains = json.loads(auth_resp.headers.get("DOMAINS", "[]"))
DOMAIN_UUID = domains[0]["uuid"]
BASE_URL = f"https://{FMC_HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}"

ports_cache = {}  # מפתח: שם האובייקט (או ID), ערך: set של פורטים

# שליפת מדיניות משם
policies_resp = safe_get(
    f"{BASE_URL}/policy/accesspolicies",
    headers={"X-auth-access-token": token},
    params={"limit": 1000},
)
policies = policies_resp.json()


def policy_uuid_by_name(name: str):
    for p in policies["items"]:
        if p["name"] == name:
            return p["id"]
    return None


# פונקציה רקורסיבית לקבלת כל הפורטים של Service
def get_all_ports(service_obj):
    """
    מקבלת Service Object (PortObjectGroup או ProtocolPortObject)
    ומחזירה set של כל הפורטים (כולל קבוצות מקוננות).
    """
    name = service_obj["name"]
    if name in ports_cache:  # כבר במטמון
        return ports_cache[name]
    all_ports = set()
    obj_type = service_obj["type"]
    if obj_type == "PortObjectGroup":
        # שלוף את הקבוצה
        time.sleep(SLEEP_TIME)
        grp_resp = safe_get(
            f"{BASE_URL}/object/portobjectgroups/{service_obj['id']}",
            headers={"X-auth-access-token": token},
        )
        group = grp_resp.json()
        # פורטים מילוליים בתוך הקבוצה
        for lit in group.get("literal", []):
            if lit.get("port"):
                all_ports.add(lit["port"])
        # חברי קבוצה – יכולים להיות גם קבוצות נוספות
        for member in group.get("objects", []):
            all_ports.update(get_all_ports(member))
    elif obj_type == "ProtocolPortObject":
        time.sleep(SLEEP_TIME)
        port_resp = safe_get(
            f"{BASE_URL}/object/protocolportobjects/{service_obj['id']}",
            headers={"X-auth-access-token": token},
        )
        port = port_resp.json().get("port")
        if port:
            all_ports.add(port)
    # שמירת תוצאה במטמון למניעת חזרות מיותרות
    ports_cache[name] = all_ports
    return all_ports


# שליפת חוקים של מדיניות
def policy_rules(policy_uuid):
    time.sleep(SLEEP_TIME)
    rules_resp = safe_get(
        f"{BASE_URL}/policy/accesspolicies/{policy_uuid}/accessrules",
        headers={"X-auth-access-token": token},
        params={"limit": 1000, "expanded": True},
    )
    rules = rules_resp.json()["items"]
    rules_list = []
    for i, rule in enumerate(rules):
        src = [obj["name"] for obj in rule.get("sourceNetworks", {}).get("objects", [])]
        dst = [obj["name"] for obj in rule.get("destinationNetworks", {}).get("objects", [])]
        svc_objs = rule.get("destinationPorts", {}).get("objects", [])
        svc_lit = rule.get("destinationPorts", {}).get("literals", [])
        #     print(f'svc_objs: {svc_objs}')
        #     print(f'svc_lit: {svc_lit}')
        all_ports = set()
        for svc in svc_objs:
            all_ports.update(get_all_ports(svc))
        for lit in svc_lit:
            port = lit.get('port')
            all_ports.add(port)
        rules_list.append(
            Rule(
                rule_number=i + 1,
                source_objects=src,
                destination_objects=dst,
                destination_services=list(all_ports),
            )
        )
    for rule in rules_list:
        if rule.destination_services[0] is None:
            rule.destination_services = []
    return rules_list


