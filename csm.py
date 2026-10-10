from rule import Rule
import requests
import urllib3
import xml.etree.ElementTree as ET

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
base_url = "https://<REDACTED_CSM_HOST>/nbi/"
csm_username = ""
csm_password = ""
Device = ""
policy_name = "<REDACTED_POLICY_NAME>"
gid_number = ""
session = requests.session()
NS = {'n': 'csm'}

print("Enter CSM username")
csm_username = input()
print("Enter CSM password")
csm_password = input()

auth_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<csm:loginRequest xmlns:csm="csm">
    <protVersion>1.0</protVersion>
    <reqId>12345</reqId>
    <username>{csm_username}</username>
    <password>{csm_password}</password>
</csm:loginRequest>"""
headers = {'Content-Type': 'text/xml'}
try:
    response = session.post(f"{base_url}/login", data=auth_payload,
                            headers=headers, verify=False)
    if response.status_code == 200:
        cookies = response.cookies.get('asCookie')
    else:
        print("Login Failed")
        print(response.text)
except Exception as e:
    print(f"Error:{e}")

# Build the request headers
headers = {
    'Content-Type': 'text/xml',
    'Cookie': f'asCookie={cookies}'  # <-- use the string we extracted above
}


def getGIDByName(hostname):  # Return GID
    name_xml = f"""
<?xml version="1.0" encoding="UTF-8"?>
<n:deviceConfigByNameRequest xmlns:n="csm">
    <protVersion>1.0</protVersion>
    <reqId>123456</reqId>
    <name>{hostname}</name>
</n:deviceConfigByNameRequest>""".strip()
    # generated the GID
    response = session.post(f"{base_url}/configservice/getDeviceConfigByName",
                            data=name_xml, headers=headers, verify=False)
    gid = response.text.split('<gid>')[1].split('</gid>')[0]
    return gid


def getPolicyList(gid):  # Return Policy List
    data_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<n:policyListByDeviceGIDRequest xmlns:n="csm">
    <protVersion>1.0</protVersion>
    <reqId>12345678</reqId>
    <gid>{gid}</gid>
</n:policyListByDeviceGIDRequest>""".strip()
    list = session.post(f"{base_url}/configservice/getPolicyListByDeviceGID",
                        data=data_xml, headers=headers, verify=False)
    return list.text


def getPolicy(policy_name):  # Return access rule policy
    policy_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<n:policyConfigByNameRequest xmlns:n="csm">
    <protVersion>1.0</protVersion>
    <reqId>1234567</reqId>
    <name>{policy_name}</name>
    <policyType>DeviceAccessRuleFirewallPolicy</policyType>
</n:policyConfigByNameRequest>""".strip()
    policy = session.post(f"{base_url}/configservice/getPolicyConfigByName",
                          data=policy_xml, headers=headers, verify=False)
    return policy.text


def getNameByGID(gid):
    gid_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<csm:getPolicyObjectByGID xmlns:csm="csm">
    <protVersion>1.0</protVersion>
    <reqId>123456</reqId>
    <gid>{gid}</gid>
</csm:getPolicyObjectByGID>""".strip()
    response = session.post(f"{base_url}/configservice/getPolicyObjectByGID",
                            data=gid_xml, headers=headers, verify=False)
    if response.status_code == 200:
        # print(f'Object:{response.text}\n')
        root = ET.fromstring(response.text)
        name = root.find(".//name")
        return name.text
    else:
        return "No name found for this GID: {gid}"


def PolicyRules(policy):
    rules = []
    root = ET.fromstring(policy)
    for rule in root.findall('.//deviceAccessRuleFirewallPolicy'):
        rule_id = rule.find('orderId').text
        sources = []
        destinations = []
        services = []
        for s in rule.findall('.//sources/networkObjectGIDs/gid'):
            name = getNameByGID(s.text)
            sources.append(name)
        for s in rule.findall('.//destinations/networkObjectGIDs/gid'):
            name = getNameByGID(s.text)
            destinations.append(name)
        for s in rule.findall('.//services/serviceObjectGIDs/gid'):
            name = getNameByGID(s.text)
            services.append(extractPorts(s.text))
        services = list(set(val for s in services for val in s))
        for s in rule.findall('.//services/serviceParameters'):
            # protocol = s.find("protocol").text
            port_elem = s.find(".//destinationPort/port")
            if port_elem is not None:
                services.append(port_elem.text)
            # port_ref = s.find(".//destinationPort/portRefGID")
            # if port_elem is not None:
            #     print(f"Service: {protocol}, Port: {port_elem.text}")
            # elif port_elem is not None:
            #     print(f"Service: {protocol}, Port: {port_ref.text}")
        rule_obj = Rule(
            rule_number=rule_id,
            source_objects=sources,
            destination_objects=destinations,
            destination_services=services
        )
        #     print("print this rule")
        #     print(ET.tostring(rule, encoding='unicode'))
        rules.append(rule_obj)
    return rules


def extractPorts(gid):
    gid_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<n:getPolicyObjectByGID xmlns:n="csm">
    <protVersion>1.0</protVersion>
    <reqId>123456</reqId>
    <gid>{gid}</gid>
</n:getPolicyObjectByGID>""".strip()
    try:
        response = session.post(f"{base_url}/configservice/getPolicyObjectByGID",
                                data=gid_xml, headers=headers, verify=False)
        if response.status_code != 200:
            print("response Failed")
            return set()
        root = ET.fromstring(response.text)
    except Exception:
        print("exception Failed")
        return set()
    all_ports = set()
    obj = root.find("policyObject")
    if obj is None:
        return all_ports
    is_group = (obj.find(".//isGroup").text == "true"
                if obj.find(".//isGroup") is not None else False)
    if is_group:
        for ref_gid in obj.findall(".//refGIDs/gid"):
            all_ports.update(extractPorts(ref_gid.text))
    # 2. חילוץ פורטים מאובייקט שירות (servicePolicyObject) [9, 10]
    obj = obj.find("servicePolicyObject")
    if obj is None:
        return all_ports
    for params in obj.findall(".//serviceParameters"):
        dest_port = params.find("destinationPort")
        if dest_port is not None:
            # פורט ישיר (Literal Port) [9]
            port_val = dest_port.find("port")
            if port_val is not None:
                all_ports.add(port_val.text)
            # הפניה לרשימת פורטים (portRefGID) - רקורסיה [9, 10]
            port_ref = dest_port.find("portRefGID")
            if port_ref is not None:
                all_ports.update(extractPorts(port_ref.text))
    # 3. חילוץ מערכים של רשימת פורטים (portListPolicyObject) [11, 12]
    # obj = obj.find("portListPolicyObject")
    # המקורות מציינים שפורטים נמצאים תחת startPort ו-endPort [11, 12]
    # for port_entry in obj.findall("port"):
    #     start = port_entry.find(".//startPort/portNum")
    #     end = port_entry.find(".//endPort/portNum")
    #     if start is not None and end is not None:
    #         val = start.text if start.text == end.text else f"{start.text}-{end.text}"
    #         all_ports.add(val)
    return all_ports


def logout():
    logout_payload = f"""<?xml version="1.0" encoding="UTF-8"?>
<csm:logoutRequest xmlns:csm="csm">
    <protVersion>1.0</protVersion>
    <reqId>145</reqId>
</csm:logoutRequest>"""
    headers = {'Content-Type': 'text/xml'}
    try:
        logoutresponse = session.post(f"{base_url}/logout", data=logout_payload,
                                      headers=headers, verify=False)
        if logoutresponse.status_code == 200:
            print("logout success")
    except Exception as e:
        print(f"Error:{e}")


# print(extractPorts(gid_number))
# print(getPolicyList(gid_number))
# name = getNameByGID(gid_number)
# print("\n----------------- GID Name -----------------")
# print(name)
# list = getPolicyList(gid, login(csm_username, csm_password))
# print("\n----------------- Policy List -----------------")
# print(list)
# print(getGIDByName(Device))
# logout()
# policy = getPolicy(policy_name)
# print(PolicyRules(policy))
# logout()
