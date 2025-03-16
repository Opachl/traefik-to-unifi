import os
import requests
import re

def sync():
    traefik_ip = os.environ.get("TRAEFIK_IP")
    traefik_api_url = os.environ.get("TRAEFIK_API_URL")
    unifi_url = os.environ.get("UNIFI_URL")
    unifi_username = os.environ.get("UNIFI_USERNAME")
    unifi_password = os.environ.get("UNIFI_PASSWORD")
    ignore_ssl_warnings = os.environ.get("IGNORE_SSL_WARNINGS")
    allow_dns_delete = os.environ.get("ALLOW_DNS_DELETE")

    if None in [traefik_ip, traefik_api_url, unifi_url, unifi_username, unifi_password]:
        raise ValueError("One or more required environment variables are not set.")

    print(f"The value of UNIFI_URL is: {unifi_url}")
    print(f"The value of TRAEFIK_API_URL is: {traefik_api_url}")

    traefik_routers_response = requests.get(f"{traefik_api_url}http/routers")
    if traefik_routers_response.status_code != 200:
        raise ValueError(f"Failed to request Traefik API. Status code: {traefik_routers_response.status_code}")

    traefik_domains = []
    for router in traefik_routers_response.json():
        if "rule" in router and "Host(" in router["rule"]:
            match = re.search(r"Host\(`([^`]+)`\)", router["rule"])
            if match:
                traefik_domains.append(match.group(1))

    if not traefik_domains:
        print("No DNS names found in Traefik routers.")
        return

    unifi_session = requests.Session()
    if ignore_ssl_warnings:
        requests.packages.urllib3.disable_warnings()
        unifi_session.verify = False

    unifi_login_response = unifi_session.post(
        f"{unifi_url}api/auth/login", json={"username": unifi_username, "password": unifi_password}
    )
    if unifi_login_response.status_code != 200:
        raise ValueError(f"Failed to login to Unifi API. Status code: {unifi_login_response.status_code}")

    unifi_session.headers.update({"X-Csrf-Token": unifi_login_response.headers["X-Csrf-Token"]})

    get_static_dns_entries_response = unifi_session.get(f"{unifi_url}proxy/network/v2/api/site/default/static-dns")
    if get_static_dns_entries_response.status_code != 200:
        raise ValueError(f"Failed to get static DNS entries. Status code: {get_static_dns_entries_response.status_code}")

    unifi_static_dns_entries = {entry["key"]: (entry["value"], entry["_id"]) for entry in get_static_dns_entries_response.json()}

    entries_to_update = []
    hosts_to_add = []
    entries_to_delete = []

    for dns_name in traefik_domains:
        if dns_name in unifi_static_dns_entries:
            if unifi_static_dns_entries[dns_name][0] != traefik_ip:
                entries_to_update.append((dns_name, unifi_static_dns_entries[dns_name][1]))
        else:
            hosts_to_add.append(dns_name)

    for entry in unifi_static_dns_entries:
        if entry not in traefik_domains:
            entries_to_delete.append(unifi_static_dns_entries[entry][1])

    for entry in entries_to_update:
        update_response = unifi_session.put(
            f"{unifi_url}proxy/network/v2/api/site/default/static-dns/{entry[1]}",
            json={"enabled": True, "key": entry[0], "record_type": "A", "value": traefik_ip, "_id": entry[1]},
        )
        if update_response.status_code == 200:
            print(f"Updated static DNS entry {entry[0]}")
        else:
            print(f"Failed to update {entry[0]}. Status code: {update_response.status_code}")

    for host in hosts_to_add:
        add_response = unifi_session.post(
            f"{unifi_url}proxy/network/v2/api/site/default/static-dns",
            json={"enabled": True, "key": host, "record_type": "A", "value": traefik_ip},
        )
        if add_response.status_code == 200:
            print(f"Added static DNS entry {host}")
        else:
            print(f"Failed to add {host}. Status code: {add_response.status_code}")

    if allow_dns_delete:
        for entry_id in entries_to_delete:
            delete_response = unifi_session.delete(f"{unifi_url}proxy/network/v2/api/site/default/static-dns/{entry_id}")
            if delete_response.status_code == 200:
                print(f"Deleted obsolete static DNS entry with ID {entry_id}")
            else:
                print(f"Failed to delete {entry_id}. Status code: {delete_response.status_code}")
