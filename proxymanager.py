#!/usr/bin/env python3
"""AWS rotating SOCKS5 proxy manager.

A single boto3 control plane that replaces the old bash/SSH scripts:

  deploy   Launch tagged Dante SOCKS5 nodes (self-configuring via user-data,
           latest Ubuntu AMI resolved from SSM, no SSH / no key files).
  status   Show every managed node and its current public IPv4.
  rotate   Give each node a fresh public IPv4. Runs once, or on a fixed
           interval (seconds) for manual "rotate now" or scheduled rotation.
  destroy  Terminate managed nodes and release their Elastic IPs.

Everything is scoped by an instance tag so the tool never touches unrelated
resources in the account. State is mirrored to state.json for quick reads.

Usage examples:
  python proxymanager.py deploy  --regions us-east-1 us-west-2 --count 1
  python proxymanager.py status
  python proxymanager.py rotate                      # one rotation, all nodes
  python proxymanager.py rotate --interval 300       # every 5 min, forever
  python proxymanager.py rotate --interval 60 --count 10
  python proxymanager.py destroy --regions us-east-1
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover
    sys.exit("boto3 is required. Install with: pip install -r requirements.txt")

HERE = Path(__file__).resolve().parent
CONFIG_PATH = HERE / "config.json"
STATE_PATH = HERE / "state.json"

DEFAULT_CONFIG = {
    "regions": ["us-east-1", "us-east-2", "us-west-1", "us-west-2"],
    "instance_type": "t3.micro",
    "socks_port": 1080,
    # Tag used to identify resources this tool owns.
    "tag_key": "app",
    "tag_value": "rotating-socks-proxy",
    # Ubuntu 24.04 LTS AMI, resolved per-region at launch time from SSM.
    "ssm_ami_parameter": "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id",
    # Optional SOCKS5 username/password. Leave blank for no-auth (SG-locked).
    "proxy_user": "",
    "proxy_pass": "",
    # Extra CIDRs allowed to reach the SOCKS port, in addition to your
    # detected public IP. e.g. ["203.0.113.4/32"].
    "extra_allowed_cidrs": [],
    "aws_profile": "",
    # IP-history log sync. Token is read from the GITHUB_TOKEN env var first,
    # then from github_token below. Needs "Contents: Read and write" on the repo.
    "github_repo": "karthikc1/AWSProxy",
    "github_log_path": "ip_history.txt",
    "github_token": "",
    # Browser control panel (webpanel.py) login.
    "web_user": "admin",
    "web_pass": "Ripeki@2026",
    "web_port": 8080,
    # When true, the gateway also self-hosts the web panel (port locked to your IPs).
    "host_panel": False,
    # Optional: route the gateway endpoint through an upstream SOCKS5 proxy
    # (e.g. "socks5://user:pass@geo.iproyal.com:11227"). Empty = use the node pool.
    "upstream_proxy": "",
}

IP_LOG_PATH = HERE / "ip_history.json"

SG_NAME = "rotating-socks-proxy-sg"

# Gateway: a small always-on node with a permanent EIP that relays to the
# rotating pool over private IPs, giving one constant public endpoint.
GATEWAY_TAG_VALUE = "rotating-socks-proxy-gateway"
GATEWAY_SG_NAME = "rotating-socks-proxy-gateway-sg"
GATEWAY_ROLE_NAME = "rotating-socks-proxy-gateway-role"
GATEWAY_PROFILE_NAME = "rotating-socks-proxy-gateway-profile"

# Tag that pins the gateway to a single node. When one node carries
# {PIN_TAG_KEY: "true"}, the gateway routes all traffic only to it; otherwise
# it round-robins across every running node.
PIN_TAG_KEY = "gw-pin"


# --------------------------------------------------------------------------- #
# config / state helpers
# --------------------------------------------------------------------------- #
def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.exists():
        cfg.update(json.loads(CONFIG_PATH.read_text()))
    return cfg


def load_state() -> dict:
    if STATE_PATH.exists():
        return json.loads(STATE_PATH.read_text())
    return {"nodes": {}}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2))


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def session(cfg: dict):
    if cfg.get("aws_profile"):
        return boto3.Session(profile_name=cfg["aws_profile"])
    return boto3.Session()


def ec2(sess, region):
    return sess.client("ec2", region_name=region)


def tag_filters(cfg: dict):
    return [{"Name": f"tag:{cfg['tag_key']}", "Values": [cfg["tag_value"]]}]


def my_public_ip() -> str:
    for url in ("https://checkip.amazonaws.com", "https://api.ipify.org"):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                return r.read().decode().strip()
        except Exception:
            continue
    raise RuntimeError("Could not determine your public IP for the security group.")


# --------------------------------------------------------------------------- #
# provisioning
# --------------------------------------------------------------------------- #
def build_user_data(cfg: dict) -> str:
    """Cloud-init that installs and configures Dante on first boot.

    The external interface is detected at runtime (no hardcoded enX0/eth0),
    which was a frequent breakage in the old scripts.
    """
    port = cfg["socks_port"]
    user = cfg.get("proxy_user") or ""
    pw = cfg.get("proxy_pass") or ""
    auth_method = "username" if user else "none"

    add_user = ""
    if user:
        add_user = (
            f'useradd -M -N -s /usr/sbin/nologin "{user}" || true\n'
            f'echo "{user}:{pw}" | chpasswd\n'
        )

    return f"""#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y dante-server
IFACE=$(ip route get 8.8.8.8 | awk '{{print $5; exit}}')
{add_user}
cat >/etc/danted.conf <<CONF
logoutput: syslog
internal: 0.0.0.0 port = {port}
external: $IFACE
socksmethod: {auth_method}
user.privileged: root
user.unprivileged: nobody
client pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
}}
socks pass {{
    from: 0.0.0.0/0 to: 0.0.0.0/0
}}
CONF
# Memory guard for tiny instances (carried over from the old setup).
if ! swapon --show | grep -q /swapfile; then
    fallocate -l 1G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    echo '/swapfile none swap sw 0 0' >>/etc/fstab
fi
systemctl enable danted
systemctl restart danted
"""


def resolve_ami(client, cfg: dict, region: str) -> str:
    ssm = session(cfg).client("ssm", region_name=region)
    return ssm.get_parameter(Name=cfg["ssm_ami_parameter"])["Parameter"]["Value"]


def ensure_security_group(client, cfg: dict, allowed_cidrs: list[str]) -> str:
    """Create/find the SG and make sure the SOCKS port is open to allowed_cidrs."""
    resp = client.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [SG_NAME]}]
    )
    if resp["SecurityGroups"]:
        sg_id = resp["SecurityGroups"][0]["GroupId"]
    else:
        sg_id = client.create_security_group(
            GroupName=SG_NAME,
            Description="Rotating SOCKS5 proxy access",
            TagSpecifications=[{
                "ResourceType": "security-group",
                "Tags": [{"Key": cfg["tag_key"], "Value": cfg["tag_value"]}],
            }],
        )["GroupId"]

    for cidr in allowed_cidrs:
        try:
            client.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "tcp",
                    "FromPort": cfg["socks_port"],
                    "ToPort": cfg["socks_port"],
                    "IpRanges": [{"CidrIp": cidr, "Description": "socks5 client"}],
                }],
            )
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                raise
    return sg_id


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_deploy(cfg: dict, args) -> None:
    regions = args.regions or cfg["regions"]
    allowed = [f"{my_public_ip()}/32"] + list(cfg.get("extra_allowed_cidrs", []))
    print(f"Allowing SOCKS clients from: {', '.join(allowed)}")

    def deploy_region(region: str):
        client = ec2(session(cfg), region)
        ami = resolve_ami(client, cfg, region)
        sg_id = ensure_security_group(client, cfg, allowed)
        resp = client.run_instances(
            ImageId=ami,
            InstanceType=cfg["instance_type"],
            MinCount=args.count,
            MaxCount=args.count,
            SecurityGroupIds=[sg_id],
            UserData=build_user_data(cfg),
            TagSpecifications=[{
                "ResourceType": "instance",
                "Tags": [
                    {"Key": cfg["tag_key"], "Value": cfg["tag_value"]},
                    {"Key": "Name", "Value": f"socks-proxy-{region}"},
                ],
            }],
        )
        ids = [i["InstanceId"] for i in resp["Instances"]]
        client.get_waiter("instance_running").wait(InstanceIds=ids)
        return region, ami, ids

    results = run_parallel(regions, deploy_region)
    state = load_state()
    for region, ami, ids in results:
        print(f"[{region}] launched {len(ids)} node(s) from {ami}: {', '.join(ids)}")
        for iid in ids:
            state["nodes"][iid] = {
                "region": region, "public_ip": None,
                "history": [], "updated": now_iso(),
            }
    save_state(state)
    print("\nNodes are self-configuring Dante via user-data (~60-90s).")
    print("Run:  python proxymanager.py status")


def list_nodes(cfg: dict, regions: list[str]):
    """Return {region: [instance dicts]} for running/pending managed nodes."""
    out = {}

    def fetch(region):
        client = ec2(session(cfg), region)
        resp = client.describe_instances(
            Filters=tag_filters(cfg) + [
                {"Name": "instance-state-name",
                 "Values": ["pending", "running", "stopping", "stopped"]},
            ]
        )
        nodes = [i for r in resp["Reservations"] for i in r["Instances"]]
        return region, nodes

    for region, nodes in run_parallel(regions, fetch):
        if nodes:
            out[region] = nodes
    return out


def discover_node_regions(cfg: dict) -> list[str]:
    """Scan every EC2 region for managed pool nodes.

    Lets the hosted panel show nodes deployed outside config.regions (e.g. a new
    ap-southeast-1 node) without redeploying the gateway."""
    sess = session(cfg)
    try:
        regions = [r["RegionName"] for r in sess.client("ec2").describe_regions()["Regions"]]
    except ClientError:
        return []

    def probe(region: str):
        try:
            client = ec2(sess, region)
            resp = client.describe_instances(
                Filters=tag_filters(cfg) + [
                    {"Name": "instance-state-name",
                     "Values": ["pending", "running"]},
                ])
            if any(r["Instances"] for r in resp["Reservations"]):
                return region
        except ClientError:
            pass
        return None

    found = []
    with ThreadPoolExecutor(max_workers=min(16, max(1, len(regions)))) as pool:
        for hit in pool.map(probe, regions):
            if hit:
                found.append(hit)
    return sorted(found)


def managed_regions(cfg: dict) -> list[str]:
    """Config regions plus any region that currently has pool nodes."""
    discovered = discover_node_regions(cfg)
    seen, out = set(), []
    for r in list(cfg.get("regions", [])) + discovered:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def cmd_status(cfg: dict, args) -> None:
    regions = args.regions or cfg["regions"]
    by_region = list_nodes(cfg, regions)
    state = load_state()
    port = cfg["socks_port"]

    header = f"{'Region':<12} {'Instance ID':<21} {'State':<10} {'Public IPv4':<16} Proxy"
    print(header)
    print("-" * len(header))
    total = 0
    for region, nodes in sorted(by_region.items()):
        for i in nodes:
            total += 1
            iid = i["InstanceId"]
            st = i["State"]["Name"]
            ip = i.get("PublicIpAddress", "-")
            proxy = f"{ip}:{port}" if ip != "-" else "-"
            print(f"{region:<12} {iid:<21} {st:<10} {ip:<16} {proxy}")
            node = state["nodes"].setdefault(iid, {"region": region, "history": []})
            node["public_ip"] = i.get("PublicIpAddress")
            node["updated"] = now_iso()
    save_state(state)
    if total == 0:
        print("(no managed nodes found)")


def _release_dangling_eips(client, cfg):
    """Release unassociated EIPs so we don't hit the per-region address cap."""
    addrs = client.describe_addresses()["Addresses"]
    for a in addrs:
        if "AssociationId" not in a and "AllocationId" in a:
            try:
                client.release_address(AllocationId=a["AllocationId"])
            except ClientError:
                pass


# --------------------------------------------------------------------------- #
# IP history log + GitHub sync (so we never reuse an address)
# --------------------------------------------------------------------------- #
def load_ip_log() -> dict:
    if IP_LOG_PATH.exists():
        try:
            return json.loads(IP_LOG_PATH.read_text())
        except json.JSONDecodeError:
            pass
    return {"records": []}


def save_ip_log(log: dict) -> None:
    IP_LOG_PATH.write_text(json.dumps(log, indent=2))


def seen_ips(log: dict) -> set[str]:
    return {r["ip"] for r in log.get("records", [])}


def ip_log_text(log: dict) -> str:
    """Remote log = just the unique IPs, one per line (compact, fast to diff)."""
    seen, lines = set(), []
    for r in log.get("records", []):
        ip = r["ip"]
        if ip not in seen:
            seen.add(ip)
            lines.append(ip)
    return "\n".join(lines) + "\n"


def _gh_headers(cfg: dict | None = None):
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token and cfg:
        token = (cfg.get("github_token") or "").strip()
    if not token:
        return None
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "proxymanager",
    }


def github_pull_ips(cfg: dict) -> set[str]:
    """Merge previously-logged IPs from the remote repo into our avoid-set."""
    headers = _gh_headers(cfg)
    repo, path = cfg.get("github_repo"), cfg.get("github_log_path")
    if not (headers and repo and path):
        return set()
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.load(r)
        content = base64.b64decode(data["content"]).decode()
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"[log] github pull warning: {e}")
        return set()
    except Exception as e:
        print(f"[log] github pull warning: {e}")
        return set()
    ips = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("timestamp", "ip")):
            continue
        # Accept plain "ip" lines and legacy "ts,region,instance,ip" rows.
        ips.add(line.split(",")[-1].strip())
    return ips


def github_push_log(cfg: dict, log: dict) -> None:
    headers = _gh_headers(cfg)
    repo, path = cfg.get("github_repo"), cfg.get("github_log_path")
    if not headers:
        print("[log] no github token (env or config); saved locally only.")
        return
    if not (repo and path):
        return
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    sha = None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                    timeout=10) as r:
            sha = json.load(r).get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"[log] github sha lookup warning: {e}")
    body = {
        "message": f"update ip history {now_iso()}",
        "content": base64.b64encode(ip_log_text(log).encode()).decode(),
    }
    if sha:
        body["sha"] = sha
    put = urllib.request.Request(url, data=json.dumps(body).encode(), method="PUT",
                                 headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(put, timeout=15):
            print(f"[log] synced {len(log.get('records', []))} IPs to "
                  f"github.com/{repo} ({path})")
    except urllib.error.HTTPError as e:
        print(f"[log] github push failed: {e.code} {e.read().decode()[:200]}")


def github_put_file(cfg: dict, path: str, content: bytes, message: str) -> bool:
    """Create/update an arbitrary file in the repo (used to ship code to the gateway)."""
    headers = _gh_headers(cfg)
    repo = cfg.get("github_repo")
    if not (headers and repo):
        print("[push] no github token/repo configured.")
        return False
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    sha = None
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                    timeout=10) as r:
            sha = json.load(r).get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"[push] sha lookup warning: {e}")
    body = {"message": message, "content": base64.b64encode(content).decode()}
    if sha:
        body["sha"] = sha
    put = urllib.request.Request(url, data=json.dumps(body).encode(), method="PUT",
                                 headers={**headers, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(put, timeout=20):
            return True
    except urllib.error.HTTPError as e:
        print(f"[push] failed for {path}: {e.code} {e.read().decode()[:200]}")
        return False


def cmd_push_code(cfg: dict, args) -> None:
    """Upload the tool's code to the repo so a hosted gateway can self-install it."""
    for fname in ("proxymanager.py", "webpanel.py"):
        p = HERE / fname
        if not p.exists():
            print(f"  {fname}: missing locally, skipped")
            continue
        ok = github_put_file(cfg, fname, p.read_bytes(), f"deploy {fname} {now_iso()}")
        print(f"  {fname}: {'pushed' if ok else 'FAILED'}")


def allocate_fresh(client, cfg, avoid: set[str], lock: threading.Lock, tries: int = 6):
    """Allocate an EIP not already in `avoid`, reserving it atomically so
    parallel rotations never pick the same address. Always returns a
    still-allocated address (never one we've released)."""
    fallback = None
    for _ in range(tries):
        try:
            alloc = client.allocate_address(Domain="vpc")
        except ClientError as e:
            if e.response["Error"]["Code"] == "AddressLimitExceeded":
                _release_dangling_eips(client, cfg)
                alloc = client.allocate_address(Domain="vpc")
            else:
                raise
        ip = alloc["PublicIp"]
        with lock:
            free = ip not in avoid
            if free:
                avoid.add(ip)  # reserve immediately
        if free:
            if fallback:
                try:
                    client.release_address(AllocationId=fallback["AllocationId"])
                except ClientError:
                    pass
            return alloc
        if fallback:
            try:
                client.release_address(AllocationId=fallback["AllocationId"])
            except ClientError:
                pass
        fallback = alloc
    if fallback:
        with lock:
            avoid.add(fallback["PublicIp"])
    return fallback


def rotate_instance(client, cfg, instance, avoid: set[str], lock: threading.Lock) -> tuple[str, str, str]:
    """Allocate a fresh (unused) EIP, associate it (replacing the current IP),
    release the old EIP. Returns (instance_id, old_ip, new_ip)."""
    iid = instance["InstanceId"]
    old_ip = instance.get("PublicIpAddress")

    # Note the current EIP allocation (if any) so we can release it after.
    # One lookup; a plain (non-EIP) public IP simply returns nothing.
    old_alloc = None
    if old_ip:
        try:
            addrs = client.describe_addresses(PublicIps=[old_ip])["Addresses"]
            if addrs:
                old_alloc = addrs[0].get("AllocationId")
        except ClientError:
            pass

    alloc = allocate_fresh(client, cfg, avoid, lock)
    client.associate_address(
        AllocationId=alloc["AllocationId"],
        InstanceId=iid,
        AllowReassociation=True,
    )
    new_ip = alloc["PublicIp"]

    if old_alloc:
        try:
            client.release_address(AllocationId=old_alloc)
        except ClientError:
            pass
    return iid, old_ip or "-", new_ip


def _collect_running(cfg: dict, regions: list[str]) -> list[tuple[str, dict]]:
    """Flat list of (region, instance) for running pool nodes."""
    out = []
    for region, nodes in list_nodes(cfg, regions).items():
        for node in nodes:
            if node["State"]["Name"] == "running":
                out.append((region, node))
    return out


def _rotate_targets(cfg: dict, targets: list[tuple[str, dict]]) -> None:
    """Rotate the given nodes, avoiding any IP we've ever logged (local + remote),
    record the new IPs, and sync the log to GitHub."""
    if not targets:
        print("No running nodes to rotate.")
        return

    log = load_ip_log()
    avoid = seen_ips(log) | github_pull_ips(cfg)
    # Also avoid IPs currently held by any running node, so an address one node
    # releases mid-batch can't immediately be handed to another.
    for _region, _nodes in list_nodes(cfg, list({r for r, _ in targets})).items():
        for _n in _nodes:
            if _n.get("PublicIpAddress"):
                avoid.add(_n["PublicIpAddress"])

    lock = threading.Lock()

    def work(region, node):
        iid = node["InstanceId"]
        try:
            client = ec2(session(cfg), region)
            return region, rotate_instance(client, cfg, node, avoid, lock)
        except ClientError as e:
            return region, (iid, "-", f"FAILED:{e.response['Error']['Code']}")

    # Parallel across nodes; the reserve-under-lock in allocate_fresh keeps
    # dedup correct while cutting wall time to roughly one node's duration.
    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(targets))) as pool:
        futs = [pool.submit(work, r, n) for r, n in targets]
        for fut in as_completed(futs):
            results.append(fut.result())

    state = load_state()
    new_entries = []
    for region, (iid, old_ip, new_ip) in results:
        if new_ip.startswith("FAILED:"):
            print(f"  {iid}: rotation failed ({new_ip[7:]}), skipped")
            continue
        print(f"  {iid}: {old_ip} -> {new_ip}")
        new_entries.append({"ts": now_iso(), "region": region,
                            "instance": iid, "ip": new_ip})
        n = state["nodes"].setdefault(iid, {"history": []})
        n["region"] = region
        n["public_ip"] = new_ip
        n.setdefault("history", []).append(new_ip)
        n["updated"] = now_iso()

    save_state(state)
    log.setdefault("records", []).extend(new_entries)
    save_ip_log(log)
    github_push_log(cfg, log)


def _rotate_once(cfg: dict, regions: list[str]) -> None:
    _rotate_targets(cfg, _collect_running(cfg, regions))


def _is_pinned(node: dict) -> bool:
    return any(t["Key"] == PIN_TAG_KEY and t["Value"] == "true"
               for t in node.get("Tags", []))


def clear_pin(cfg: dict, regions: list[str]) -> None:
    """Remove the pin tag from every node in the given regions."""
    for region in regions:
        client = ec2(session(cfg), region)
        resp = client.describe_instances(Filters=tag_filters(cfg) + [
            {"Name": f"tag:{PIN_TAG_KEY}", "Values": ["true"]}])
        ids = [i["InstanceId"] for r in resp["Reservations"] for i in r["Instances"]]
        if ids:
            client.delete_tags(Resources=ids, Tags=[{"Key": PIN_TAG_KEY}])


def set_pin(cfg: dict, region: str, instance_id: str) -> None:
    """Pin the gateway to a single node: tag it and clear the tag elsewhere."""
    clear_pin(cfg, [region])
    client = ec2(session(cfg), region)
    client.create_tags(Resources=[instance_id],
                       Tags=[{"Key": PIN_TAG_KEY, "Value": "true"}])


def cmd_menu(cfg: dict, args) -> None:
    regions = getattr(args, "regions", None) or cfg["regions"]
    while True:
        targets = _collect_running(cfg, regions)
        if not targets:
            print("No running nodes found. Deploy some first.")
            return
        gw = load_state().get("gateway") or {}
        eip = resolve_gateway_eip(cfg)
        endpoint = f"{eip}:{cfg['socks_port']}" if eip else "—"
        pinned_ip = next((n.get("PublicIpAddress") for _, n in targets
                          if _is_pinned(n)), None)
        mode = f"pinned -> {pinned_ip}" if pinned_ip else "round-robin"

        id_w = max((len(n["InstanceId"]) for _, n in targets), default=11)
        n_max = len(targets)

        print()
        print("  AWS Rotating SOCKS5 Proxy")
        print(f"  endpoint  {endpoint}")
        print(f"  mode      {mode}")
        print()
        print(f"  {'#':<3}{'node':<{id_w + 2}}exit ip")
        print(f"  {'-' * (3 + id_w + 2 + 15)}")
        for i, (region, n) in enumerate(targets, 1):
            tag = "   * pinned" if _is_pinned(n) else ""
            print(f"  {i:<3}{n['InstanceId']:<{id_w + 2}}"
                  f"{n.get('PublicIpAddress', '-')}{tag}")
        print()
        print(f"  rotate   1-{n_max} one    a all")
        print(f"  pin      p1-p{n_max} set   u off")
        print("  l log    r refresh    q quit")
        choice = input("  > ").strip().lower()

        if choice == "q":
            break
        elif choice == "r":
            continue
        elif choice == "u":
            clear_pin(cfg, list({r for r, _ in targets}))
            print("Unpinned. Gateway will round-robin again within ~10s.")
        elif choice == "a":
            print(f"Rotating all @ {now_iso()}")
            _rotate_targets(cfg, targets)
        elif choice == "l":
            log = load_ip_log()
            recs = log.get("records", [])
            print(f"{len(recs)} IP(s) logged. Last 10:")
            for r in recs[-10:]:
                print(f"  {r['ts']}  {r['region']}  {r['instance']}  {r['ip']}")
        elif choice.startswith("p") and choice[1:].isdigit() \
                and 1 <= int(choice[1:]) <= len(targets):
            region, n = targets[int(choice[1:]) - 1]
            set_pin(cfg, region, n["InstanceId"])
            print(f"Pinned gateway exit to {n['InstanceId']} "
                  f"({n.get('PublicIpAddress', '-')}). Active within ~10s.")
        elif choice.isdigit() and 1 <= int(choice) <= len(targets):
            sel = targets[int(choice) - 1]
            print(f"Rotating {sel[1]['InstanceId']} @ {now_iso()}")
            _rotate_targets(cfg, [sel])
        else:
            print("Invalid choice.")


def cmd_rotate(cfg: dict, args) -> None:
    regions = args.regions or cfg["regions"]
    if not args.interval:
        print(f"Rotating IPv4 for all nodes @ {now_iso()}")
        _rotate_once(cfg, regions)
        return

    cycle = 0
    while True:
        cycle += 1
        print(f"\nRotation #{cycle} @ {now_iso()}")
        _rotate_once(cfg, regions)
        if args.count and cycle >= args.count:
            break
        print(f"Sleeping {args.interval}s...")
        time.sleep(args.interval)


def cmd_destroy(cfg: dict, args) -> None:
    regions = args.regions or cfg["regions"]
    by_region = list_nodes(cfg, regions)
    if not by_region and not args.yes:
        print("No managed nodes found.")
        return
    if not args.yes:
        total = sum(len(v) for v in by_region.values())
        ans = input(f"Terminate {total} node(s) and release their EIPs? [y/N] ")
        if ans.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    state = load_state()
    for region, nodes in by_region.items():
        client = ec2(session(cfg), region)
        ids = [n["InstanceId"] for n in nodes]
        # Release EIPs attached to these nodes.
        for n in nodes:
            ip = n.get("PublicIpAddress")
            if ip:
                addrs = client.describe_addresses(
                    Filters=[{"Name": "instance-id", "Values": [n["InstanceId"]]}]
                )["Addresses"]
                for a in addrs:
                    if "AllocationId" in a:
                        try:
                            client.release_address(AllocationId=a["AllocationId"])
                        except ClientError:
                            pass
        client.terminate_instances(InstanceIds=ids)
        print(f"[{region}] terminated: {', '.join(ids)}")
        for iid in ids:
            state["nodes"].pop(iid, None)
    save_state(state)


# --------------------------------------------------------------------------- #
# gateway: constant public endpoint in front of the rotating pool
# --------------------------------------------------------------------------- #
_GW_FORWARDER_BODY = r'''
_lock = threading.Lock()
_targets = []
_rr = itertools.cycle([])


def refresh():
    global _targets, _rr
    ec2 = boto3.client("ec2", region_name=REGION)
    resp = ec2.describe_instances(Filters=[
        {"Name": "tag:" + TAG_KEY, "Values": [TAG_VALUE]},
        {"Name": "instance-state-name", "Values": ["running"]},
    ])
    insts = [i for r in resp["Reservations"] for i in r["Instances"]
             if i.get("PrivateIpAddress")]

    def is_pinned(i):
        return any(t["Key"] == PIN_TAG_KEY and t["Value"] == "true"
                   for t in i.get("Tags", []))

    pinned = [i for i in insts if is_pinned(i)]
    chosen = pinned if pinned else insts
    ips = [i["PrivateIpAddress"] for i in chosen]
    with _lock:
        if ips != _targets:
            _targets = ips
            _rr = itertools.cycle(ips) if ips else itertools.cycle([])
            print("targets:", ips, "(pinned)" if pinned else "(all)", flush=True)


def pick():
    with _lock:
        if not _targets:
            return None
        return next(_rr)


def pipe(a, b):
    try:
        while True:
            data = a.recv(BUFSIZE)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client):
    target = pick()
    if not target:
        client.close()
        return
    try:
        upstream = socket.create_connection((target, NODE_PORT), timeout=10)
    except OSError:
        client.close()
        return
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()


def refresher():
    while True:
        try:
            refresh()
        except Exception as e:
            print("refresh error:", e, flush=True)
        time.sleep(10)


def main():
    try:
        refresh()
    except Exception as e:
        print("initial refresh error:", e, flush=True)
    threading.Thread(target=refresher, daemon=True).start()
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(256)
    print("listening on", LISTEN, flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


main()
'''


def build_gateway_forwarder(cfg: dict, region: str) -> str:
    port = cfg["socks_port"]
    header = (
        "#!/usr/bin/env python3\n"
        "import socket, threading, itertools, time\n"
        "import boto3\n"
        f'REGION = "{region}"\n'
        f'TAG_KEY = "{cfg["tag_key"]}"\n'
        f'TAG_VALUE = "{cfg["tag_value"]}"\n'
        f'PIN_TAG_KEY = "{PIN_TAG_KEY}"\n'
        f"NODE_PORT = {port}\n"
        f'LISTEN = ("0.0.0.0", {port})\n'
        "BUFSIZE = 65536\n"
    )
    return header + _GW_FORWARDER_BODY


def build_upstream_relay(cfg: dict) -> str:
    """A self-contained SOCKS5 server that forwards every CONNECT through an
    authenticated upstream SOCKS5 proxy (e.g. IProyal). Runs on the gateway in
    place of the plain forwarder, so the public endpoint exits via the upstream
    while nothing else in the fleet changes. Reverting = clear upstream_proxy."""
    u = urllib.parse.urlparse(cfg["upstream_proxy"])
    host, port = u.hostname, u.port
    user = urllib.parse.unquote(u.username or "")
    password = urllib.parse.unquote(u.password or "")
    lport = cfg["socks_port"]
    return f'''#!/usr/bin/env python3
import socket, threading
UP_HOST = "{host}"
UP_PORT = {port}
UP_USER = "{user}"
UP_PASS = "{password}"
LISTEN = ("0.0.0.0", {lport})
BUFSIZE = 65536


def recvn(sock, n):
    buf = b""
    while len(buf) < n:
        d = sock.recv(n - len(buf))
        if not d:
            raise OSError("peer closed")
        buf += d
    return buf


def read_addr(sock, atyp):
    if atyp == 1:
        return recvn(sock, 4)
    if atyp == 4:
        return recvn(sock, 16)
    if atyp == 3:
        ln = recvn(sock, 1)
        return ln + recvn(sock, ln[0])
    raise OSError("bad atyp")


def pipe(a, b):
    try:
        while True:
            d = a.recv(BUFSIZE)
            if not d:
                break
            b.sendall(d)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def open_upstream(atyp, addr, port_bytes):
    up = socket.create_connection((UP_HOST, UP_PORT), timeout=15)
    up.sendall(b"\\x05\\x01\\x02")               # offer username/password
    if recvn(up, 2)[1] != 0x02:
        up.close(); raise OSError("upstream refused userpass")
    u, p = UP_USER.encode(), UP_PASS.encode()
    up.sendall(b"\\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
    if recvn(up, 2)[1] != 0x00:
        up.close(); raise OSError("upstream auth failed")
    up.sendall(b"\\x05\\x01\\x00" + bytes([atyp]) + addr + port_bytes)
    return up


def handle(client):
    up = None
    try:
        nm = recvn(client, 2)[1]
        recvn(client, nm)
        client.sendall(b"\\x05\\x00")            # no auth to our own client
        head = recvn(client, 4)                  # VER CMD RSV ATYP
        if head[1] != 0x01:                      # only CONNECT
            client.sendall(b"\\x05\\x07\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
            client.close(); return
        atyp = head[3]
        addr = read_addr(client, atyp)
        port_bytes = recvn(client, 2)
        up = open_upstream(atyp, addr, port_bytes)
        rep = recvn(up, 4)
        raddr = read_addr(up, rep[3])
        rport = recvn(up, 2)
        client.sendall(rep + raddr + rport)
        if rep[1] != 0x00:
            up.close(); client.close(); return
        threading.Thread(target=pipe, args=(client, up), daemon=True).start()
        threading.Thread(target=pipe, args=(up, client), daemon=True).start()
    except OSError:
        for s in (client, up):
            try:
                if s: s.close()
            except OSError:
                pass


def main():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(256)
    print("upstream relay on", LISTEN, "->", UP_HOST, UP_PORT, flush=True)
    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


main()
'''


def build_gateway_user_data(cfg: dict, region: str) -> str:
    script = build_upstream_relay(cfg) if cfg.get("upstream_proxy") \
        else build_gateway_forwarder(cfg, region)
    base = f"""#!/bin/bash
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3-boto3
cat >/opt/gwforward.py <<'PYEOF'
{script}
PYEOF
cat >/etc/systemd/system/gwforward.service <<'UNIT'
[Unit]
Description=SOCKS5 gateway forwarder
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 /opt/gwforward.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable gwforward
systemctl start gwforward
"""
    return base + build_panel_setup(cfg) if cfg.get("host_panel") else base


def build_panel_setup(cfg: dict) -> str:
    """Bash appended to gateway user-data: fetch code from the repo, write a
    local config, and run the web panel as a service (uses the instance role,
    so no AWS keys are stored on the box)."""
    box_cfg = dict(cfg)
    box_cfg["aws_profile"] = ""          # use the instance role
    box_cfg["host_panel"] = False        # avoid recursion if ever re-read
    cfg_json = json.dumps(box_cfg, indent=2)
    token = cfg.get("github_token", "")
    repo = cfg.get("github_repo", "")
    return f"""
apt-get install -y python3-flask curl
mkdir -p /opt/proxy
cat >/opt/proxy/config.json <<'CJSON'
{cfg_json}
CJSON
for f in proxymanager.py webpanel.py; do
  curl -fsSL -H "Authorization: Bearer {token}" \
       -H "Accept: application/vnd.github.raw" \
       "https://api.github.com/repos/{repo}/contents/$f" -o /opt/proxy/$f
done
cat >/etc/systemd/system/webpanel.service <<'UNIT'
[Unit]
Description=Proxy web control panel
After=network-online.target
Wants=network-online.target
[Service]
WorkingDirectory=/opt/proxy
ExecStart=/usr/bin/python3 /opt/proxy/webpanel.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable webpanel
systemctl start webpanel
"""


def ensure_gateway_iam(cfg: dict) -> str:
    """Create the role + instance profile granting ec2:DescribeInstances."""
    iam = session(cfg).client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    # DescribeInstances for the forwarder; the rest lets the hosted web panel
    # rotate/pin without stored AWS keys (it uses this instance role).
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeAddresses",
                "ec2:AllocateAddress",
                "ec2:AssociateAddress",
                "ec2:ReleaseAddress",
                "ec2:CreateTags",
                "ec2:DeleteTags",
            ],
            "Resource": "*",
        }],
    }
    try:
        iam.create_role(RoleName=GATEWAY_ROLE_NAME,
                        AssumeRolePolicyDocument=json.dumps(trust))
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
    iam.put_role_policy(RoleName=GATEWAY_ROLE_NAME, PolicyName="describe-instances",
                        PolicyDocument=json.dumps(policy))
    try:
        iam.create_instance_profile(InstanceProfileName=GATEWAY_PROFILE_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] != "EntityAlreadyExists":
            raise
    try:
        iam.add_role_to_instance_profile(InstanceProfileName=GATEWAY_PROFILE_NAME,
                                         RoleName=GATEWAY_ROLE_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("LimitExceeded",):
            raise
    return GATEWAY_PROFILE_NAME


def ensure_gateway_sg(client, cfg: dict, vpc_id: str) -> str:
    resp = client.describe_security_groups(
        Filters=[{"Name": "group-name", "Values": [GATEWAY_SG_NAME]},
                 {"Name": "vpc-id", "Values": [vpc_id]}])
    if resp["SecurityGroups"]:
        sg_id = resp["SecurityGroups"][0]["GroupId"]
    else:
        sg_id = client.create_security_group(
            GroupName=GATEWAY_SG_NAME, VpcId=vpc_id,
            Description="Rotating SOCKS5 gateway (public endpoint)",
            TagSpecifications=[{"ResourceType": "security-group",
                                "Tags": [{"Key": cfg["tag_key"],
                                          "Value": GATEWAY_TAG_VALUE}]}],
        )["GroupId"]
    try:
        client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": cfg["socks_port"],
                            "ToPort": cfg["socks_port"],
                            "IpRanges": [{"CidrIp": "0.0.0.0/0",
                                          "Description": "public socks endpoint"}]}])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
            raise
    return sg_id


def allow_panel_access(client, cfg: dict, gw_sg_id: str) -> list[str]:
    """Open the web panel port on the gateway SG, restricted to your IP(s)."""
    cidrs = list(dict.fromkeys(
        [f"{my_public_ip()}/32"] + list(cfg.get("extra_allowed_cidrs", []))))
    port = int(cfg.get("web_port", 8080))
    for cidr in cidrs:
        try:
            client.authorize_security_group_ingress(
                GroupId=gw_sg_id,
                IpPermissions=[{"IpProtocol": "tcp", "FromPort": port, "ToPort": port,
                                "IpRanges": [{"CidrIp": cidr,
                                              "Description": "web panel (restricted)"}]}])
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                raise
    return cidrs


def allow_gateway_to_nodes(client, cfg: dict, node_sg_id: str, gw_sg_id: str) -> None:
    """Let the gateway reach node Dante on the private network."""
    try:
        client.authorize_security_group_ingress(
            GroupId=node_sg_id,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": cfg["socks_port"],
                            "ToPort": cfg["socks_port"],
                            "UserIdGroupPairs": [{"GroupId": gw_sg_id,
                                                  "Description": "gateway relay"}]}])
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
            raise


def _find_gateway_instances(client, cfg):
    resp = client.describe_instances(
        Filters=[{"Name": f"tag:{cfg['tag_key']}", "Values": [GATEWAY_TAG_VALUE]},
                 {"Name": "instance-state-name",
                  "Values": ["pending", "running", "stopping", "stopped"]}])
    return [i for r in resp["Reservations"] for i in r["Instances"]]


def resolve_gateway_eip(cfg: dict) -> str | None:
    """Return the gateway's public EIP.

    Uses local state when present (CLI machine), otherwise queries AWS — needed
    when the web panel runs on the gateway itself and has no state.json."""
    gw = load_state().get("gateway") or {}
    if gw.get("eip"):
        return gw["eip"]

    regions = [gw["region"]] if gw.get("region") else list(cfg["regions"])
    for region in regions:
        client = ec2(session(cfg), region)
        for inst in _find_gateway_instances(client, cfg):
            if inst["State"]["Name"] != "running":
                continue
            ip = inst.get("PublicIpAddress")
            if ip:
                return ip
            addrs = client.describe_addresses(
                Filters=[{"Name": "instance-id", "Values": [inst["InstanceId"]]}])
            for a in addrs["Addresses"]:
                if a.get("PublicIp"):
                    return a["PublicIp"]
    return None


def cmd_gateway_up(cfg: dict, args) -> None:
    region = args.region or cfg["regions"][0]
    client = ec2(session(cfg), region)

    # Find an existing pool node to borrow its VPC/subnet + node SG.
    by_region = list_nodes(cfg, [region])
    nodes = by_region.get(region, [])
    running = [n for n in nodes if n["State"]["Name"] == "running"]
    if not running:
        sys.exit(f"No running pool nodes in {region}. Deploy nodes first.")
    ref = running[0]
    vpc_id = ref["VpcId"]
    subnet_id = ref["SubnetId"]
    node_sg_id = ref["SecurityGroups"][0]["GroupId"]

    # If a gateway already exists, replace it but KEEP its EIP so the public
    # endpoint stays constant across redeploys (e.g. to pick up new forwarder).
    reuse_alloc = None
    existing = _find_gateway_instances(client, cfg)
    if existing:
        for i in existing:
            addrs = client.describe_addresses(
                Filters=[{"Name": "instance-id", "Values": [i["InstanceId"]]}])
            for a in addrs["Addresses"]:
                if "AllocationId" in a:
                    reuse_alloc = a["AllocationId"]
        if not reuse_alloc:
            reuse_alloc = (load_state().get("gateway") or {}).get("allocation_id")
        old_ids = [i["InstanceId"] for i in existing]
        print(f"[{region}] replacing existing gateway {old_ids} "
              f"(keeping EIP alloc {reuse_alloc})")
        client.terminate_instances(InstanceIds=old_ids)
        client.get_waiter("instance_terminated").wait(InstanceIds=old_ids)

    print(f"[{region}] gateway in vpc={vpc_id} subnet={subnet_id}")
    profile = ensure_gateway_iam(cfg)
    gw_sg = ensure_gateway_sg(client, cfg, vpc_id)
    allow_gateway_to_nodes(client, cfg, node_sg_id, gw_sg)
    panel_cidrs = allow_panel_access(client, cfg, gw_sg) if cfg.get("host_panel") else []

    ami = resolve_ami(client, cfg, region)
    # IAM instance profiles are eventually consistent; retry the launch.
    last_err = None
    for _ in range(12):
        try:
            resp = client.run_instances(
                ImageId=ami, InstanceType=cfg["instance_type"],
                MinCount=1, MaxCount=1,
                SecurityGroupIds=[gw_sg], SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile},
                UserData=build_gateway_user_data(cfg, region),
                TagSpecifications=[{"ResourceType": "instance",
                                    "Tags": [{"Key": cfg["tag_key"],
                                              "Value": GATEWAY_TAG_VALUE},
                                             {"Key": "Name",
                                              "Value": f"socks-gateway-{region}"}]}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValue" \
                    and "Instance Profile" in str(e):
                last_err = e
                time.sleep(5)
                continue
            raise
    else:
        raise last_err

    gw_id = resp["Instances"][0]["InstanceId"]
    client.get_waiter("instance_running").wait(InstanceIds=[gw_id])

    if reuse_alloc:
        client.associate_address(AllocationId=reuse_alloc, InstanceId=gw_id,
                                 AllowReassociation=True)
        alloc_id = reuse_alloc
        eip = client.describe_addresses(AllocationIds=[reuse_alloc])[
            "Addresses"][0]["PublicIp"]
    else:
        alloc = client.allocate_address(Domain="vpc")
        client.associate_address(AllocationId=alloc["AllocationId"], InstanceId=gw_id,
                                 AllowReassociation=True)
        alloc_id = alloc["AllocationId"]
        eip = alloc["PublicIp"]

    state = load_state()
    state["gateway"] = {"region": region, "instance_id": gw_id, "eip": eip,
                        "allocation_id": alloc_id, "updated": now_iso()}
    save_state(state)

    print(f"\nGateway launched: {gw_id}")
    print(f"Permanent endpoint (never changes):  {eip}:{cfg['socks_port']}")
    if cfg.get("upstream_proxy"):
        up = urllib.parse.urlparse(cfg["upstream_proxy"])
        print(f"UPSTREAM MODE: exiting via {up.hostname}:{up.port} "
              "(node pool bypassed). Clear upstream_proxy to revert.")
    else:
        print("Forwarder is installing (~60-90s). It relays to the pool's private IPs,")
        print("so rotations are picked up automatically with no endpoint change.")
    if cfg.get("host_panel"):
        print(f"\nWeb panel:  http://{eip}:{cfg.get('web_port', 8080)}")
        print(f"  login: {cfg.get('web_user')} / {cfg.get('web_pass')}")
        print(f"  reachable from: {', '.join(panel_cidrs)}")
        print("  (panel self-installs from the repo ~90s after boot)")


def cmd_gateway_down(cfg: dict, args) -> None:
    state = load_state()
    gw = state.get("gateway")
    region = args.region or (gw or {}).get("region") or cfg["regions"][0]
    client = ec2(session(cfg), region)
    resp = client.describe_instances(
        Filters=[{"Name": f"tag:{cfg['tag_key']}", "Values": [GATEWAY_TAG_VALUE]},
                 {"Name": "instance-state-name",
                  "Values": ["pending", "running", "stopping", "stopped"]}])
    ids = [i["InstanceId"] for r in resp["Reservations"] for i in r["Instances"]]
    if not ids:
        print("No gateway found.")
    else:
        for r in resp["Reservations"]:
            for i in r["Instances"]:
                addrs = client.describe_addresses(
                    Filters=[{"Name": "instance-id", "Values": [i["InstanceId"]]}])
                for a in addrs["Addresses"]:
                    if "AllocationId" in a:
                        try:
                            client.release_address(AllocationId=a["AllocationId"])
                        except ClientError:
                            pass
        client.terminate_instances(InstanceIds=ids)
        print(f"[{region}] gateway terminated: {', '.join(ids)}")
    state.pop("gateway", None)
    save_state(state)


# --------------------------------------------------------------------------- #
# util
# --------------------------------------------------------------------------- #
def run_parallel(regions, fn):
    results = []
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(regions)))) as pool:
        futs = [pool.submit(fn, r) for r in regions]
        for fut in as_completed(futs):
            results.append(fut.result())
    return results


def main() -> None:
    cfg = load_config()
    p = argparse.ArgumentParser(description="AWS rotating SOCKS5 proxy manager")
    sub = p.add_subparsers(dest="cmd")

    common_regions = dict(nargs="*", metavar="REGION",
                          help="Regions to act on (default: config regions)")

    mp = sub.add_parser("menu", help="Interactive: pick a node to rotate, or all")
    mp.add_argument("--regions", **common_regions)

    dp = sub.add_parser("deploy", help="Launch Dante SOCKS5 nodes")
    dp.add_argument("--regions", **common_regions)
    dp.add_argument("--count", type=int, default=1, help="Nodes per region")

    sp = sub.add_parser("status", help="List managed nodes and IPs")
    sp.add_argument("--regions", **common_regions)

    rp = sub.add_parser("rotate", help="Rotate public IPv4 of all nodes")
    rp.add_argument("--regions", **common_regions)
    rp.add_argument("--interval", type=int, default=0,
                    help="Seconds between rotations (0 = run once)")
    rp.add_argument("--count", type=int, default=0,
                    help="Number of rotation cycles (0 = forever when --interval set)")

    xp = sub.add_parser("destroy", help="Terminate nodes and release EIPs")
    xp.add_argument("--regions", **common_regions)
    xp.add_argument("--yes", action="store_true", help="Skip confirmation")

    gu = sub.add_parser("gateway-up",
                        help="Launch/replace the constant-endpoint gateway (keeps EIP)")
    gu.add_argument("--region", metavar="REGION",
                    help="Region to place the gateway (default: first config region)")

    gr = sub.add_parser("gateway-refresh",
                        help="Redeploy the gateway forwarder, keeping the same EIP")
    gr.add_argument("--region", metavar="REGION")

    gd = sub.add_parser("gateway-down", help="Terminate the gateway and release its EIP")
    gd.add_argument("--region", metavar="REGION")

    sub.add_parser("push-code",
                   help="Upload proxymanager.py + webpanel.py to the repo (for hosted gateway)")

    args = p.parse_args()
    cmd = args.cmd or "menu"  # running with no subcommand opens the menu
    {
        "menu": cmd_menu,
        "deploy": cmd_deploy,
        "status": cmd_status,
        "rotate": cmd_rotate,
        "destroy": cmd_destroy,
        "gateway-up": cmd_gateway_up,
        "gateway-refresh": cmd_gateway_up,
        "gateway-down": cmd_gateway_down,
        "push-code": cmd_push_code,
    }[cmd](cfg, args)


if __name__ == "__main__":
    main()
