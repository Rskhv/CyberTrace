"""Create administrator Ed25519 keys or sign a tightly scoped scan manifest."""
import argparse
import json
from pathlib import Path
from .crypto import create_scan_authorization, generate_ed25519_keypair

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True)
    key=sub.add_parser("keygen"); key.add_argument("--private",required=True); key.add_argument("--public",required=True)
    auth=sub.add_parser("authorize"); auth.add_argument("--private",required=True); auth.add_argument("--signer-id",required=True)
    auth.add_argument("--scanner-id",required=True); auth.add_argument("--target",required=True); auth.add_argument("--subnet",required=True)
    auth.add_argument("--ports",required=True); auth.add_argument("--protocols",default="TCP"); auth.add_argument("--scan-types",default="SYN")
    auth.add_argument("--environment",default="lab"); auth.add_argument("--ttl-seconds",type=int,default=900); auth.add_argument("--output",required=True)
    a=p.parse_args()
    if a.command=="keygen": generate_ed25519_keypair(a.private,a.public); print("Ed25519 key pair created."); return
    bundle=create_scan_authorization(signer_id=a.signer_id,private_key_pem=Path(a.private).read_bytes(),scanner_id=a.scanner_id,
        target_ip=a.target,permitted_subnet=a.subnet,permitted_ports=[int(x) for x in a.ports.split(",")],
        protocols=a.protocols.split(","),scan_types=a.scan_types.split(","),environment=a.environment,ttl_seconds=a.ttl_seconds)
    Path(a.output).write_text(json.dumps(bundle,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    print(f"Signed authorization written: {a.output}")

if __name__=="__main__": main()
