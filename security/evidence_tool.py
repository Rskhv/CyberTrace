"""Encrypt, fingerprint, sign, or verify a single evidence file."""
import argparse, hashlib, json
from pathlib import Path
from .crypto import create_evidence_manifest, decrypt_bytes, encrypt_bytes, verify_evidence
from .key_management import load_key

def _new_output(path: str, source: str) -> Path:
    out=Path(path)
    if out.resolve()==Path(source).resolve(): raise ValueError("output must differ from input")
    if out.exists(): raise FileExistsError(f"refusing to overwrite {out}")
    out.parent.mkdir(parents=True,exist_ok=True)
    return out

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="command",required=True)
    enc=sub.add_parser("encrypt"); enc.add_argument("--input",required=True); enc.add_argument("--output",required=True); enc.add_argument("--key-file"); enc.add_argument("--key-env",default="CYBERTRACE_EVIDENCE_KEY"); enc.add_argument("--key-id",required=True)
    dec=sub.add_parser("decrypt"); dec.add_argument("--input",required=True); dec.add_argument("--output",required=True); dec.add_argument("--key-file"); dec.add_argument("--key-env",default="CYBERTRACE_EVIDENCE_KEY")
    sign=sub.add_parser("sign"); sign.add_argument("--input",required=True); sign.add_argument("--private-key",required=True); sign.add_argument("--key-id",required=True); sign.add_argument("--output",required=True)
    verify=sub.add_parser("verify"); verify.add_argument("--input",required=True); verify.add_argument("--manifest",required=True); verify.add_argument("--public-key",required=True)
    a=p.parse_args()
    if a.command=="encrypt":
        envelope=encrypt_bytes(Path(a.input).read_bytes(),load_key(env_name=a.key_env,path=a.key_file),key_id=a.key_id)
        _new_output(a.output,a.input).write_text(json.dumps(envelope,sort_keys=True)+"\n",encoding="utf-8"); print("ENCRYPTED")
    elif a.command=="decrypt":
        data=decrypt_bytes(json.loads(Path(a.input).read_text()),load_key(env_name=a.key_env,path=a.key_file))
        _new_output(a.output,a.input).write_bytes(data); print("DECRYPTED")
    elif a.command=="sign":
        bundle=create_evidence_manifest(a.input,{},Path(a.private_key).read_bytes(),key_id=a.key_id)
        _new_output(a.output,a.input).write_text(json.dumps(bundle,sort_keys=True,indent=2)+"\n",encoding="utf-8"); print(bundle["manifest"]["sha256"])
    else:
        status=verify_evidence(a.input,json.loads(Path(a.manifest).read_text()),Path(a.public_key).read_bytes())
        print(status)
        if status!="VALID": raise SystemExit(1)

if __name__=="__main__": main()
