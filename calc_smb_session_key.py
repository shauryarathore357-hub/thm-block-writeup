#!/usr/bin/env python3
"""
Calculate the SMB2/SMB3 Random Session Key from an NTLMv2 exchange,
using either a plaintext password or an NT hash.

Based on the NTLMv2 Key Exchange Key derivation (RFC-ish, per MS-NLMP)
and the technique described in:
"Decrypting SMB3 Traffic with just a PCAP? Absolutely (maybe.)"

Usage examples:
    # With plaintext password:
    python3 calc_smb_session_key.py -u mrealman -d BLOCK -p Blockbuster1 \
        -n <NTProofStr_hex> -k <EncryptedSessionKey_hex>

    # With NT hash instead of password (when password is uncracked):
    python3 calc_smb_session_key.py -u eshellstrop -d WORKGROUP -ph <NThash_hex> \
        -n <NTProofStr_hex> -k <EncryptedSessionKey_hex>

Requires: pycryptodome
    pip install pycryptodome --break-system-packages
"""

import argparse
import hashlib
import hmac
from binascii import unhexlify, hexlify

try:
    from Crypto.Cipher import ARC4
    from Crypto.Hash import MD4
except ImportError:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Hash import MD4


def ntowfv1(password):
    """Compute NT hash (NTOWFv1) from a plaintext password."""
    md4 = MD4.new()
    md4.update(password.encode('utf-16-le'))
    return md4.digest()


def ntowfv2(nt_hash, user, domain):
    """Compute NTOWFv2 key from NT hash, username, and domain."""
    identity = (user.upper() + domain).encode('utf-16-le')
    return hmac.new(nt_hash, identity, hashlib.md5).digest()


def main():
    parser = argparse.ArgumentParser(description="Compute SMB2 Random Session Key")
    parser.add_argument('-u', '--user', required=True, help='Username')
    parser.add_argument('-d', '--domain', required=True, help='Domain')
    parser.add_argument('-p', '--password', help='Plaintext password')
    parser.add_argument('-ph', '--nthash', help='NT hash (hex string) instead of password')
    parser.add_argument('-n', '--ntproofstr', required=True, help='NTProofStr from NTLMv2 response (hex)')
    parser.add_argument('-k', '--enckey', required=True, help='Encrypted Session Key from NTLMSSP_AUTH (hex)')
    args = parser.parse_args()

    if args.password:
        nt_hash = ntowfv1(args.password)
    elif args.nthash:
        nt_hash = unhexlify(args.nthash)
    else:
        parser.error("Must supply either --password or --nthash")

    ntproofstr = unhexlify(args.ntproofstr)
    enc_session_key = unhexlify(args.enckey)

    # NTLMv2 Key Exchange Key derivation
    response_key_nt = ntowfv2(nt_hash, args.user, args.domain)
    key_exchange_key = hmac.new(response_key_nt, ntproofstr, hashlib.md5).digest()

    # RC4-decrypt the Encrypted Session Key using the Key Exchange Key to get
    # the Random Session Key (the actual SMB2 session key Wireshark needs)
    cipher = ARC4.new(key_exchange_key)
    random_session_key = cipher.decrypt(enc_session_key)

    print(f"Key Exchange Key   : {hexlify(key_exchange_key).decode()}")
    print(f"Random Session Key : {hexlify(random_session_key).decode()}")
    print()
    print("=> Use the Random Session Key above in Wireshark:")
    print("   Edit > Preferences > Protocols > SMB2 > add row with:")
    print("   - Session ID (reversed byte order, from the packet)")
    print("   - The Random Session Key printed above")


if __name__ == '__main__':
    main()
