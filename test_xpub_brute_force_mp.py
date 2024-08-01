import xpub_brute_force_mp as xbf

from mnemonic import Mnemonic

from hdwallet import HDWallet as HDWallet
from hdwallet.utils import is_root_xpublic_key
from hdwallet.symbols import ETH 
from hdwallet.symbols import BTC

from rbloom import Bloom
from hashlib import sha256
from pickle import dumps

from collections.abc import Generator
base58_alphabet = '123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ'
alphabet_length = len(base58_alphabet)

def lcg(modulus: int, a: int, c: int, seed: int) -> Generator[int, None, None]:
    """Linear congruential generator."""
    while True:
        seed = (a * seed + c) % modulus
        yield seed

LCG_MOD = 2**64
LCG_A = 6364136223846793005
LCG_C = 1442695040888963407
LCG_SEED = 2**64 - 1  
LCG = lcg(LCG_MOD, LCG_A, LCG_C, LCG_SEED)

def generate_random_addr(lcgenerator, length=52):
    """Generate a pseudo-random string of a given length."""
    # Generate pseudo-random indicies
    i = 0
    random_indicies = [ next(lcgenerator) for i in range(0,length) ]
    # Build the random string by selecting characters based on the pseudo-random indexes
    random_addr = ''.join(base58_alphabet[index % alphabet_length] for index in random_indicies)
    return random_addr

def hash_func(obj):
    h = sha256(dumps(obj)).digest()
    return int.from_bytes(h[:16], "big") - 2**127

def generate_bloom_filter(size: int, false_positive_rate: float):
    bf = Bloom(size, false_positive_rate, hash_func)
    entries = 0
    i = 0 
    while i < BF_SIZE//2:
        bf.add(generate_random_addr(LCG))
        i += 1
    return bf

BF_SIZE=2**16
BF_FPR=0.00001
BF=generate_bloom_filter(BF_SIZE, BF_FPR)

def bip39_to_seed(mnemonic, passphrase="", language="english", debug=False):
    mnemo = Mnemonic(language)
    return mnemo.to_seed(mnemonic, passphrase=passphrase)

mnemonic = "violin curtain quiz situate option dress online drift deny book venture october insect cycle current trophy maze fun panic acquire meadow cancel season market"
bip39seed_bytes =  bip39_to_seed(mnemonic)

def generate_xkey_from_seed(bip39seed: bytes, dpath: str="m/44'/0'/0'/0/0", currency: str=BTC, debug: bool=False) -> (str, str):
    xkey=dict()
    # Initialize HDWallet
    hdwallet: HDWallet = HDWallet(symbol=currency)
    # Get HDWallet from seed
    hdwallet.from_seed(seed=bip39seed.hex())

    # Derivation from path
    if dpath != "m":
        hdwallet.from_path(dpath)
    # m/44'/3'/0'/0/0
    # m
    # '     Hardened derivation 
    # 44    bip-0044
    #  0    Currency 0=Bitcoin 3=Ethereum
    #  0    Account
    #  0    External = 0, Internal = 1
    #  0    Address index 
    xkey["xprv"] = hdwallet.xprivate_key()
    xkey["xpub"] = hdwallet.xpublic_key()
    xkey["root_xpub"] = hdwallet.root_xpublic_key()
    xkey["root_xprv"] = hdwallet.root_xprivate_key()

    return xkey 

def generate_xprv_from_xprv(xprv: str, dpath: str="m/44'/0'/0'/0/0", currency: str=BTC, debug: bool=False):
    hdwallet: HDWallet = HDWallet(symbol=currency)
    hdwallet.from_xprivate_key(xprivate_key=xprv)
    hdwallet.from_path(dpath)

    return hdwallet.xprivate_key()

def generate_xpub_from_xprv(xprv: str, dpath: str="m/44'/0'/0'/0/0", currency: str=BTC, debug: bool=False):
    hdwallet: HDWallet = HDWallet(symbol=currency)
    hdwallet.from_xprivate_key(xprivate_key=xprv)
    hdwallet.from_path(dpath)

    return hdwallet.xpublic_key()
    

def generate_xpub_from_xpub(xpub: str, dpath: str="m/44'/0'/0'/0/0", currency: str=BTC, debug: bool=False):
    hdwallet: HDWallet = HDWallet(symbol=currency)
    #hdwallet.from_xpublic_key(xpublic_key=xpubkey, strict=STRICT)
    hdwallet.from_xpublic_key(xpublic_key=xpub)
    
    hdwallet.from_path(dpath)

    return hdwallet.xpublic_key()  

def generate_addr_from_xpub(xpub: str, currency: str=BTC, debug: bool=False):
    hdwallet: HDWallet = HDWallet(symbol=currency)
    #hdwallet.from_xpublic_key(xpublic_key=xpubkey, strict=STRICT)
    hdwallet.from_xpublic_key(xpublic_key=xpub)

    addr = dict()
    addr["PK_compressed"] = hdwallet.compressed()
    addr["PK_uncompressed"] = hdwallet.uncompressed()
    addr["P2PKH"] = hdwallet.p2pkh_address()
    addr["P2SH"] = hdwallet.p2sh_address()
    addr["P2WPKH"] = hdwallet.p2wpkh_address()
    addr["P2WPKH_in_P2SH"] = hdwallet.p2wpkh_in_p2sh_address()
    addr["P2WSH"] = hdwallet.p2wsh_address()
    addr["P2WSH_in_P2SH"] = hdwallet.p2wsh_in_p2sh_address()

    return addr

# m / purpose' / coin_type' / account' / change / address_index
# m / 44'      / 0'         / 0'       / 0      / 0 

def test_1():

    root_xkey =  generate_xkey_from_seed(bip39seed_bytes, "m"); root_xkey
    assert root_xkey["xpub"] == root_xkey["root_xpub"]

    account_xpub =  generate_xpub_from_xprv(root_xkey["xprv"], "m/44'/0'/0'")
    assert account_xpub ==  generate_xkey_from_seed(bip39seed_bytes, "m/44'/0'/0'")["xpub"]

    addr0_xpub =  generate_xpub_from_xpub(account_xpub, "m/0/0")
    assert addr0_xpub ==  generate_xkey_from_seed(bip39seed_bytes, "m/44'/0'/0'/0/0")["xpub"]

    addr_xpub =  generate_xpub_from_xpub(account_xpub, "m/0/1337")
    assert addr_xpub ==  generate_xkey_from_seed(bip39seed_bytes, "m/44'/0'/0'/0/1337")["xpub"]

    addr =  generate_addr_from_xpub(addr_xpub)
    assert addr['P2PKH'] == "126vmB9dDizgAo3BoGT3LxCTXj1uyH3npp"

    # add address to search in filter 
    BF.add(addr["P2PKH"])
    addr_bloom="./test_gen_addr_filter.bloom" 
    BF.save(addr_bloom) # save filter

    # brute force real address
    matches = xbf.derive_full(xpub=account_xpub, der_path="m/0/", num_producer=3, addr_bloom=addr_bloom, currency=BTC, stop_after=2000)

    assert len(matches) == 1
    assert matches[0]["P2PKH"] == "126vmB9dDizgAo3BoGT3LxCTXj1uyH3npp"
    print(matches)


