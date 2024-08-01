
import sys

from hdwallet import HDWallet as HDWallet
from hdwallet.utils import is_root_xpublic_key
from hdwallet.symbols import ETH 
from hdwallet.symbols import BTC

from rbloom import Bloom
from hashlib import sha256
from pickle import dumps

import multiprocessing as mp
import math 

def hash_func(obj):
    h = sha256(dumps(obj)).digest()
    return int.from_bytes(h[:16], "big") - 2**127

def load_bf(path: str="./bf/btc_addr.bloom"):
    # load bloom filter
    return Bloom.load(path, hash_func)

def producer(queue, producer_id, xpub, der_path, currency, idx_range_start, idx_range_size):
    if (idx_range_start + idx_range_size) > 2**31:
        idx_range_end = 2**31
    else:
        idx_range_end = idx_range_start + idx_range_size
    print(f"Starting searching {idx_range_size} indices from {der_path}{idx_range_start} to {der_path}{(idx_range_end)} ... ", file=sys.stderr)
    assert 0 <= idx_range_start <= idx_range_end <= 2**31,"Invalid idx range given"
    hdwallet: HDWallet = HDWallet(symbol=currency)
    
    
    for idx in range(idx_range_start, idx_range_end):
        # iterate index 
        # at most from 0x80000000 to 0xffffffff
        # but hdwallet defines this range as 0 to 2**31 (non-hardened) without '

        # generate candidate address 
        hdwallet.from_xpublic_key(xpublic_key=xpub)
        hdwallet.from_path(der_path + str(idx))

        candidate = dict()
        candidate["PK_compressed"] = hdwallet.compressed()
        candidate["P2PKH"] = hdwallet.p2pkh_address()
        candidate["xpub"] = xpub
        candidate["path"] = der_path + str(idx)
        # check only P2PKH address
        # better would be to check against pk database
        #candidate["PK_compressed"] = hdwallet.compressed()
        #candidate["PK_uncompressed"] = hdwallet.uncompressed()
        #candidate["P2PKH"] = hdwallet.p2pkh_address()
        #candidate["P2SH"] = hdwallet.p2sh_address()
        #candidate["P2WPKH"] = hdwallet.p2wpkh_address()
        #candidate["P2WPKH_in_P2SH"] = hdwallet.p2wpkh_in_p2sh_address()
        #candidate["P2WSH"] = hdwallet.p2wsh_address()
        #candidate["P2WSH_in_P2SH"] = hdwallet.p2wsh_in_p2sh_address()
        queue.put(candidate)
    queue.close()
    print(f'Producer {producer_id} finished', file=sys.stderr)


def consumer(queue, result_queue, num_producer, addr_bloom, out_path=None):
    print("Loading bloom filter ...", file=sys.stderr)
    bf = load_bf(addr_bloom)

    matches = list()
    finished_producers = 0

    print("Staring checking derived addresses ...", file=sys.stderr)
    while finished_producers < num_producer:
        candidate = queue.get()
        #print(f"checking: {candidate}", file=sys.stderr)
        if candidate and isinstance(candidate, dict):
            if candidate["P2PKH"] in bf:
                print(candidate)
                matches.append(candidate)
        elif candidate and candidate == "done": # candidate is None
            finished_producers += 1

    if out_path:
        with open(match_path, 'w') as f:
            for candidate in matches:
                f.write(candidate + '\n')
    result_queue.put(matches)
    result_queue.close()
    queue.close()
    print('Consumer finished processing all items', file=sys.stderr)

def derive_full(xpub, der_path, addr_bloom, num_producer=2, currency=BTC, out_path=None, stop_after=2**31):
    assert stop_after <= 2**31,"Invalid number of indices to stop_after. At most 2**31 indices per derivation path level"
    matches = list()

    queue = mp.Queue()
    result_queue = mp.Queue() # the matches as return value
    idx_range_size = math.ceil(stop_after / num_producer)  # calc idx range per producer 
    #idx_range_size = math.ceil(2000 / num_producer)  # debug range

    producer_processes = [mp.Process(target=producer, 
                                     args=(queue, i, xpub, der_path, currency, 
                                           i * idx_range_size, idx_range_size)) 
                                     for i in range(0,num_producer)]
    consumer_process = mp.Process(target=consumer, 
                                  args=(queue, result_queue, num_producer, addr_bloom, out_path))

    # Start the producer processes
    for p in producer_processes:
        p.start()

    # Start the consumer process
    consumer_process.start()

    # Wait for all producer processes to finish
    for p in producer_processes:
        p.join()

    # Signal the consumer process that production is done
    for _ in range(num_producer):
        queue.put("done")

    # Wait for the consumer process to finish
    consumer_process.join()
    
    print('All processes finished', file=sys.stderr)
    return result_queue.get()

def main():
    parser = argparse.ArgumentParser(description="""xpub brute force script.
                                                    The BIP44 path levels are defined as:
                                                    m / purpose' / coin_type' / account' / change / address_index
                                                    Depending on the --from-* options derivation is started at
                                                    different levels in the path.""")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subparser for 'derive-full' command
    parser_derive_full = subparsers.add_parser('derive-full', help="Derive (brute force) all addresses from given xpub key, path and level")
    
    parser_derive_full.add_argument('--xpub', type=str, required=True, help='Extended public key')
    parser_derive_full.add_argument('--der-path', type=str, required=True, help='Derivation path to start from without last index e.g.m m/ or m/0/')
    parser_derive_full.add_argument('--addr-bloom', type=str, required=True, help='Location of bloom filter for addresses')
    
    parser_derive_full.add_argument('--currency', type=str, required=False, default=BTC, help='Optionally provide a currency')
    parser_derive_full.add_argument('--out-path', type=str, required=False, help='Optionally provide a output file path to store matches')

    args = parser.parse_args()

    if args.command == 'derive_full':
        derive_full(args.xpub, args.der_path, args.addr_bloom, args.currency, args.out_path)

if __name__ == "__main__":
    main()