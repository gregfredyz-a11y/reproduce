from classSECP import Secp256k1
from coincurve import PublicKey
from random import randint
import multiprocessing as mp
import os
import sys

N = Secp256k1.n
Gx = Secp256k1.G.x
P = Secp256k1.p
TARGET_FILE = "allpubs_point.txt"
NUM_CORES = os.cpu_count() or 1  # Falls back to 1 if None

def process_chunk(lines_chunk, worker_id):
    """Worker function that processes a specific batch of public keys."""
    # Print status to show the core is active
    print(f"[Core {worker_id}] Processing {len(lines_chunk)} keys...")
    
    for line in lines_chunk:
        line = line.strip()
        if not line:
            continue
        
        try:
            # Parse your public key format here
            # For example, if it's a hex string:
            pub_bytes = bytes.fromhex(line)
            pub = PublicKey(pub_bytes)
            
            # --- Your ECC Math / Reproduction logic goes here ---
            # Example: point verification or multiplication
            
        except Exception as e:
            # Fail silently or log error to keep workers from crashing
            continue
            
    print(f"[Core {worker_id}] Done.")

if __name__ == "__main__":
    # 1. Read target file safely
    if not os.path.exists(TARGET_FILE):
        print(f"Error: {TARGET_FILE} not found!")
        sys.exit(1)
        
    with open(TARGET_FILE, "r") as f:
        all_lines = f.readlines()
        
    total_lines = len(all_lines)
    if total_lines == 0:
        print("Error: Target file is empty!")
        sys.exit(1)
        
    print(f"Loaded {total_lines} targets. Spawning workers across {NUM_CORES} cores...")

    # 2. Divide lines into equal chunks for each CPU core
    chunk_size = (total_lines + NUM_CORES - 1) // NUM_CORES
    chunks = [all_lines[i:i + chunk_size] for i in range(0, total_lines, chunk_size)]

    # 3. Launch Process Pool
    processes = []
    for core_idx in range(len(chunks)):
        p = mp.Process(target=process_chunk, args=(chunks[core_idx], core_idx))
        processes.append(p)
        p.start()

    # 4. Wait for all CPU cores to finish
    for p in processes:
        p.join()

    print("All CPU cores have finished processing.")
