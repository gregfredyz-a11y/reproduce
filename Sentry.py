import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from coincurve import PublicKey
import os

def read_points(filename):
    points = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ',' not in line:
                    continue
                parts = line.split(',')
                x_str = parts[0].strip()
                if x_str:
                    points.add(int(x_str))
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
    return points

def scan_chunk(start_l, chunk_size, target_points):
    """
    Scans a massive block of keys using fast batch processing.
    """
    found_results = []
    
    # Pre-generate the scalar bytes for the entire batch
    # This minimizes the overhead of crossing the Python -> C boundary
    scalars = [
        (start_l + i).to_bytes(32, 'big') 
        for i in range(chunk_size)
    ]
    
    for idx, priv_bytes in enumerate(scalars):
        try:
            current_l = start_l + idx
            pub = PublicKey.from_valid_secret(priv_bytes)
            x_coord = pub.point()[0]
            
            if x_coord in target_points:
                match_info = f"Private Key (l) = {current_l}\nX-Coordinate = {x_coord}\n"
                print(f"\n[FOUND] Match discovered at l = {current_l}!")
                found_results.append(match_info)
                
        except ValueError:
            continue
            
    return found_results

def main():
    target_file = "allpubs_point.txt"
    output_file = "foundall.txt"
    all_pubs = read_points(target_file)
    
    if not all_pubs:
        print("No valid target points loaded. Exiting.")
        return

    # Define your massive range here (e.g., 2 Billion keys)
    # Change START_KEY to your desired starting point (e.g., skipping low-entropy keys)
    START_KEY = 1000
    TOTAL_KEYS_TO_SCAN = 2_000_000_000 
    
    # 100,000 is an optimal size for modern CPU caches
    BATCH_SIZE = 100_000 
    
    num_workers = multiprocessing.cpu_count()
    
    print(f"Loaded {len(all_pubs)} target points.")
    print(f"Starting multi-core deployment across {num_workers} CPU cores...")
    print(f"Scanning range: {START_KEY} to {START_KEY + TOTAL_KEYS_TO_SCAN:,}")
    print(f"Results will stream live to: {output_file}\n")

    current_start = START_KEY
    end_marker = START_KEY + TOTAL_KEYS_TO_SCAN

    # Initialize output file
    if not os.path.exists(output_file):
        with open(output_file, 'w') as f:
            f.write("--- Scan Started ---\n")

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        while current_start < end_marker:
            futures = []
            
            # Submit batches to fill up all CPU workers
            for _ in range(num_workers):
                if current_start >= end_marker:
                    break
                
                futures.append(
                    executor.submit(scan_chunk, current_start, BATCH_SIZE, all_pubs)
                )
                current_start += BATCH_SIZE
            
            # Gather results from this round of workers and write immediately to disk
            for future in futures:
                results = future.result()
                if results:
                    with open(output_file, 'a') as f:
                        for match in results:
                            f.write(match + "\n")
            
            # Print a clean, non-bloating progress metric
            print(f"Progress: Cleared up to key {current_start:,}...", end="\r")

    print(f"\nScan complete. All findings saved to {output_file}")

if __name__ == "__main__":
    main()
