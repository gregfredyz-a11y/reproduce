import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from coincurve import PublicKey

def read_points(filename):
    points = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or ',' not in line:
                    continue
                # CORRECTED PARSING: Split first, then strip the individual X-coordinate string
                parts = line.split(',')
                x_str = parts[0].strip() 
                if x_str:
                    points.add(int(x_str))
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
    except ValueError as e:
        print(f"Error parsing line '{line}': {e}")
    return points

def check_range(start_sebra, end_sebra, target_points):
    MAX_LIMIT = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    found_results = []

    for sebra in range(start_sebra, end_sebra):
        l = sebra 
        
        if l >= MAX_LIMIT or l <= 0:
            continue
            
        try:
            priv_bytes = l.to_bytes(32, 'big')
            pub = PublicKey.from_valid_secret(priv_bytes)
            x_coord = pub.point()[0]  # pub.point() returns (X, Y). We only want X.
            
            # Fast O(1) set lookup against actual public X-coordinates
            if x_coord in target_points:
                print(f"\n[FOUND] Match found! Private Key (l) = {l}")
                print(f"Matching X-Coordinate = {x_coord}")
                found_results.append(l)
                
        except ValueError:
            # Skip invalid private key scalars
            continue
            
    return found_results

def main():
    target_file = "allpubs_point.txt"
    all_pubs = read_points(target_file)
    
    if not all_pubs:
        print("No valid target points loaded. Exiting.")
        return

    print(f"Loaded {len(all_pubs)} target points successfully. Starting search...")

    # Define your search boundaries
    total_range = 150000
    num_workers = multiprocessing.cpu_count()
    chunk_size = total_range // num_workers

    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i in range(num_workers):
            start = 1 + (i * chunk_size)
            end = start + chunk_size if i < num_workers - 1 else total_range + 1
            futures.append(executor.submit(check_range, start, end, all_pubs))
        
        for future in futures:
            future.result()

if __name__ == "__main__":
    main()
