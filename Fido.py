import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from coincurve import PublicKey

def read_points(filename):
    points = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Split by comma and extract the X-coordinate integer
                x_str = line.split(',')[0].strip()
                points.add(int(x_str))
    except FileNotFoundError:
        print(f"Error: {filename} not found.")
    return points

def check_range(start_sebra, end_sebra, target_points):
    """
    Processes a chunk of sebra values.
    Adjust the logic inside this function to match your exact mathematical progression.
    """
    MAX_LIMIT = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    found_results = []

    for sebra in range(start_sebra, end_sebra):
        # Replicating your intended logic per sebra iteration safely
        l = sebra 
        
        if l >= MAX_LIMIT:
            continue
            
        try:
            priv_bytes = l.to_bytes(32, 'big')
            pub = PublicKey.from_valid_secret(priv_bytes)
            x_coord = pub.point()[0]
            
            # Fast O(1) set lookup
            if x_coord in target_points:
                print(f"\n[FOUND] Match found! l = {l}")
                found_results.append(l)
                
        except ValueError:
            # Handles cases where 'l' might be an invalid private key scalar
            continue
            
    return found_results

def main():
    target_file = "allpubs_point.txt"
    all_pubs = read_points(target_file)
    
    if not all_pubs:
        print("No points to search. Exiting.")
        return

    print(f"Loaded {len(all_pubs)} target points. Starting search...")

    # Define your search boundaries
    total_range = 150000
    num_workers = multiprocessing.cpu_count()
    chunk_size = total_range // num_workers

    # Split work across all available CPU cores
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        for i in range(num_workers):
            start = 1 + (i * chunk_size)
            # Ensure the last chunk captures any rounding remainders
            end = start + chunk_size if i < num_workers - 1 else total_range + 1
            futures.append(executor.submit(check_range, start, end, all_pubs))
        
        # Gather results as they finish
        for future in futures:
            future.result()

if __name__ == "__main__":
    main()
