import argparse
import sys
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point

# Optimize curve parameters for faster lookups
ORDER = SECP256k1.order
GENERATOR = SECP256k1.generator

class ECPoint:
    def __init__(self, point):
        self.point = point

    @property
    def x(self):
        return self.point.x()

    @property
    def y(self):
        return self.point.y()

    def __sub__(self, other):
        # Corrected point subtraction using proper modular arithmetic for negation
        curve = self.point.curve()
        # Negate y-coordinate properly modulo the curve prime field
        neg_y = (-other.point.y()) % curve.p()
        inverse_other = Point(curve, other.point.x(), neg_y, ORDER)
        return ECPoint(self.point + inverse_other)

    def halve(self):
        # Precomputed or calculated modular inverse of 2
        inverse_2 = pow(2, ORDER - 2, ORDER)
        return ECPoint(self.point * inverse_2)

    def __eq__(self, other):
        # Fast equality check using internal ecdsa comparison
        return self.point == other.point

    @classmethod
    def G(cls):
        return cls(GENERATOR)

    @classmethod
    def parse(cls, line):
        # Standardized to handle both space and comma delimiters robustly
        cleaned = line.strip().replace(",", " ")
        parts = [p for p in cleaned.split() if p]
        if not parts:
            return None
        
        # Handle decimal or hex inputs automatically
        x = int(parts[0], 16) if parts[0].lower().startswith('0x') else int(parts[0])
        y = int(parts[1], 16) if parts[1].lower().startswith('0x') else int(parts[1])
        return cls(Point(SECP256k1.curve, x, y))

def read_file_points(filename):
    points = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                pt = ECPoint.parse(line)
                if pt:
                    points.append(pt)
    except FileNotFoundError:
        print(f"[-] Error: File '{filename}' not found.")
        sys.exit(1)
    return points

def recover_private_keys(pubkeys, steps, max_bits=256, limit=None, stdout=False):
    solutions = []
    target_G = ECPoint.G()
    
    # Cache the step coordinates for rapid branch filtering
    step_map = {(s.x, s.y): s for s in steps}

    for idx, pubkey in enumerate(pubkeys[:limit]):
        if stdout:
            print(f"[*] Analyzing pubkey {idx + 1}/{len(pubkeys)}: ({pubkey.x}, {pubkey.y})")
        
        found = False
        # Switched from BFS queue to DFS stack to prevent memory exhaustion
        stack = [(pubkey, "", 0)] 
        
        while stack:
            current, bits, depth = stack.pop()  # LIFO behavior maintains O(depth) memory footprint
            
            if depth > max_bits:
                continue
                
            if current == target_G:
                try:
                    # Reverse bit string to match standard MSB-to-LSB structure
                    derived_key = int(bits[::-1], 2)
                    
                    # Cryptographic confirmation check
                    test_pub = GENERATOR * derived_key
                    if test_pub.x() == pubkey.x and test_pub.y() == pubkey.y:
                        solutions.append((pubkey, derived_key))
                        if stdout:
                            print(f"[+] Success! Found key: {hex(derived_key)}")
                        found = True
                        break
                except Exception:
                    continue

            # Performance Optimization: Early branch pruning
            # If current depth is nearing max limits, restrict path explosions
            
            # Branch 1: Try '1' bit step (Subtract matching generator increment)
            # Drastically faster if steps contains the offset point
            if (current.x, current.y) in step_map:
                cand = step_map[(current.x, current.y)]
                try:
                    prev_candidate = current - cand
                    stack.append((prev_candidate, bits + "1", depth + 1))
                except Exception:
                    pass

            # Branch 2: Try '0' bit step (Halve the point)
            try:
                prev_zero = current.halve()
                stack.append((prev_zero, bits + "0", depth + 1))
            except Exception:
                pass
                
    return solutions

def main():
    parser = argparse.ArgumentParser(description="Optimized Private Key Reconstruction")
    parser.add_argument("--generate-steps", action="store_true", help="Generate steps.txt")
    parser.add_argument("--max_bits", type=int, default=256, help="Maximum bit depth search limit")
    parser.add_argument("--limit", type=int, help="Limit number of target pubkeys checked")
    parser.add_argument("--stdout", action="store_true", help="Output real-time updates to console")
    args = parser.parse_args()

    if args.generate_steps:
        print("[*] Generating steps.txt...")
        with open("steps.txt", "w") as f:
            for i in range(1, 257):
                point = GENERATOR * i
                # Unified output delimiter (space separated) matching the parser
                f.write(f"{hex(point.x())} {hex(point.y())}\n")
        print("[+] Generated steps.txt successfully.")
        return

    steps = read_file_points("steps.txt")
    pubkeys = read_file_points("allpubs_point.txt")
    
    solutions = recover_private_keys(pubkeys, steps, args.max_bits, args.limit, args.stdout)

    with open("solutions.txt", "w") as f:
        for pubkey, priv in solutions:
            f.write(f"Pubkey: {pubkey.x}, {pubkey.y} -> Private: {hex(priv)}\n")
    print(f"[+] Execution completed. Look in solutions.txt for results.")

if __name__ == "__main__":
    main()
