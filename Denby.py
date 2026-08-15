import argparse
import sys
from ecdsa.curves import SECP256k1
from ecdsa.ellipticcurve import Point, INFINITY

# Global optimizations
ORDER = SECP256k1.order
GENERATOR = SECP256k1.generator

class ECPoint:
    def __init__(self, point):
        self.point = point

    @property
    def x(self):
        return self.point.x() if self.point != INFINITY else None

    @property
    def y(self):
        return self.point.y() if self.point != INFINITY else None

    def __sub__(self, other):
        # SECP256k1 curve prime field order
        p = self.point.curve().p()
        
        # Correct negation in python-ecdsa:
        # Create the inverse point by keeping X and negating Y mod P
        neg_y = (-other.point.y()) % p
        inverse_point = Point(self.point.curve(), other.point.x(), neg_y, ORDER)
        
        return ECPoint(self.point + inverse_point)

    def halve(self):
        # Multiply by the modular inverse of 2 mod curve order
        inverse_2 = pow(2, ORDER - 2, ORDER)
        return ECPoint(self.point * inverse_2)

    def __eq__(self, other):
        if other is None:
            return False
        return self.point == other.point

    @classmethod
    def G(cls):
        return cls(GENERATOR)

    @classmethod
    def parse(cls, line):
        cleaned = line.strip().replace(",", " ")
        parts = [p for p in cleaned.split() if p]
        if not parts or len(parts) < 2:
            return None
        
        # Read format seamlessly whether input is decimal integers or 0x hexadecimal coordinates
        x = int(parts[0], 16) if parts[0].lower().startswith('0x') else int(parts[0])
        y = int(parts[1], 16) if parts[1].lower().startswith('0x') else int(parts[1])
        return cls(Point(SECP256k1.curve, x, y, ORDER))


def read_file_points(filename):
    points = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                pt = ECPoint.parse(line)
                if pt:
                    points.append(pt)
    except FileNotFoundError:
        print(f"[-] Error: Target file '{filename}' was not found.")
        sys.exit(1)
    return points


def recover_private_keys(pubkeys, steps, max_bits=256, limit=None, stdout=False):
    solutions = []
    target_G = ECPoint.G()
    
    # Store steps map as dictionary using coordinate pairs for O(1) instantaneous lookups
    step_map = {(s.x, s.y): s for s in steps if s.x is not None}

    for idx, pubkey in enumerate(pubkeys[:limit]):
        if stdout:
            print(f"[*] Checking public key {idx + 1}/{len(pubkeys)}")
        
        # DFS Stack setup (current_point, bit_string, depth)
        stack = [(pubkey, "", 0)]
        found = False
        
        while stack and not found:
            current, bits, depth = stack.pop()
            
            if depth > max_bits:
                continue
                
            if current == target_G:
                try:
                    # Convert bits to private key integer reverse order 
                    derived_key = int(bits[::-1], 2)
                    
                    # Cryptographic signature validation test check
                    test_pub = GENERATOR * derived_key
                    if test_pub.x() == pubkey.x and test_pub.y() == pubkey.y:
                        solutions.append((pubkey, derived_key))
                        if stdout:
                            print(f"[+] Private key matched: {hex(derived_key)}")
                        found = True
                        break
                except Exception:
                    continue

            # Route A: Match point subtraction logic against pre-calculated lookup database
            if (current.x, current.y) in step_map:
                cand = step_map[(current.x, current.y)]
                try:
                    prev_candidate = current - cand
                    stack.append((prev_candidate, bits + "1", depth + 1))
                except Exception:
                    pass

            # Route B: Halve the coordinate space back down
            try:
                prev_zero = current.halve()
                stack.append((prev_zero, bits + "0", depth + 1))
            except Exception:
                pass
                
    return solutions


def main():
    parser = argparse.ArgumentParser(description="Deterministic Private Key Reconstruction Script")
    parser.add_argument("--generate-steps", action="store_true", help="Generate local steps.txt file database")
    parser.add_argument("--max_bits", type=int, default=256, help="Maximum bit string analysis limit")
    parser.add_argument("--limit", type=int, help="Limit total public keys tested")
    parser.add_argument("--stdout", action="store_true", help="Output execution updates to terminal interface")
    args = parser.parse_args()

    if args.generate_steps:
        print("[*] Generating lookup steps.txt...")
        with open("steps.txt", "w") as f:
            for i in range(1, 257):
                point = GENERATOR * i
                f.write(f"{hex(point.x())} {hex(point.y())}\n")
        print("[+] Finished writing steps.txt database.")
        return

    steps = read_file_points("steps.txt")
    pubkeys = read_file_points("allpubs_point.txt")
    
    solutions = recover_private_keys(pubkeys, steps, args.max_bits, args.limit, args.stdout)

    with open("solutions.txt", "w") as f:
        for pubkey, priv in solutions:
            f.write(f"Pubkey: {pubkey.x}, {pubkey.y} -> Private: {hex(priv)}\n")
    print("[+] Complete. Saved outputs to solutions.txt file.")

if __name__ == "__main__":
    main()
