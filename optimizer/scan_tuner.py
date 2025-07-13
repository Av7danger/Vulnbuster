"""
Auto-Tuning Scan Optimizer
Analyzes past scans, enables/disables modules dynamically, tracks success rate per tech stack.
"""
import json
import os
from collections import defaultdict

PROFILE_PATH = 'optimizer/scan_profile_stats.json'

class ScanTuner:
    def __init__(self):
        self.stats = defaultdict(lambda: defaultdict(int))
        if os.path.exists(PROFILE_PATH):
            with open(PROFILE_PATH) as f:
                self.stats.update(json.load(f))

    def update(self, tech_stack, module, success):
        self.stats[tech_stack][module] += int(success)
        with open(PROFILE_PATH, 'w') as f:
            json.dump(self.stats, f, indent=2)

    def recommend(self, tech_stack):
        if tech_stack not in self.stats:
            return []
        modules = self.stats[tech_stack]
        # Recommend modules with highest success rate
        sorted_mods = sorted(modules.items(), key=lambda x: -x[1])
        return [m for m, _ in sorted_mods if modules[m] > 0]

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Auto-Tuning Scan Optimizer")
    parser.add_argument('--update', nargs=3, metavar=('TECH','MODULE','SUCCESS'), help='Update stats')
    parser.add_argument('--recommend', metavar='TECH', help='Recommend modules for tech stack')
    args = parser.parse_args()
    tuner = ScanTuner()
    if args.update:
        tech, mod, succ = args.update
        tuner.update(tech, mod, succ == '1')
        print(f"Updated {mod} for {tech} with success={succ}")
    if args.recommend:
        recs = tuner.recommend(args.recommend)
        print(f"Recommended modules for {args.recommend}: {recs}")

if __name__ == "__main__":
    main() 