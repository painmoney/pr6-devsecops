#!/usr/bin/env python3
"""
Script to check Bandit results for CI/CD pipeline.
Returns 0 if no HIGH severity issues, 1 if found.
"""
import json
import sys
import os

def main():
    report_file = 'bandit-report.json'
    
    if not os.path.exists(report_file):
        print("⚠️ No Bandit report found")
        print("high_count=0")
        return 0
    
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
        
        high_count = 0
        for issue in data.get('results', []):
            if issue.get('issue_severity') == 'HIGH':
                high_count += 1
                print(f"❌ HIGH severity: {issue.get('issue_text', 'Unknown')}")
        
        print(f"high_count={high_count}")
        
        if high_count > 0:
            print(f"🚨 Found {high_count} HIGH severity vulnerabilities!")
            return 1
        else:
            print("✅ No HIGH severity vulnerabilities found")
            return 0
            
    except Exception as e:
        print(f"⚠️ Error reading Bandit report: {e}")
        print("high_count=0")
        return 0

if __name__ == "__main__":
    sys.exit(main())