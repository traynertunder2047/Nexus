import sys
from modules.github_check import check_github

def run_recon(username):
    print(f"\n[*] Starting OSINT scan for target: {username}")
    print("-" * 50)
    
    # 1. Run GitHub Module
    print("[+] Checking GitHub...")
    github_results = check_github(username)
    if github_results["found"]:
        print(f"  [✓] FOUND: {github_results['profile_url']}")
        print(f"      Details: {github_results['details']}")
    else:
        print("  [✗] Not Found on GitHub")
        
    print("-" * 50)
    print("[*] Scan complete.")

if __name__ == "__main__":
    # Ensure the user entered a username
    target = input("Enter the username to investigate: ").strip()
    if not target:
        print("[-] Error: Username cannot be blank.")
        sys.exit()
        
    run_recon(target)