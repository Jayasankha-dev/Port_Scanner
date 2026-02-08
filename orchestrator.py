#!/usr/bin/env python3
import subprocess
import json
import sys
import os
import platform
from datetime import datetime

class BugBountyOrchestrator:
    def __init__(self, target):
        # Sanitize target: Remove protocol and trailing slashes for DNS tools
        self.target = target.replace('http://', '').replace('https://', '').strip('/')
        self.start_time = datetime.now()
        self.results = {
            "target": self.target,
            "scan_time": self.start_time.isoformat(),
            "port_scan": {},
            "recon": {},
            "fuzzing": {},
            "summary": {}
        }
        
        # Detect Platform
        self.is_windows = platform.system() == "Windows"
        self.ext = ".exe" if self.is_windows else ""
        
        # Ensure bin directory exists
        if not os.path.exists("bin"):
            os.makedirs("bin")
    
    def check_tool(self, tool_name, tool_path):
        """Verify that the binary exists and is executable"""
        if not os.path.exists(tool_path):
            print(f"[-] Error: {tool_name} missing at {tool_path}")
            print(f"    Please ensure all tools are compiled in the 'bin/' folder.")
            return False
        return True
    
    def run_tool(self, name, command, timeout=300):
        """Safely execute external tools and capture their output"""
        print(f"\n{'='*60}")
        print(f"[*] Starting Module: {name}")
        print(f"{'='*60}")
        
        try:
            # Using shell=False for security and better process control
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore' # Prevents crashes if tool outputs non-UTF8 chars
            )
            
            output = result.stdout.strip()
            stderr = result.stderr.strip()
            
            if result.returncode != 0 and stderr:
                output += f"\n\n[STDERR]\n{stderr}"
            
            print(f"[+] {name} completed (Return Code: {result.returncode})")
            return {
                "success": True,
                "output": output,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            print(f"[-] Error: {name} timed out after {timeout} seconds")
            return {"success": False, "output": "Execution Timeout", "return_code": -1}
        except Exception as e:
            print(f"[-] Fatal Error in {name}: {str(e)}")
            return {"success": False, "output": str(e), "return_code": -1}

    def run_all(self):
        """Execute the full security scanning pipeline"""
        # 1. C++ Port Scanner
        port_bin = os.path.join("bin", f"port_scanner{self.ext}")
        if self.check_tool("Port Scanner", port_bin):
            # Scan ports 1-1000
            self.results["port_scan"] = self.run_tool("Port Scan", [port_bin, self.target, "1", "1000"])

        # 2. Go Recon Tool
        recon_bin = os.path.join("bin", f"web_recon{self.ext}")
        if self.check_tool("Web Recon", recon_bin):
            self.results["recon"] = self.run_tool("Reconnaissance", [recon_bin, self.target])

        # 3. Rust HTTP Fuzzer
        fuzz_bin = os.path.join("bin", f"http_fuzzer{self.ext}")
        if self.check_tool("HTTP Fuzzer", fuzz_bin):
            target_url = f"http://{self.target}"
            self.results["fuzzing"] = self.run_tool("Fuzzing", [fuzz_bin, target_url])

        self.generate_summary()
        self.print_final_report()
        self.save_to_json()

    def generate_summary(self):
        """Parse raw output strings into numerical data for the report"""
        summary = {"ports": 0, "subdomains": 0, "vulns": 0}
        
        if self.results["port_scan"].get("success"):
            summary["ports"] = self.results["port_scan"]["output"].count("OPEN")
            
        if self.results["recon"].get("success"):
            summary["subdomains"] = self.results["recon"]["output"].count("Found:")
            
        if self.results["fuzzing"].get("success"):
            f_out = self.results["fuzzing"]["output"]
            summary["vulns"] = f_out.count("!!! Found:") + f_out.count("[VULN]")
            
        self.results["summary"] = summary

    def print_final_report(self):
        """Displays a clean, human-readable summary in the terminal"""
        print("\n" + "█"*60)
        print("🛡️  BUG BOUNTY SCAN REPORT SUMMARY")
        print("█"*60)
        print(f"Target Domain : {self.target}")
        print(f"Total Duration: {(datetime.now() - self.start_time).total_seconds():.1f}s")
        print("-" * 60)
        
        s = self.results["summary"]
        print(f" [+] Open Ports Found    : {s['ports']}")
        print(f" [+] Subdomains Detected : {s['subdomains']}")
        print(f" [+] Security Alerts     : {s['vulns']}")
        
        print("-" * 60)
        if s['vulns'] > 0:
            print(" ⚠️  CRITICAL: Potential vulnerabilities found. Check logs.")
        else:
            print(" ✅ No high-severity vulnerabilities detected by automated tools.")
        print("█"*60)

    def save_to_json(self):
        """Saves all raw data to a JSON file for later analysis"""
        filename = f"scan_{self.target.replace('.', '_')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4)
        print(f"\n[*] Full report saved to: {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python orchestrator.py <target_domain>")
        sys.exit(1)
    
    print("Initializing Bug Bounty Automation...")
    orchestrator = BugBountyOrchestrator(sys.argv[1])
    orchestrator.run_all()