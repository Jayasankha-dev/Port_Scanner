package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ReconResult stores all gathered information
type ReconResult struct {
	Subdomains   []string
	Technologies []string
	Endpoints    []string
	Emails       []string
	APIKeys      []string
	Headers      map[string][]string
	IPs          []string
}

// ReconTool represents the main scanning engine
type ReconTool struct {
	Target    string
	Results   ReconResult
	Client    *http.Client
	UserAgent string
}

// NewReconTool initializes the scanner with optimized network settings
func NewReconTool(target string) *ReconTool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 30 * time.Second,
	}

	return &ReconTool{
		Target: target,
		Client: &http.Client{
			Transport: tr,
			Timeout:   15 * time.Second,
		},
		UserAgent: "BugBountyRecon/2.0",
		Results: ReconResult{
			Headers: make(map[string][]string),
			IPs:     make([]string, 0),
		},
	}
}

// FindSubdomains performs DNS brute-forcing on common prefixes
func (r *ReconTool) FindSubdomains() {
	fmt.Println("\n[*] Enumerating Subdomains...")
	
	commonSubdomains := []string{
		"www", "mail", "ftp", "admin", "test", "dev", "api", "vpn", "app", "staging",
	}
	
	var wg sync.WaitGroup
	var mu sync.Mutex
	
	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			fqdn := fmt.Sprintf("%s.%s", s, r.Target)
			if addrs, err := net.LookupHost(fqdn); err == nil {
				mu.Lock()
				r.Results.Subdomains = append(r.Results.Subdomains, fqdn)
				r.Results.IPs = append(r.Results.IPs, addrs...)
				fmt.Printf(" [+] Found: %s -> %v\n", fqdn, addrs)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
}

// FingerprintTech analyzes HTTP headers and body content for software stacks
func (r *ReconTool) FingerprintTech() {
	fmt.Println("\n[*] Identifying Web Technologies...")
	
	targetURL := fmt.Sprintf("http://%s", r.Target)
	req, _ := http.NewRequest("GET", targetURL, nil)
	req.Header.Set("User-Agent", r.UserAgent)
	
	resp, err := r.Client.Do(req)
	if err != nil {
		fmt.Printf(" [!] Connection failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	bodyStr := string(body)

	// Technology Signatures
	techs := map[string]string{
		"WordPress": "wp-content",
		"PHP":       "PHP/",
		"Nginx":     "nginx",
		"Apache":    "Apache",
		"React":     "react",
	}

	for name, pattern := range techs {
		if strings.Contains(bodyStr, pattern) || strings.Contains(resp.Header.Get("Server"), pattern) {
			r.Results.Technologies = append(r.Results.Technologies, name)
			fmt.Printf(" [+] Detected: %s\n", name)
		}
	}
}

// FindSensitiveInfo uses RegEx to find leaks like API keys or Emails
func (r *ReconTool) FindSensitiveInfo(body string) {
	fmt.Println("\n[*] Searching for Sensitive Data...")
	
	// Email Search
	emailRegex := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emails := emailRegex.FindAllString(body, -1)
	r.Results.Emails = emails
	for _, email := range emails {
		fmt.Printf(" [+] Email Leaked: %s\n", email)
	}

	// API Key Search (Common Patterns)
	apiKeyRegex := regexp.MustCompile(`(?i)(api_key|secret|token|password)["']?\s*[:=]\s*["']([a-zA-Z0-9]{20,})["']`)
	matches := apiKeyRegex.FindAllString(body, -1)
	if len(matches) > 0 {
		fmt.Printf(" [!] WARNING: %d Potential Secret(s) Found!\n", len(matches))
		r.Results.APIKeys = matches
	}
}

// ScanPorts checks for common open network services
func (r *ReconTool) ScanPorts() {
	fmt.Println("\n[*] Checking Common Services...")
	ports := []int{21, 22, 80, 443, 3306, 8080}
	
	for _, port := range ports {
		address := fmt.Sprintf("%s:%d", r.Target, port)
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err == nil {
			fmt.Printf(" [+] Port %d is OPEN\n", port)
			conn.Close()
		}
	}
}

// Run executes the full reconnaissance pipeline
func (r *ReconTool) Run() {
	fmt.Println("====================================================")
	fmt.Printf("   RECONNAISSANCE STARTING: %s\n", r.Target)
	fmt.Println("====================================================")

	r.ScanPorts()
	r.FindSubdomains()
	r.FingerprintTech()

	// Analyze Main Page
	resp, err := r.Client.Get("http://" + r.Target)
	if err == nil {
		body, _ := ioutil.ReadAll(resp.Body)
		r.FindSensitiveInfo(string(body))
		resp.Body.Close()
	}

	fmt.Println("\n[*] Recon Complete. Target Profiled Successfully.")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run web_recon.go <domain>")
		return
	}
	
	target := os.Args[1]
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	
	recon := NewReconTool(target)
	recon.Run()
}