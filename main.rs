use reqwest;
use tokio;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use std::collections::HashMap;
use std::env;
use colored::*;

#[derive(Clone)]
struct Fuzzer {
    client: reqwest::Client,
    wordlist: Vec<String>,
    target: String,
}

impl Fuzzer {
    fn new(target: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .user_agent("BugBountyFuzzer/2.0")
            .build()
            .expect("Fatal: Failed to initialize HTTP client");

        let wordlist = vec![
            "admin".to_string(), "login".to_string(), "config".to_string(),
            "backup".to_string(), ".git".to_string(), ".env".to_string(),
            "phpinfo".to_string(), "wp-admin".to_string(), "robots.txt".to_string(),
            "api".to_string(), "v1".to_string(), "test".to_string(), "dev".to_string(),
        ];

        Fuzzer {
            client,
            wordlist,
            target: target.trim_end_matches('/').to_string(),
        }
    }

    async fn check_vulnerabilities(&self, body: &str, status: u16) -> Vec<String> {
        let mut vulns = Vec::new();
        let body_lc = body.to_lowercase();

        if body_lc.contains("sql syntax") || body_lc.contains("mysql_fetch") {
            vulns.push("SQL Injection".red().bold().to_string());
        }
        if body_lc.contains("<script>") || body_lc.contains("alert(") {
            vulns.push("XSS Pattern".yellow().bold().to_string());
        }
        if body_lc.contains("root:x:0:0") || body_lc.contains("/etc/passwd") {
            vulns.push("LFI/Traversal".magenta().bold().to_string());
        }

        match status {
            403 => vulns.push("Forbidden Access".cyan().to_string()),
            500 => vulns.push("Server Error".red().to_string()),
            _ => {}
        }
        vulns
    }

    async fn run_scan(&self, max_threads: usize) {
        println!("{}", "=====================================".blue());
        println!("{} {}", "Targeting:".bold(), self.target.bright_cyan());
        println!("{} {}", "Concurrency:".bold(), max_threads);
        println!("{}", "=====================================\n".blue());

        let semaphore = Arc::new(Semaphore::new(max_threads));
        let mut tasks = Vec::new();

        // 1. Directory Fuzzing Logic
        for word in &self.wordlist {
            let fuzzer = self.clone();
            let word = word.clone();
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

            tasks.push(tokio::spawn(async move {
                let url = format!("{}/{}", fuzzer.target, word);
                if let Ok(resp) = fuzzer.client.get(&url).send().await {
                    let status = resp.status().as_u16();
                    let len = resp.content_length().unwrap_or(0);
                    
                    if status != 404 {
                        let vulns = fuzzer.check_vulnerabilities("", status).await;
                        println!(
                            "{} /{:15} -> {} (Size: {}) {}",
                            "[DIR]".green(), word, status.to_string().bright_white(), len,
                            if !vulns.is_empty() { format!("!!! Found: {}", vulns.join(", ")) } else { "".to_string() }
                        );
                    }
                }
                drop(permit);
            }));
        }

        // 2. Parameter Fuzzing Logic
        let params = vec!["id", "page", "file", "cmd"];
        let payloads = vec!["' OR 1=1--", "../../etc/passwd", "<script>alert(1)</script>"];

        for p in params {
            for payload in &payloads {
                let fuzzer = self.clone();
                let p = p.to_string();
                let payload = payload.to_string();
                let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();

                tasks.push(tokio::spawn(async move {
                    let mut query = HashMap::new();
                    query.insert(&p, &payload);

                    if let Ok(resp) = fuzzer.client.get(&fuzzer.target).query(&query).send().await {
                        let status = resp.status().as_u16();
                        if let Ok(text) = resp.text().await {
                            let vulns = fuzzer.check_vulnerabilities(&text, status).await;
                            if !vulns.is_empty() {
                                println!(
                                    "{} Param: {} Pay: {} -> {}",
                                    "[VULN]".red().bold(), p.yellow(), payload.cyan(), vulns.join(", ")
                                );
                            }
                        }
                    }
                    drop(permit);
                }));
            }
        }

        for task in tasks { let _ = task.await; }
        println!("\n{}", "Finished! All paths and parameters scanned.".green().bold());
    }
}



#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let raw_target = args.get(1).map(|s| s.as_str()).unwrap_or("http://testphp.vulnweb.com");

    let target = if !raw_target.starts_with("http") {
        format!("http://{}", raw_target)
    } else {
        raw_target.to_string()
    };

    let fuzzer = Fuzzer::new(&target);
    fuzzer.run_scan(15).await;
}