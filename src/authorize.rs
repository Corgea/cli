use crate::{config::Config, utils::{terminal, api}};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use http_body_util::Full;
use hyper::body::Bytes;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tokio::net::TcpListener;


const DEFAULT_PORT: u16 = 9876;

pub fn run(scope: Option<String>, url: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    // Build the authorization URL
    let base_domain = match (scope, url) {
        // If scope is provided, use it (takes precedence)
        (Some(ref s), _) if !s.is_empty() => format!("https://{}.corgea.app", s),
        // If URL is provided but no scope, use the URL
        (_, Some(ref u)) if !u.is_empty() => u.clone(),
        // Default fallback
        _ => "https://www.corgea.app".to_string(),
    };
    
    // Find available port starting from default
    let port = find_available_port(DEFAULT_PORT)?;
    let callback_url = format!("http://localhost:{}", port);
    let auth_url = format!("{}/authorize?callback={}", base_domain, 
                          urlencoding::encode(&callback_url));
    
    println!("Opening browser to authorize Corgea CLI...");
    println!("Authorization URL: {}", auth_url);
    
    // Open browser
    if let Err(e) = open::that(&auth_url) {
        eprintln!("Failed to open browser automatically: {}", e);
        println!("Please manually open the following URL in your browser:");
        println!("{}", auth_url);
    }
    
    // Set up shared state for the authorization code
    let auth_code = Arc::new(Mutex::new(None::<String>));
    let auth_code_clone = auth_code.clone();
    
    // Set up loading message
    let stop_signal = Arc::new(Mutex::new(false));
    let stop_signal_clone = stop_signal.clone();
    
    // Start loading spinner in a separate thread
    let loading_handle = thread::spawn(move || {
        terminal::show_loading_message("Waiting for authorization...", stop_signal_clone);
    });
    
    // Start the HTTP server to listen for the callback
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(async {
        start_callback_server(port, auth_code_clone).await
    });
    
    // Stop the loading spinner
    *stop_signal.lock().unwrap() = true;
    loading_handle.join().unwrap();
    
    match result {
        Ok(code) => {
            
            // Exchange the code for a user token
            let user_token = api::exchange_code_for_token(&base_domain, &code)?;
            
            // Save the user token to config
            let mut config = Config::load().expect("Failed to load config");
            config.set_token(user_token).expect("Failed to save user token");
            config.set_url(base_domain).expect("Failed to save URL");
            
            println!("\r🎉 Successfully authenticated to Corgea!");
            println!("You can now use other Corgea CLI commands.");
            
            Ok(())
        }
        Err(e) => {
            eprintln!("\r❌ Authorization failed: {}", e);
            Err(e)
        }
    }
}

fn find_available_port(start_port: u16) -> Result<u16, Box<dyn std::error::Error>> {
    // Try a more reliable approach - start from a higher range that's less likely to be used
    let search_ranges = vec![
        (start_port, start_port + 50),
        (9000, 9100),
        (8000, 8100),
        (7000, 7100),
    ];
    
    for (range_start, range_end) in search_ranges {
        for port in range_start..range_end {
            if port_is_available(port) {
                return Ok(port);
            }
        }
    }
    
    Err("No available ports found after checking multiple ranges".into())
}

fn port_is_available(port: u16) -> bool {
    match std::net::TcpListener::bind(format!("127.0.0.1:{}", port)) {
        Ok(listener) => {
            // Successfully bound - port is available
            // The listener will be dropped here, freeing the port
            drop(listener);
            true
        }
        Err(_) => {
            // Port is in use or binding failed
            false
        }
    }
}

async fn start_callback_server(
    port: u16,
    auth_code: Arc<Mutex<Option<String>>>,
) -> Result<String, Box<dyn std::error::Error>> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = match TcpListener::bind(&addr).await {
        Ok(listener) => {
            listener
        }
        Err(e) => {
            return Err(format!("Failed to bind to {}: {}", addr, e).into());
        }
    };
    
    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let auth_code_clone = auth_code.clone();
        
        let service = service_fn(move |req| {
            handle_callback(req, auth_code_clone.clone())
        });
        
        tokio::task::spawn(async move {
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service)
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
        
        // Check if we got the code
        if let Ok(code_guard) = auth_code.lock() {
            if let Some(code) = code_guard.as_ref() {
                return Ok(code.clone());
            }
        }
        
        // Add a small delay to prevent busy waiting
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn handle_callback(
    req: Request<Incoming>,
    auth_code: Arc<Mutex<Option<String>>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let uri = req.uri();
    
    // Parse query parameters
    if let Some(query) = uri.query() {
        let params = parse_query_params(query);
        
        if let Some(code) = params.get("code") {
            // Store the authorization code
            if let Ok(mut code_guard) = auth_code.lock() {
                *code_guard = Some(code.clone());
            }
            
            // Return success page
            let success_html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Corgea CLI - Authorization Successful</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { 
            font-family: 'Inter', sans-serif;
            margin: 0;
            padding: 0;
            background: #f8f9fa;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: white;
            text-align: center;
            padding: 60px 40px;
            border-radius: 16px;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.1);
            max-width: 500px;
            width: 90%;
        }
        .success-icon {
            width: 80px;
            height: 80px;
            background: #F56C26;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            color: white;
            font-size: 40px;
            font-weight: bold;
        }
        h1 { 
            color: #333;
            margin: 0 0 10px 0;
            font-size: 32px;
            font-weight: 700;
        }
        .subtitle {
            color: #666;
            font-size: 16px;
            margin-bottom: 40px;
        }
        .next-steps {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 24px;
            margin: 30px 0;
            text-align: left;
        }
        .next-steps h3 {
            color: #333;
            font-size: 18px;
            font-weight: 600;
            margin: 0 0 16px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .step {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 12px;
            padding: 8px 0;
        }
        .step:last-child {
            margin-bottom: 0;
        }
        .step-icon {
            width: 24px;
            height: 24px;
            background: #F56C26;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 12px;
            font-weight: bold;
            flex-shrink: 0;
            margin-top: 2px;
        }
        .step-content {
            flex: 1;
        }
        .step-title {
            color: #333;
            font-weight: 500;
            margin-bottom: 4px;
        }
        .step-description {
            color: #666;
            font-size: 14px;
            line-height: 1.4;
        }
        .return-button {
            background: #F56C26;
            color: white;
            border: none;
            padding: 12px 32px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
            margin: 20px 0;
        }
        .return-button:hover {
            background: #e55a1f;
        }
        .footer {
            color: #999;
            font-size: 12px;
            margin-top: 20px;
        }
        .footer a {
            color: #F56C26;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success-icon"><i class="fas fa-check"></i></div>
        <h1>Successfully Signed In!</h1>
        <div class="subtitle">Your CLI is now authenticated with Corgea</div>
        
        <div class="next-steps">
            <h3><i class="fas fa-bolt"></i> Next Steps</h3>
            <div class="steps">
                <div class="step">
                    <div class="step-icon"><i class="fas fa-terminal"></i></div>
                    <div class="step-content">
                        <div class="step-title">Return to your CLI</div>
                        <div class="step-description">Go back to your terminal and start running security scans on your codebase</div>
                    </div>
                </div>
                <div class="step">
                    <div class="step-icon"><i class="fas fa-play"></i></div>
                    <div class="step-content">
                        <div class="step-title">Run Your First Scan</div>
                        <div class="step-description">Use the Corgea CLI commands to analyze your code for security vulnerabilities</div>
                    </div>
                </div>
            </div>
        </div>
        

        <div class="footer">
            Authentication successful - Ready to scan with Corgea AI<br>
            Need help? - <a href="https://docs.corgea.app/">Documentation</a>
        </div>
    </div>
    <script>
        // Simple script for any future functionality
    </script>
</body>
</html>
            "#;
            
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(success_html)))
                .unwrap());
        }
        
        if let Some(error) = params.get("error") {
            let default_error = "Unknown error occurred".to_string();
            let error_description = params.get("error_description")
                .unwrap_or(&default_error);
            
            let error_html = format!(r#"
<!DOCTYPE html>
<html>
<head>
    <title>Corgea CLI - Authorization Failed</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body {{ 
            font-family: 'Inter', sans-serif;
            text-align: center; 
            padding: 50px; 
            background: rgb(33, 37, 41);
            color: white;
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        .container {{
            background: rgba(220, 53, 69, 0.1);
            border: 2px solid #dc3545;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(220, 53, 69, 0.3);
            max-width: 400px;
        }}
        h1 {{ 
            color: #dc3545; 
            margin-bottom: 20px; 
            font-size: 28px;
            font-weight: 600;
        }}
        .error-icon {{ 
            font-size: 48px; 
            margin-bottom: 20px; 
            color: #dc3545;
        }}
        .message {{ 
            font-size: 18px; 
            margin-bottom: 20px; 
            color: #e9ecef;
        }}
        .instruction {{ 
            font-size: 14px; 
            color: #adb5bd;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="error-icon">❌</div>
        <h1>Authorization Failed</h1>
        <div class="message">Error: {}</div>
        <div class="instruction">{}</div>
        <div class="instruction">Please return to your terminal and try again.</div>
    </div>
</body>
</html>
            "#, error, error_description);
            
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "text/html")
                .body(Full::new(Bytes::from(error_html)))
                .unwrap());
        }
    }
    
    // Default response for other requests
    let response_html = r#"
<!DOCTYPE html>
<html>
<head>
    <title>Corgea CLI - Waiting for Authorization</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { 
            font-family: 'Inter', sans-serif;
            text-align: center; 
            padding: 50px; 
            background: rgb(33, 37, 41);
            color: white;
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            background: rgba(245, 108, 38, 0.1);
            border: 2px solid #F56C26;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 4px 20px rgba(245, 108, 38, 0.3);
            max-width: 400px;
        }
        h1 {
            color: #F56C26;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 20px;
        }
        p {
            color: #e9ecef;
            font-size: 16px;
            margin-bottom: 20px;
        }
        .spinner { 
            font-size: 32px; 
            animation: spin 1s linear infinite; 
            color: #F56C26;
            margin-bottom: 20px;
        }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <h1>Waiting for Authorization...</h1>
        <p>Please complete the authorization process in the main browser window.</p>
    </div>
</body>
</html>
    "#;
    
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html")
        .body(Full::new(Bytes::from(response_html)))
        .unwrap())
}

fn parse_query_params(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|param| {
            let mut parts = param.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => {
                    Some((
                        urlencoding::decode(key).ok()?.into_owned(),
                        urlencoding::decode(value).ok()?.into_owned(),
                    ))
                }
                _ => None,
            }
        })
        .collect()
}


