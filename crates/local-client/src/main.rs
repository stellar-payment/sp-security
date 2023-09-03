#[tokio::main]
async fn main() {
    reqwest::get("http://example.com");
    println!("Hello, world!");
}
