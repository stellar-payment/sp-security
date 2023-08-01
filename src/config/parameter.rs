use dotenv;

pub fn init() {
   dotenv::dotenv().ok().expect("failed to load .env file");
}


pub fn get(param: &str) -> String {
    let env_param = std::env::var(param)
    .expect(&format!("{} is not defined in the environment", param));
    return env_param;
}