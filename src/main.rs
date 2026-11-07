fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = tlsprint::cli::run(
        &args,
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut std::io::stderr(),
    );
    std::process::exit(code);
}
