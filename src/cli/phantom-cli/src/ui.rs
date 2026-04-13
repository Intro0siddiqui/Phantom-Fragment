use colored::*;

pub fn info(label: &str, value: &str) {
    println!("{} {}", label.yellow(), value.cyan());
}

pub fn success(message: &str) {
    println!("{}", message.green());
}

pub fn success_with_prefix(prefix: &str, message: &str) {
    println!("{} {}", prefix.green().bold(), message.cyan());
}

pub fn error_with_prefix(prefix: &str, message: &str) {
    eprintln!("{} {}", prefix.red().bold(), message);
}

pub fn error_bold(message: &str) {
    eprintln!("{}", message.red().bold());
}

pub fn warn(message: &str) {
    println!("{}", message.yellow());
}

pub fn warn_with_prefix(prefix: &str, message: &str) {
    println!("{} {}", prefix.yellow(), message);
}

pub fn warn_bold(message: &str) {
    println!("{}", message.yellow().bold());
}

pub fn dimmed(message: &str) {
    println!("{}", message.dimmed());
}

pub fn print_header(title: &str) {
    println!("{}", title.cyan().bold());
}

pub fn print_divider_full() {
    println!("{}", "─".repeat(80).dimmed());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_info() {
        info("Label:", "value");
    }

    #[test]
    fn test_success() {
        success("Operation completed");
    }

    #[test]
    fn test_error() {
        error_bold("Something went wrong");
    }

    #[test]
    fn test_warn() {
        warn("This is a warning");
    }

    #[test]
    fn test_dimmed() {
        dimmed("This text is dimmed");
    }
}
