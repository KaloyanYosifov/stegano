pub trait PasswordReader {
    fn read_password(&self) -> Option<String>;
    fn read_password_prompt(&self, message: &str) -> Option<String>;
}

#[derive(Default)]
pub struct PromptPasswordReader;

impl PasswordReader for PromptPasswordReader {
    fn read_password(&self) -> Option<String> {
        match rpassword::read_password() {
            Ok(pass) => Some(pass),
            _ => None,
        }
    }

    fn read_password_prompt(&self, message: &str) -> Option<String> {
        match rpassword::prompt_password(message) {
            Ok(pass) => Some(pass),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Only for tests
// ---------------------------------------------------------------------------
#[cfg(test)]
pub struct PredefinedPasswordReader {
    message: Option<String>,
}

#[cfg(test)]
impl PredefinedPasswordReader {
    pub fn new(message: Option<String>) -> Self {
        Self { message }
    }
}

#[cfg(test)]
impl PasswordReader for PredefinedPasswordReader {
    fn read_password(&self) -> Option<String> {
        self.message.clone()
    }

    fn read_password_prompt(&self, message: &str) -> Option<String> {
        println!("{}", message);

        self.message.clone()
    }
}
