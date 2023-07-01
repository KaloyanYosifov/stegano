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
