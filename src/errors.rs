use std::array::TryFromSliceError;
use std::string::FromUtf8Error;

#[derive(Debug, Clone)]
pub struct Error {
    message: String,
}
impl Error {
    pub fn new(message: &str) -> Self {
        Self {message: message.into()}
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for Error {}
impl From<ResponseError> for Error {
    fn from(error: ResponseError) -> Self {
        Self::new(&format!("Error communicating with device: {error}"))
    }
}

#[derive(Debug, Clone)]
pub struct ResponseError {
    message: String,
}
impl ResponseError {
    pub fn new(message: &str) -> Self {
        ResponseError {message: message.into()}
    }
}
impl std::fmt::Display for ResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ResponseError {}
impl From<TryFromSliceError> for ResponseError {
    fn from(error: TryFromSliceError) -> Self {
        Self {message: format!("Unable to convert passed bytes: {error}")}
    }
}
impl From<FromUtf8Error> for ResponseError {
    fn from(error: FromUtf8Error) -> Self {
        Self {message: format!("Unable to convert bytes into string: {error}")}
    }
}
