use std::convert::From;
use std::error::Error;
use std::io::Error as IOError;
use std::fmt::{Display, Formatter, Error as FmtError};

use ring::error::Unspecified;


#[derive(Debug)]
pub enum CrypticError {
    DecryptionError(String),
    IOError(String)
}

impl Display for CrypticError {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), FmtError> {
        fmt.write_str(&format!("{:?}", self))
    }
}

impl Error for CrypticError {
    fn description(&self) -> &str {
        match self {
            &CrypticError::DecryptionError(ref message) => message,
            &CrypticError::IOError(ref message) => message,
        }
    }
}

impl From<IOError> for CrypticError {
    fn from(err: IOError) -> Self {
        CrypticError::IOError(format!("{}", err))
    }
}

impl From<Unspecified> for CrypticError {
    fn from(_: Unspecified) -> Self {
        CrypticError::DecryptionError(
            "Failed decryption, possibly due to wrong password".to_string()
        )
    }
}
