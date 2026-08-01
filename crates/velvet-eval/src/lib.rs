pub mod bench;
pub mod cli;
pub mod ingest;
pub mod integrity;
pub mod metrics;
pub mod query;
pub mod recipes;
pub mod replay;
pub mod report;
pub mod schema;
pub mod store;

pub type Result<T> = std::result::Result<T, EvalError>;

#[derive(Debug)]
pub enum EvalError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Message(String),
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Json(error) => write!(formatter, "{error}"),
            Self::Message(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for EvalError {}

impl From<std::io::Error> for EvalError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for EvalError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub fn message(error: impl Into<String>) -> EvalError {
    EvalError::Message(error.into())
}
