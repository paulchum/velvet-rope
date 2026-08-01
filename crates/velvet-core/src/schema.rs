use serde_json::Value;

use crate::ThreadRecord;

pub fn thread_schema_json() -> Value {
    serde_json::to_value(schemars::schema_for!(ThreadRecord)).expect("thread schema serializes")
}
