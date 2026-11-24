use crate::json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn record_ids<'a>(
    input: &'a BTreeMap<String, Value>,
    name: &str,
) -> Result<BTreeSet<&'a str>, String> {
    let list = input
        .get(name)
        .ok_or_else(|| format!("Missing {name} record inventory."))?
        .array()?;
    list.iter()
        .map(|value| {
            let id = value.string()?;
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|ch| ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch))
            {
                return Err("Invalid signed record ID in peer inventory.".into());
            }
            Ok(id)
        })
        .collect()
}

pub fn plan(input: Value) -> Result<Value, String> {
    let input = input.object()?;
    let local = record_ids(input, "local")?;
    let remote = record_ids(input, "remote")?;
    let ids = |values: Vec<&&str>| {
        Value::Array(
            values
                .into_iter()
                .map(|id| Value::String((*id).into()))
                .collect(),
        )
    };
    Ok(Value::Object(BTreeMap::from([
        ("missing".into(), ids(local.difference(&remote).collect())),
        ("common".into(), ids(local.intersection(&remote).collect())),
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_only_missing_records() {
        let shared = "3".repeat(64);
        let new = "9".repeat(64);
        let foreign = "0".repeat(64);
        let request = crate::json::parse(&format!(
            r#"{{"local":["{shared}","{new}"],"remote":["{foreign}","{shared}","{shared}"]}}"#
        ))
        .unwrap();
        let result = plan(request).unwrap();
        assert_eq!(
            result.object().unwrap()["missing"],
            Value::Array(vec![Value::String(new)])
        );
        assert_eq!(
            result.object().unwrap()["common"],
            Value::Array(vec![Value::String(shared)])
        );
    }
}
