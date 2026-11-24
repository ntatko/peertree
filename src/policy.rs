use crate::json::Value;
use std::collections::{BTreeMap, BTreeSet};

fn property<'a>(object: &'a BTreeMap<String, Value>, key: &str) -> Result<&'a Value, String> {
    object.get(key).ok_or_else(|| format!("Missing {key}."))
}

fn fields(object: &BTreeMap<String, Value>, supported: &[&str]) -> Result<(), String> {
    if let Some(key) = object.keys().find(|key| !supported.contains(&key.as_str())) {
        return Err(format!("Unknown policy field {key}."));
    }
    Ok(())
}

fn branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && branch.len() <= 255
        && !branch.starts_with('-')
        && !branch.contains("..")
        && !branch.contains("@{")
        && !branch.ends_with('.')
        && branch != "@"
        && !branch
            .chars()
            .any(|ch| ch.is_ascii_control() || " ~^:?*[\\\"".contains(ch))
        && branch
            .split('/')
            .all(|part| !part.is_empty() && !part.starts_with('.') && !part.ends_with(".lock"))
}

pub struct Policy {
    branches: BTreeSet<String>,
    required: usize,
    checks: BTreeMap<String, Vec<String>>,
}

impl Policy {
    pub fn parse(value: &Value) -> Result<Self, String> {
        let config = value.object()?;
        fields(
            config,
            &["version", "protected_branches", "review", "checks"],
        )?;
        if property(config, "version")?.unsigned()? != 1 {
            return Err("PeerTree supports policy version 1.".into());
        }
        let mut branches = BTreeSet::new();
        for branch in property(config, "protected_branches")?.array()? {
            let branch = branch.string()?;
            if !branch_name(branch) || !branches.insert(branch.to_owned()) {
                return Err(format!("Invalid or duplicate protected branch {branch:?}."));
            }
        }
        if branches.is_empty() {
            return Err("List at least one protected branch.".into());
        }
        let review = property(config, "review")?.object()?;
        fields(review, &["required_approvals", "allow_self_approval"])?;
        let required = property(review, "required_approvals")?.unsigned()?;
        if !(1..=20).contains(&required) {
            return Err("Required approvals must be between 1 and 20.".into());
        }
        if !matches!(
            review.get("allow_self_approval"),
            None | Some(Value::Bool(false))
        ) {
            return Err("PeerTree policy version 1 requires independent reviewers.".into());
        }
        let mut checks = BTreeMap::new();
        let configured = property(config, "checks")?.object()?;
        if configured.len() > 32 {
            return Err("List at most 32 required checks.".into());
        }
        for (name, value) in configured {
            let valid_name = !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || b"._-".contains(&ch));
            let args = value
                .array()?
                .iter()
                .map(|arg| arg.string().map(str::to_owned))
                .collect::<Result<Vec<_>, _>>()?;
            if !valid_name
                || args.len() > 32
                || args.first().is_none_or(|arg| arg.trim().is_empty())
                || args
                    .iter()
                    .any(|arg| arg.len() > 1024 || arg.contains('\0'))
            {
                return Err(format!(
                    "Invalid check name or command arguments for {name:?}."
                ));
            }
            checks.insert(name.clone(), args);
        }
        Ok(Self {
            branches,
            required,
            checks,
        })
    }

    pub fn evaluate(&self, context: &BTreeMap<String, Value>) -> Result<Value, String> {
        let target = property(context, "target")?.string()?;
        if !self.branches.contains(target) {
            return Err(format!(
                "{target} is outside the committed protected branch list."
            ));
        }
        let author = property(context, "author")?.string()?;
        let mut votes = BTreeMap::new();
        for item in property(context, "reviews")?.array()? {
            let review = item.object()?;
            let who = property(review, "who")?.string()?;
            let vote = property(review, "vote")?.string()?;
            if who != author
                && (!matches!(vote, "approve" | "changes") || votes.insert(who, vote).is_some())
            {
                return Err("Expected one current verdict per reviewer.".into());
            }
        }
        let passes = property(context, "passed")?
            .array()?
            .iter()
            .map(Value::string)
            .collect::<Result<BTreeSet<_>, _>>()?;
        let approvals = votes.values().filter(|vote| **vote == "approve").count();
        let blocked = votes.values().any(|vote| *vote == "changes");
        let missing = self
            .checks
            .keys()
            .filter(|check| !passes.contains(check.as_str()))
            .map(|check| Value::String(check.clone()))
            .collect::<Vec<_>>();
        let ready = approvals >= self.required && !blocked && missing.is_empty();
        Ok(Value::Object(BTreeMap::from([
            ("approvals".into(), Value::Number(approvals.to_string())),
            ("required".into(), Value::Number(self.required.to_string())),
            ("blocked".into(), Value::Bool(blocked)),
            ("missing".into(), Value::Array(missing)),
            ("ready".into(), Value::Bool(ready)),
        ])))
    }
}

pub fn request(input: Value) -> Result<Value, String> {
    let context = input.object()?;
    let config = property(context, "policy")?;
    let policy = Policy::parse(config)?;
    match property(context, "operation")?.string()? {
        "validate" => Ok(config.clone()),
        "evaluate" => policy.evaluate(context),
        _ => Err("Unknown policy operation.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse;

    #[test]
    fn approvals_from_distinct_peers_and_required_checks_gate_the_merge() {
        let input = parse(
            r#"{
          "operation":"evaluate","target":"dev","author":"author",
          "policy":{"version":1,"protected_branches":["dev"],"review":{"required_approvals":2},
                    "checks":{"lint":["./lint.sh"],"test":["./test.sh"]}},
          "reviews":[{"who":"author","vote":"approve"},{"who":"one","vote":"approve"},
                     {"who":"two","vote":"approve"}],
          "passed":["test"]
        }"#,
        )
        .unwrap();
        let first = request(input.clone()).unwrap();
        assert_eq!(
            first.object().unwrap()["approvals"],
            Value::Number("2".into())
        );
        assert_eq!(
            first.object().unwrap()["missing"],
            Value::Array(vec![Value::String("lint".into())])
        );
        assert_eq!(first.object().unwrap()["ready"], Value::Bool(false));
        let mut changed = input.object().unwrap().clone();
        changed.insert("passed".into(), parse(r#"["lint","test"]"#).unwrap());
        assert_eq!(
            request(Value::Object(changed)).unwrap().object().unwrap()["ready"],
            Value::Bool(true)
        );
    }
}
