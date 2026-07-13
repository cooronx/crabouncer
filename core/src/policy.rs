use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityUid, PolicySet, Request,
    Schema, ValidationMode, Validator,
};
use protocol::EvaluationRequest;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use crate::error::{ApiError, Result};

#[derive(Deserialize)]
struct PolicyDraft {
    name: String,
    source: String,
    #[serde(default = "enabled")]
    enabled: bool,
}

fn enabled() -> bool {
    true
}

pub(crate) fn validate_workspace(
    schema_source: &str,
    policies: &Value,
    entities: &Value,
) -> Result<()> {
    let schema = parse_schema(schema_source)?;
    let set = parse_policies(policies)?;
    let validation = Validator::new(schema.clone()).validate(&set, ValidationMode::Strict);
    if !validation.validation_passed() {
        let errors = validation
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        return Err(ApiError::validation(
            "Cedar policies do not conform to the schema",
            json!(errors),
        ));
    }
    Entities::from_json_value(entities.clone(), Some(&schema)).map_err(|e| {
        ApiError::validation(
            "Cedar entities do not conform to the schema",
            json!([e.to_string()]),
        )
    })?;
    Ok(())
}

pub(crate) fn evaluate(
    schema_source: &str,
    policies: &Value,
    persistent_entities: &Value,
    input: &EvaluationRequest,
    organization_id: Uuid,
    authoritative_subject: Option<Value>,
) -> Result<Value> {
    let expected_org = organization_id.to_string();
    if input
        .resource
        .properties
        .get("organization_id")
        .and_then(Value::as_str)
        != Some(expected_org.as_str())
    {
        return Ok(
            json!({ "decision": false, "reason": "tenant_mismatch", "policies": [], "errors": [] }),
        );
    }
    let schema = parse_schema(schema_source)?;
    let policies = parse_policies(policies)?;
    let principal = uid(&input.subject.kind, &input.subject.id)?;
    let action = uid("Action", &input.action.name)?;
    let resource = uid(&input.resource.kind, &input.resource.id)?;
    let mut all_entities = persistent_entities
        .as_array()
        .cloned()
        .ok_or_else(|| ApiError::validation("entities must be an array", Value::Null))?;
    let mut subject_attrs = input.subject.properties.clone();
    subject_attrs.insert(
        "organization_id".into(),
        Value::String(expected_org.clone()),
    );
    if let Some(Value::Object(authoritative)) = authoritative_subject {
        for (key, value) in authoritative {
            subject_attrs.insert(key, value);
        }
    }
    replace_entity(
        &mut all_entities,
        &input.subject.kind,
        &input.subject.id,
        Value::Object(subject_attrs),
    );
    let mut resource_attrs = input.resource.properties.clone();
    resource_attrs.insert("organization_id".into(), Value::String(expected_org));
    replace_entity(
        &mut all_entities,
        &input.resource.kind,
        &input.resource.id,
        Value::Object(resource_attrs),
    );
    let entities =
        Entities::from_json_value(Value::Array(all_entities), Some(&schema)).map_err(|e| {
            ApiError::validation(
                "request entities do not conform to the active schema",
                json!([e.to_string()]),
            )
        })?;
    let context = Context::from_json_value(
        Value::Object(input.context.clone()),
        Some((&schema, &action)),
    )
    .map_err(|e| {
        ApiError::validation(
            "context does not conform to the active schema",
            json!([e.to_string()]),
        )
    })?;
    let request =
        Request::new(principal, action, resource, context, Some(&schema)).map_err(|e| {
            ApiError::validation(
                "request does not conform to the active schema",
                json!([e.to_string()]),
            )
        })?;
    let response = Authorizer::new().is_authorized(&request, &policies, &entities);
    let allowed = response.decision() == CedarDecision::Allow;
    let reasons = response
        .diagnostics()
        .reason()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let errors = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let reason = if allowed {
        "permit"
    } else if reasons.is_empty() {
        "no_permit"
    } else {
        "explicit_forbid"
    };
    Ok(json!({ "decision": allowed, "reason": reason, "policies": reasons, "errors": errors }))
}

fn parse_schema(source: &str) -> Result<Schema> {
    if source.trim().is_empty() {
        return Err(ApiError::validation(
            "Cedar schema is required",
            Value::Null,
        ));
    }
    Schema::from_json_str(source).map_err(|e| {
        ApiError::validation("Cedar schema could not be parsed", json!([e.to_string()]))
    })
}

fn parse_policies(value: &Value) -> Result<PolicySet> {
    let drafts: Vec<PolicyDraft> = serde_json::from_value(value.clone()).map_err(|e| {
        ApiError::validation(
            "policies must be an array of {name, source, enabled}",
            json!([e.to_string()]),
        )
    })?;
    let source = drafts
        .into_iter()
        .filter(|p| p.enabled)
        .map(|p| format!("// {}\n{}", p.name, p.source))
        .collect::<Vec<_>>()
        .join("\n");
    PolicySet::from_str(&source).map_err(|e| {
        ApiError::validation("Cedar policies could not be parsed", json!([e.to_string()]))
    })
}

fn uid(kind: &str, id: &str) -> Result<EntityUid> {
    if kind.is_empty()
        || !kind
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')
    {
        return Err(ApiError::bad_request("Cedar entity type is invalid"));
    }
    let quoted = serde_json::to_string(id)
        .map_err(|_| ApiError::bad_request("Cedar entity id is invalid"))?;
    EntityUid::from_str(&format!("{kind}::{quoted}"))
        .map_err(|_| ApiError::bad_request("Cedar entity UID is invalid"))
}

fn replace_entity(entities: &mut Vec<Value>, kind: &str, id: &str, attrs: Value) {
    entities.retain(|entity| {
        let uid = entity.get("uid");
        uid.and_then(|v| v.get("type")).and_then(Value::as_str) != Some(kind)
            || uid.and_then(|v| v.get("id")).and_then(Value::as_str) != Some(id)
    });
    entities.push(json!({ "uid": { "type": kind, "id": id }, "attrs": attrs, "parents": [] }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_cross_tenant_resource_before_cedar() {
        let request = EvaluationRequest {
            subject: protocol::Subject::user("alice"),
            action: protocol::Action::new("read"),
            resource: protocol::Resource::new("Document", "one")
                .property("organization_id", "other"),
            context: Default::default(),
        };
        let result = evaluate("{}", &json!([]), &json!([]), &request, Uuid::nil(), None).unwrap();
        assert_eq!(result["reason"], "tenant_mismatch");
    }

    #[test]
    fn evaluates_request_entities_against_a_validated_release() {
        let organization_id = Uuid::now_v7();
        let schema = json!({
            "": {
                "entityTypes": {
                    "User": { "shape": { "type": "Record", "attributes": { "organization_id": { "type": "String", "required": true } } } },
                    "Document": { "shape": { "type": "Record", "attributes": { "organization_id": { "type": "String", "required": true } } } }
                },
                "actions": {
                    "read": { "appliesTo": { "principalTypes": ["User"], "resourceTypes": ["Document"], "context": { "type": "Record", "attributes": {} } } }
                }
            }
        }).to_string();
        let policies = json!([{ "name": "same tenant", "enabled": true, "source": "permit (principal, action == Action::\"read\", resource) when { principal.organization_id == resource.organization_id };" }]);
        let request = EvaluationRequest {
            subject: protocol::Subject::user(Uuid::now_v7().to_string()),
            action: protocol::Action::new("read"),
            resource: protocol::Resource::new("Document", "one")
                .property("organization_id", organization_id.to_string()),
            context: Default::default(),
        };
        let result = evaluate(
            &schema,
            &policies,
            &json!([]),
            &request,
            organization_id,
            None,
        )
        .unwrap();
        assert_eq!(result["decision"], true);
        assert_eq!(result["reason"], "permit");
    }
}
