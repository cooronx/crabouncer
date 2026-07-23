use std::str::FromStr;

use authzen_rs::EvaluationRequest;
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, EntityTypeName, EntityUid, PolicySet,
    Request, Schema, ValidationMode, Validator,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::{
    error::{ApiError, Result},
    iam,
};

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
    iam::reject_reserved_entities(entities)?;
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

pub(crate) fn validate_schema_evolution(current: &str, next: &str) -> Result<()> {
    parse_schema(current)?;
    parse_schema(next)?;
    let current: Value = serde_json::from_str(current).map_err(|error| {
        ApiError::validation(
            "current Cedar schema could not be parsed",
            json!([error.to_string()]),
        )
    })?;
    let next: Value = serde_json::from_str(next).map_err(|error| {
        ApiError::validation(
            "new Cedar schema could not be parsed",
            json!([error.to_string()]),
        )
    })?;
    let current_namespaces = current
        .as_object()
        .ok_or_else(|| ApiError::validation("Cedar schema must be an object", Value::Null))?;
    let next_namespaces = next
        .as_object()
        .ok_or_else(|| ApiError::validation("Cedar schema must be an object", Value::Null))?;
    let mut errors = Vec::new();

    for (namespace, current_namespace) in current_namespaces {
        let Some(next_namespace) = next_namespaces.get(namespace) else {
            errors.push(format!("namespace {namespace:?} cannot be removed"));
            continue;
        };
        compare_named_definitions(
            namespace,
            "commonTypes",
            current_namespace,
            next_namespace,
            false,
            &mut errors,
        );
        compare_named_definitions(
            namespace,
            "actions",
            current_namespace,
            next_namespace,
            false,
            &mut errors,
        );
        compare_named_definitions(
            namespace,
            "entityTypes",
            current_namespace,
            next_namespace,
            true,
            &mut errors,
        );
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(ApiError::validation(
            "Cedar schema evolution must be backward compatible",
            json!(errors),
        ))
    }
}

pub(crate) fn evaluate(
    schema_source: &str,
    policies: &Value,
    persistent_entities: &Value,
    input: &EvaluationRequest,
    organization_id: Uuid,
    authoritative_subject: Option<Value>,
) -> Result<Value> {
    input
        .validate()
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    let subject = input
        .subject()
        .ok_or_else(|| ApiError::bad_request("subject is required"))?;
    let subject_type = subject
        .subject_type()
        .ok_or_else(|| ApiError::bad_request("subject.type is required"))?;
    let subject_id = subject
        .id()
        .ok_or_else(|| ApiError::bad_request("subject.id is required"))?;
    let action = input
        .action()
        .ok_or_else(|| ApiError::bad_request("action is required"))?;
    let action_name = action
        .name()
        .ok_or_else(|| ApiError::bad_request("action.name is required"))?;
    let resource = input
        .resource()
        .ok_or_else(|| ApiError::bad_request("resource is required"))?;
    let resource_type = resource
        .resource_type()
        .ok_or_else(|| ApiError::bad_request("resource.type is required"))?;
    let resource_id = resource
        .id()
        .ok_or_else(|| ApiError::bad_request("resource.id is required"))?;
    let expected_org = organization_id.to_string();
    if let Some(resource_org) = resource.properties().get("organization_id")
        && resource_org.as_str() != Some(expected_org.as_str())
    {
        return Ok(
            json!({ "decision": false, "reason": "tenant_mismatch", "policies": [], "errors": [] }),
        );
    }
    let schema = parse_schema(schema_source)?;
    let policies = parse_policies(policies)?;
    let principal = uid(subject_type, subject_id)?;
    let action = uid("Action", action_name)?;
    let resource_uid = uid(resource_type, resource_id)?;
    let mut all_entities = iam::filter_reserved_entities(persistent_entities)?;
    let mut subject_attrs = subject.properties().clone();
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
        subject_type,
        subject_id,
        Value::Object(subject_attrs),
    );
    let mut resource_attrs = resource.properties().clone();
    resource_attrs.insert("organization_id".into(), Value::String(expected_org));
    replace_entity(
        &mut all_entities,
        resource_type,
        resource_id,
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
        Value::Object(input.context().cloned().unwrap_or_default()),
        Some((&schema, &action)),
    )
    .map_err(|e| {
        ApiError::validation(
            "context does not conform to the active schema",
            json!([e.to_string()]),
        )
    })?;
    let request =
        Request::new(principal, action, resource_uid, context, Some(&schema)).map_err(|e| {
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

pub(crate) fn validate_synced_resource(
    schema_source: &str,
    resource_type: &str,
    resource_id: &str,
    properties: &Map<String, Value>,
    organization_id: Uuid,
) -> Result<Value> {
    if properties.contains_key("organization_id") {
        return Err(ApiError::bad_request(
            "organization_id is reserved and supplied by Crabouncer",
        ));
    }
    let mut attributes = properties.clone();
    attributes.insert(
        "organization_id".into(),
        Value::String(organization_id.to_string()),
    );
    validate_stored_resource(
        schema_source,
        resource_type,
        resource_id,
        &Value::Object(attributes.clone()),
    )?;
    Ok(Value::Object(attributes))
}

pub(crate) fn validate_stored_resource(
    schema_source: &str,
    resource_type: &str,
    resource_id: &str,
    properties: &Value,
) -> Result<()> {
    let schema = parse_schema(schema_source)?;
    uid(resource_type, resource_id)?;
    let entity = json!([{
        "uid": { "type": resource_type, "id": resource_id },
        "attrs": properties,
        "parents": []
    }]);
    Entities::from_json_value(entity, Some(&schema)).map_err(|error| {
        ApiError::validation(
            "resource does not conform to the active Cedar schema",
            json!([error.to_string()]),
        )
    })?;
    Ok(())
}

pub(crate) fn validate_resource_identity(resource_type: &str, resource_id: &str) -> Result<()> {
    uid(resource_type, resource_id).map(|_| ())
}

pub(crate) fn applicable_actions(
    schema_source: &str,
    subject_type: &str,
    resource_type: &str,
) -> Result<Vec<String>> {
    let schema = parse_schema(schema_source)?;
    let subject_type = EntityTypeName::from_str(subject_type)
        .map_err(|_| ApiError::bad_request("subject.type is invalid"))?;
    let resource_type = EntityTypeName::from_str(resource_type)
        .map_err(|_| ApiError::bad_request("resource.type is invalid"))?;
    let mut actions = schema
        .actions_for_principal_and_resource(&subject_type, &resource_type)
        .map(|action| action.id().unescaped().to_owned())
        .collect::<Vec<_>>();
    actions.sort();
    Ok(actions)
}

fn compare_named_definitions(
    namespace: &str,
    section: &str,
    current_namespace: &Value,
    next_namespace: &Value,
    allow_optional_attributes: bool,
    errors: &mut Vec<String>,
) {
    let current = current_namespace
        .get(section)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let next = next_namespace
        .get(section)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, definition) in current {
        let path = format!("{namespace:?}.{section}.{name}");
        let Some(next_definition) = next.get(&name) else {
            errors.push(format!("{path} cannot be removed"));
            continue;
        };
        if allow_optional_attributes {
            compare_entity_definition(&path, &definition, next_definition, errors);
        } else if &definition != next_definition {
            errors.push(format!("{path} cannot be changed"));
        }
    }
}

fn compare_entity_definition(path: &str, current: &Value, next: &Value, errors: &mut Vec<String>) {
    let (Some(current), Some(next)) = (current.as_object(), next.as_object()) else {
        if current != next {
            errors.push(format!("{path} cannot be changed"));
        }
        return;
    };

    for (key, current_value) in current {
        match key.as_str() {
            "shape" => compare_entity_shape(path, current_value, next.get(key), errors),
            "memberOfTypes" => {
                let current_types = current_value.as_array().cloned().unwrap_or_default();
                let next_types = next
                    .get(key)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if current_types
                    .iter()
                    .any(|entity_type| !next_types.contains(entity_type))
                {
                    errors.push(format!("{path}.memberOfTypes cannot remove parent types"));
                }
            }
            _ if next.get(key) != Some(current_value) => {
                errors.push(format!("{path}.{key} cannot be changed"));
            }
            _ => {}
        }
    }
    for key in next.keys() {
        if !current.contains_key(key) && key != "memberOfTypes" {
            errors.push(format!("{path}.{key} cannot be added"));
        }
    }
}

fn compare_entity_shape(
    path: &str,
    current: &Value,
    next: Option<&Value>,
    errors: &mut Vec<String>,
) {
    let (Some(current), Some(next)) = (current.as_object(), next.and_then(Value::as_object)) else {
        errors.push(format!("{path}.shape cannot be changed"));
        return;
    };
    for (key, current_value) in current {
        if key != "attributes" && next.get(key) != Some(current_value) {
            errors.push(format!("{path}.shape.{key} cannot be changed"));
        }
    }
    for key in next.keys() {
        if !current.contains_key(key) && key != "attributes" {
            errors.push(format!("{path}.shape.{key} cannot be added"));
        }
    }
    let current_attributes = current
        .get("attributes")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let next_attributes = next
        .get("attributes")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, definition) in &current_attributes {
        if next_attributes.get(name) != Some(definition) {
            errors.push(format!("{path}.shape.attributes.{name} cannot be changed"));
        }
    }
    for (name, definition) in &next_attributes {
        if !current_attributes.contains_key(name)
            && definition.get("required").and_then(Value::as_bool) != Some(false)
        {
            errors.push(format!(
                "{path}.shape.attributes.{name} must be optional when added"
            ));
        }
    }
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
        let request = EvaluationRequest::new(
            authzen_rs::Subject::new("User", "alice"),
            authzen_rs::Action::new("read"),
            authzen_rs::Resource::new("Document", "one").with_property("organization_id", "other"),
        );
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
        let request = EvaluationRequest::new(
            authzen_rs::Subject::new("User", Uuid::now_v7().to_string()),
            authzen_rs::Action::new("read"),
            authzen_rs::Resource::new("Document", "one")
                .with_property("organization_id", organization_id.to_string()),
        );
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

    #[test]
    fn injects_tenant_when_resource_omits_it() {
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
        let request = EvaluationRequest::new(
            authzen_rs::Subject::new("User", Uuid::now_v7().to_string()),
            authzen_rs::Action::new("read"),
            authzen_rs::Resource::new("Document", "one"),
        );
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
    }

    #[test]
    fn validates_and_injects_synced_resource_tenant() {
        let organization_id = Uuid::now_v7();
        let schema = json!({
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "organization_id": { "type": "String", "required": true },
                                "title": { "type": "String", "required": true }
                            }
                        }
                    }
                },
                "actions": {}
            }
        })
        .to_string();
        let properties = Map::from_iter([("title".into(), json!("Roadmap"))]);
        let result =
            validate_synced_resource(&schema, "Document", "one", &properties, organization_id)
                .unwrap();
        assert_eq!(result["organization_id"], organization_id.to_string());
    }

    #[test]
    fn allows_optional_attributes_in_schema_evolution() {
        let current = json!({
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "organization_id": { "type": "String", "required": true }
                            }
                        }
                    }
                },
                "actions": {}
            }
        })
        .to_string();
        let next = json!({
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "organization_id": { "type": "String", "required": true },
                                "title": { "type": "String", "required": false }
                            }
                        }
                    }
                },
                "actions": {}
            }
        })
        .to_string();
        validate_schema_evolution(&current, &next).unwrap();
    }

    #[test]
    fn rejects_required_attributes_in_schema_evolution() {
        let current = json!({
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": { "type": "Record", "attributes": {} }
                    }
                },
                "actions": {}
            }
        })
        .to_string();
        let next = json!({
            "": {
                "entityTypes": {
                    "Document": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "title": { "type": "String", "required": true }
                            }
                        }
                    }
                },
                "actions": {}
            }
        })
        .to_string();
        assert!(validate_schema_evolution(&current, &next).is_err());
    }
}
