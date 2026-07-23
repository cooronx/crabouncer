use std::collections::BTreeSet;

use cedar_policy::{Entities, EntityUid, Schema};
use serde_json::{Value, json};

use crate::error::{ApiError, Result};

const RESERVED_TYPES: [&str; 3] = ["User", "Group", "Role"];

pub(crate) fn reject_reserved_entities(entities: &Value) -> Result<()> {
    let entities = entities
        .as_array()
        .ok_or_else(|| ApiError::validation("entities must be an array", Value::Null))?;
    for (index, entity) in entities.iter().enumerate() {
        let uid = parse_entity_uid(entity, index)?;
        if let Some(entity_type) = reserved_root_type(&uid) {
            return Err(ApiError::validation(
                "Workspace entities cannot define Crabouncer-managed entity types",
                json!([format!(
                    "entities[{index}] defines reserved entity type {entity_type}"
                )]),
            ));
        }
    }
    Ok(())
}

pub(crate) fn filter_reserved_entities(entities: &Value) -> Result<Vec<Value>> {
    let entities = entities
        .as_array()
        .ok_or_else(|| ApiError::validation("entities must be an array", Value::Null))?;
    let mut filtered = Vec::with_capacity(entities.len());
    for (index, entity) in entities.iter().enumerate() {
        let uid = parse_entity_uid(entity, index)?;
        if reserved_root_type(&uid).is_none() {
            filtered.push(entity.clone());
        }
    }
    Ok(filtered)
}

pub(crate) fn validate_schema_contract(schema_source: &str) -> Result<()> {
    let raw: Value = serde_json::from_str(schema_source).map_err(|error| {
        ApiError::validation(
            "Cedar schema could not be parsed",
            json!([error.to_string()]),
        )
    })?;
    let schema = Schema::from_json_str(schema_source).map_err(|error| {
        ApiError::validation(
            "Cedar schema could not be parsed",
            json!([error.to_string()]),
        )
    })?;
    let entity_types = raw
        .get("")
        .and_then(|namespace| namespace.get("entityTypes"))
        .and_then(Value::as_object)
        .ok_or_else(|| iam_schema_error("the root namespace must define entityTypes"))?;

    require_membership(entity_types, "User", &["Group", "Role"])?;
    require_membership(entity_types, "Group", &["Role"])?;
    if !entity_types.contains_key("Role") {
        return Err(iam_schema_error(
            "the root namespace must define the Role entity type",
        ));
    }

    let probe = iam_probe_entities();
    Entities::from_json_value(probe.clone(), Some(&schema)).map_err(|error| {
        iam_schema_error(format!(
            "User, Group, and Role must accept Crabouncer's attributes and no additional required attributes: {error}"
        ))
    })?;

    for (entity_index, field) in [
        (0, "organization_id"),
        (0, "email"),
        (0, "role"),
        (1, "organization_id"),
        (1, "kind"),
        (2, "organization_id"),
        (2, "application_id"),
    ] {
        let mut missing = probe.clone();
        missing[entity_index]["attrs"]
            .as_object_mut()
            .expect("probe attributes are objects")
            .remove(field);
        if Entities::from_json_value(missing, Some(&schema)).is_ok() {
            return Err(iam_schema_error(format!(
                "{}.{} must be a required String attribute",
                RESERVED_TYPES[entity_index], field
            )));
        }
    }
    Ok(())
}

fn parse_entity_uid(entity: &Value, index: usize) -> Result<EntityUid> {
    let raw_uid = entity.get("uid").ok_or_else(|| {
        ApiError::validation(
            "Cedar entity UID is required",
            json!([format!("entities[{index}].uid is missing")]),
        )
    })?;
    EntityUid::from_json(raw_uid.clone()).map_err(|error| {
        ApiError::validation(
            "Cedar entity UID could not be parsed",
            json!([format!("entities[{index}].uid: {error}")]),
        )
    })
}

pub(crate) fn reserved_root_type(uid: &EntityUid) -> Option<&'static str> {
    let entity_type = uid.type_name();
    if entity_type.namespace_components().next().is_some() {
        return None;
    }
    RESERVED_TYPES
        .iter()
        .copied()
        .find(|reserved| entity_type.basename() == *reserved)
}

fn require_membership(
    entity_types: &serde_json::Map<String, Value>,
    entity_type: &str,
    required: &[&str],
) -> Result<()> {
    let definition = entity_types.get(entity_type).ok_or_else(|| {
        iam_schema_error(format!(
            "the root namespace must define the {entity_type} entity type"
        ))
    })?;
    let memberships = definition
        .get("memberOfTypes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    for parent in required {
        if !memberships.contains(parent) {
            return Err(iam_schema_error(format!(
                "{entity_type}.memberOfTypes must include {parent}"
            )));
        }
    }
    Ok(())
}

fn iam_probe_entities() -> Value {
    json!([
        {
            "uid": { "type": "User", "id": "probe-user" },
            "attrs": {
                "organization_id": "probe-organization",
                "email": "probe@example.com",
                "role": "member"
            },
            "parents": [
                { "type": "Group", "id": "probe-group" },
                { "type": "Role", "id": "probe-role" }
            ]
        },
        {
            "uid": { "type": "Group", "id": "probe-group" },
            "attrs": {
                "organization_id": "probe-organization",
                "kind": "virtual"
            },
            "parents": [{ "type": "Role", "id": "probe-role" }]
        },
        {
            "uid": { "type": "Role", "id": "probe-role" },
            "attrs": {
                "organization_id": "probe-organization",
                "application_id": "probe-application"
            },
            "parents": []
        }
    ])
}

fn iam_schema_error(message: impl Into<String>) -> ApiError {
    ApiError::validation(message, Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schema() -> String {
        json!({
            "": {
                "entityTypes": {
                    "User": {
                        "memberOfTypes": ["Group", "Role"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "organization_id": { "type": "String", "required": true },
                                "email": { "type": "String", "required": true },
                                "role": { "type": "String", "required": true },
                                "department": { "type": "String", "required": false }
                            }
                        }
                    },
                    "Group": {
                        "memberOfTypes": ["Role"],
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "organization_id": { "type": "String", "required": true },
                                "kind": { "type": "String", "required": true }
                            }
                        }
                    },
                    "Role": {
                        "shape": {
                            "type": "Record",
                            "attributes": {
                                "organization_id": { "type": "String", "required": true },
                                "application_id": { "type": "String", "required": true }
                            }
                        }
                    }
                },
                "actions": {}
            }
        })
        .to_string()
    }

    #[test]
    fn accepts_the_iam_schema_contract() {
        validate_schema_contract(&schema()).unwrap();
    }

    #[test]
    fn rejects_missing_or_optional_system_attributes() {
        let mut missing_membership: Value = serde_json::from_str(&schema()).unwrap();
        missing_membership[""]["entityTypes"]["User"]["memberOfTypes"] = json!(["Group"]);
        assert!(validate_schema_contract(&missing_membership.to_string()).is_err());

        let mut optional_attribute: Value = serde_json::from_str(&schema()).unwrap();
        optional_attribute[""]["entityTypes"]["Role"]["shape"]["attributes"]["application_id"]["required"] =
            json!(false);
        assert!(validate_schema_contract(&optional_attribute.to_string()).is_err());
    }

    #[test]
    fn rejects_implicit_and_explicit_reserved_entities() {
        for uid in [
            json!({ "type": "User", "id": "one" }),
            json!({ "__entity": { "type": "Group", "id": "one" } }),
            json!({ "type": "Role", "id": "one" }),
        ] {
            let entities = json!([{ "uid": uid, "attrs": {}, "parents": [] }]);
            assert!(reject_reserved_entities(&entities).is_err());
        }
    }

    #[test]
    fn keeps_namespaced_and_business_entities() {
        let entities = json!([
            {
                "uid": { "type": "Application::Role", "id": "one" },
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "Document", "id": "one" },
                "attrs": {},
                "parents": []
            }
        ]);
        reject_reserved_entities(&entities).unwrap();
        assert_eq!(
            filter_reserved_entities(&entities).unwrap(),
            entities.as_array().unwrap().to_owned()
        );
    }

    #[test]
    fn filters_reserved_entities_and_rejects_malformed_uids() {
        let entities = json!([
            {
                "uid": { "__entity": { "type": "Role", "id": "reader" } },
                "attrs": {},
                "parents": []
            },
            {
                "uid": { "type": "Document", "id": "one" },
                "attrs": {},
                "parents": []
            }
        ]);
        let filtered = filter_reserved_entities(&entities).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0]["uid"]["type"], "Document");

        assert!(filter_reserved_entities(&json!([{}])).is_err());
        assert!(
            filter_reserved_entities(&json!([{ "uid": { "type": "bad type", "id": "one" } }]))
                .is_err()
        );
    }
}
