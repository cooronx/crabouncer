use std::{collections::BTreeSet, str::FromStr};

use cedar_policy::{Entities, EntityTypeName, EntityUid, Schema};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{
    db::{AuthorizationGroup, AuthorizationIdentity},
    error::{ApiError, Result},
};

const RESERVED_TYPES: [&str; 3] = ["User", "Group", "Role"];

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub(crate) struct IamSnapshot {
    pub(crate) groups: Vec<IamGroupSnapshot>,
    pub(crate) roles: Vec<String>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct IamGroupSnapshot {
    pub(crate) key: String,
    pub(crate) kind: String,
}

pub(crate) struct IamProjection {
    pub(crate) entities: Vec<Value>,
    pub(crate) snapshot: IamSnapshot,
}

pub(crate) fn schema_is_iam_ready(schema_source: &str) -> bool {
    validate_schema_contract(schema_source).is_ok()
}

pub(crate) fn project_identity(
    identity: &AuthorizationIdentity,
    organization_id: uuid::Uuid,
    application_id: uuid::Uuid,
    request_attributes: &Map<String, Value>,
    include_graph: bool,
) -> IamProjection {
    let organization_id = organization_id.to_string();
    let application_id = application_id.to_string();
    let mut user_attributes = request_attributes.clone();
    user_attributes.insert(
        "organization_id".into(),
        Value::String(organization_id.clone()),
    );
    user_attributes.insert("email".into(), Value::String(identity.email.clone()));
    user_attributes.insert(
        "role".into(),
        Value::String(identity.organization_role.clone()),
    );

    let mut groups: Vec<AuthorizationGroup> = identity.groups.clone();
    groups.sort_by(|left, right| (&left.kind, &left.key).cmp(&(&right.kind, &right.key)));
    let mut direct_roles = identity.direct_role_keys.clone();
    direct_roles.sort();
    direct_roles.dedup();

    let mut user_parents = Vec::new();
    let mut group_entities = Vec::new();
    let mut effective_roles = BTreeSet::new();
    let mut snapshot = IamSnapshot::default();
    if include_graph {
        for group in groups {
            let mut group_roles = group.role_keys;
            group_roles.sort();
            group_roles.dedup();
            effective_roles.extend(group_roles.iter().cloned());
            user_parents.push(entity_uid("Group", &group.key));
            group_entities.push(json!({
                "uid": entity_uid("Group", &group.key),
                "attrs": {
                    "organization_id": organization_id,
                    "kind": group.kind,
                },
                "parents": group_roles
                    .iter()
                    .map(|key| entity_uid("Role", key))
                    .collect::<Vec<_>>(),
            }));
            snapshot.groups.push(IamGroupSnapshot {
                key: group.key,
                kind: group.kind,
            });
        }
        for role in direct_roles {
            effective_roles.insert(role.clone());
            user_parents.push(entity_uid("Role", &role));
        }
        snapshot.roles = effective_roles.iter().cloned().collect();
    }

    let mut entities = vec![json!({
        "uid": entity_uid("User", &identity.user_id.to_string()),
        "attrs": user_attributes,
        "parents": user_parents,
    })];
    entities.extend(group_entities);
    entities.extend(effective_roles.into_iter().map(|key| {
        json!({
            "uid": entity_uid("Role", &key),
            "attrs": {
                "organization_id": organization_id,
                "application_id": application_id,
            },
            "parents": [],
        })
    }));
    IamProjection { entities, snapshot }
}

pub(crate) fn validate_business_resource_type(resource_type: &str) -> Result<()> {
    let entity_type = EntityTypeName::from_str(resource_type)
        .map_err(|_| ApiError::bad_request("Cedar entity type is invalid"))?;
    if reserved_root_type_name(&entity_type).is_some() {
        Err(ApiError::bad_request(
            "User, Group, and Role are managed identity types and cannot be business resources",
        ))
    } else {
        Ok(())
    }
}

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
    reserved_root_type_name(uid.type_name())
}

fn reserved_root_type_name(entity_type: &EntityTypeName) -> Option<&'static str> {
    if entity_type.namespace_components().next().is_some() {
        return None;
    }
    RESERVED_TYPES
        .iter()
        .copied()
        .find(|reserved| entity_type.basename() == *reserved)
}

fn entity_uid(entity_type: &str, id: &str) -> Value {
    json!({ "type": entity_type, "id": id })
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
    use crate::db::AuthorizationGroup;

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
        assert!(validate_business_resource_type("Application::Role").is_ok());
        assert!(validate_business_resource_type("Document").is_ok());
        assert!(validate_business_resource_type("Role").is_err());
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

    #[test]
    fn projects_authoritative_groups_and_roles_with_stable_snapshots() {
        let user_id = uuid::Uuid::now_v7();
        let organization_id = uuid::Uuid::now_v7();
        let application_id = uuid::Uuid::now_v7();
        let identity = AuthorizationIdentity {
            user_id,
            email: "alice@example.com".into(),
            organization_role: "member".into(),
            groups: vec![
                AuthorizationGroup {
                    key: "research".into(),
                    kind: "virtual".into(),
                    role_keys: vec!["reader".into(), "editor".into()],
                },
                AuthorizationGroup {
                    key: "engineering".into(),
                    kind: "physical".into(),
                    role_keys: vec!["reader".into()],
                },
            ],
            direct_role_keys: vec!["writer".into(), "reader".into(), "writer".into()],
        };
        let request_attributes = Map::from_iter([
            ("department".into(), json!("Research")),
            ("email".into(), json!("spoofed@example.com")),
        ]);
        let projection = project_identity(
            &identity,
            organization_id,
            application_id,
            &request_attributes,
            true,
        );

        assert_eq!(
            projection.snapshot.groups,
            vec![
                IamGroupSnapshot {
                    key: "engineering".into(),
                    kind: "physical".into(),
                },
                IamGroupSnapshot {
                    key: "research".into(),
                    kind: "virtual".into(),
                },
            ]
        );
        assert_eq!(
            projection.snapshot.roles,
            vec!["editor", "reader", "writer"]
        );
        assert_eq!(projection.entities.len(), 6);
        assert_eq!(
            projection.entities[0]["attrs"]["email"],
            "alice@example.com"
        );
        assert_eq!(projection.entities[0]["attrs"]["department"], "Research");
        assert_eq!(
            projection.entities[0]["parents"].as_array().unwrap().len(),
            4
        );
    }

    #[test]
    fn legacy_projection_contains_only_the_authoritative_user() {
        let identity = AuthorizationIdentity {
            user_id: uuid::Uuid::now_v7(),
            email: "alice@example.com".into(),
            organization_role: "member".into(),
            groups: vec![AuthorizationGroup {
                key: "engineering".into(),
                kind: "physical".into(),
                role_keys: vec!["reader".into()],
            }],
            direct_role_keys: vec!["reader".into()],
        };
        let projection = project_identity(
            &identity,
            uuid::Uuid::now_v7(),
            uuid::Uuid::now_v7(),
            &Map::new(),
            false,
        );
        assert_eq!(projection.entities.len(), 1);
        assert_eq!(projection.entities[0]["parents"], json!([]));
        assert_eq!(projection.snapshot, IamSnapshot::default());
    }
}
