//! Stable wire types shared by Crabouncer and its Rust SDK.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type Properties = Map<String, Value>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Subject {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub properties: Properties,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Action {
    pub name: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub properties: Properties,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Resource {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub properties: Properties,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct EvaluationRequest {
    pub subject: Subject,
    pub action: Action,
    pub resource: Resource,
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub context: Properties,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Decision {
    pub decision: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<DecisionContext>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct DecisionContext {
    pub request_id: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationSemantic {
    #[default]
    ExecuteAll,
    DenyOnFirstDeny,
    PermitOnFirstPermit,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EvaluationDefaults {
    pub subject: Option<Subject>,
    pub action: Option<Action>,
    pub resource: Option<Resource>,
    pub context: Option<Properties>,
    #[serde(default)]
    pub evaluations: Vec<PartialEvaluation>,
    #[serde(default)]
    pub options: EvaluationOptions,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PartialEvaluation {
    pub subject: Option<Subject>,
    pub action: Option<Action>,
    pub resource: Option<Resource>,
    pub context: Option<Properties>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EvaluationOptions {
    #[serde(default)]
    pub evaluations_semantic: EvaluationSemantic,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct EvaluationsResponse {
    pub evaluations: Vec<Decision>,
}

impl Subject {
    pub fn user(id: impl Into<String>) -> Self {
        Self {
            kind: "User".into(),
            id: id.into(),
            properties: Map::new(),
        }
    }
}

impl Action {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            properties: Map::new(),
        }
    }
}

impl Resource {
    pub fn new(kind: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            id: id.into(),
            properties: Map::new(),
        }
    }

    pub fn property(mut self, name: impl Into<String>, value: impl Into<Value>) -> Self {
        self.properties.insert(name.into(), value.into());
        self
    }
}
