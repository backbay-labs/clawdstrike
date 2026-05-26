//! Typed accessors over `endpointDecision` JSON metadata embedded in
//! signed endpoint receipts. Includes helpers that decode graph, sensor
//! state, policy, and actor sub-objects, plus the lower-level string/value
//! probes used throughout the receipts module.

use super::super::*;

pub(crate) fn receipt_endpoint_decision_graph(
    receipt: &SignedReceipt,
) -> Result<EndpointGraphReference> {
    let graph = receipt_endpoint_decision_value(receipt, &["graph"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing graph reference"))?;
    serde_json::from_value(graph.clone()).context("decode endpoint receipt graph reference")
}

pub(crate) fn receipt_endpoint_decision_sensor_state(
    receipt: &SignedReceipt,
) -> Result<EndpointSensorState> {
    let sensor_state = receipt_endpoint_decision_value(receipt, &["sensorState"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing sensor state"))?;
    serde_json::from_value(sensor_state.clone()).context("decode endpoint receipt sensor state")
}

pub(crate) fn receipt_endpoint_decision_policy(
    receipt: &SignedReceipt,
) -> Result<EndpointPolicySnapshot> {
    let policy = receipt_endpoint_decision_value(receipt, &["policy"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing policy snapshot"))?;
    serde_json::from_value(policy.clone()).context("decode endpoint receipt policy snapshot")
}

pub(crate) fn receipt_endpoint_decision_actor(
    receipt: &SignedReceipt,
) -> Result<EndpointDecisionActor> {
    let actor = receipt_endpoint_decision_value(receipt, &["actor"])
        .ok_or_else(|| anyhow::anyhow!("endpoint receipt is missing actor"))?;
    serde_json::from_value(actor.clone()).context("decode endpoint receipt actor")
}

pub(crate) fn receipt_endpoint_decision_str<'a>(
    receipt: &'a SignedReceipt,
    path: &[&str],
) -> Option<&'a str> {
    receipt_endpoint_decision_value(receipt, path)?.as_str()
}

pub(crate) fn receipt_endpoint_decision_value<'a>(
    receipt: &'a SignedReceipt,
    path: &[&str],
) -> Option<&'a Value> {
    let mut value = receipt.receipt.metadata.as_ref()?.get("endpointDecision")?;
    for key in path {
        value = value.get(*key)?;
    }
    Some(value)
}

pub(crate) fn protected_observation_ids_for_receipts(
    receipts: &[SignedReceipt],
    graph: &CausalGraph,
) -> BTreeSet<String> {
    let mut observation_ids = BTreeSet::new();
    let mut graph_node_ids = BTreeSet::new();
    let mut graph_edge_ids = BTreeSet::new();

    for receipt in receipts {
        let Some(endpoint_decision) = receipt
            .receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("endpointDecision"))
        else {
            continue;
        };

        if let Some(observation_id) = endpoint_decision
            .get("decision")
            .and_then(|decision| decision.get("observationId"))
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            observation_ids.insert(observation_id.to_string());
        }

        let Some(graph_ref) = endpoint_decision.get("graph") else {
            continue;
        };
        if let Some(node_id) = graph_ref
            .get("processNodeId")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            graph_node_ids.insert(node_id.to_string());
        }
        if let Some(node_ids) = graph_ref
            .get("nodeIds")
            .and_then(serde_json::Value::as_array)
        {
            graph_node_ids.extend(
                node_ids
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
        if let Some(edge_ids) = graph_ref
            .get("edgeIds")
            .and_then(serde_json::Value::as_array)
        {
            graph_edge_ids.extend(
                edge_ids
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string),
            );
        }
    }

    for edge in &graph.edges {
        if graph_edge_ids.contains(&edge.edge_id)
            || graph_node_ids.contains(&edge.from)
            || graph_node_ids.contains(&edge.to)
        {
            observation_ids.insert(edge.observation_id.clone());
        }
    }

    observation_ids
}
