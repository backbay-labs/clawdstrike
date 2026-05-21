use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::super::event::{
    CredentialKind, EndpointEvent, EndpointObservation, FileOperation, PackageManager,
};
use super::super::{
    agent_id_field, approval_id_field, insert_json, normalize_hostname, normalize_path_string,
    normalized_identity_value, reconstruct_path, stable_id, string_field, tool_call_id_field,
    workload_id_field,
};
use super::graph::CausalGraph;
use super::node::{CausalEdge, CausalEdgeKind, CausalNode, CausalNodeKind};

#[derive(Clone, Debug, Default)]
pub struct CausalGraphRecorder {
    graph: CausalGraph,
    last_node_by_session: BTreeMap<String, String>,
    process_nodes: BTreeMap<String, String>,
}

impl CausalGraphRecorder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn graph(&self) -> &CausalGraph {
        &self.graph
    }

    pub fn into_graph(self) -> CausalGraph {
        self.graph
    }

    pub fn record_observation(&mut self, observation: &EndpointObservation) -> Vec<String> {
        let mut touched = Vec::new();
        let process_node = self.process_node(observation);
        touched.push(process_node.clone());
        touched.extend(self.identity_context_nodes(observation, &process_node));

        if let Some(parent_guid) = observation
            .process
            .parent_process_guid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let parent = self.ensure_node(
                CausalNodeKind::Process,
                format!("guid:{parent_guid}"),
                parent_guid.to_string(),
                observation.timestamp,
                BTreeMap::new(),
            );
            self.add_edge(
                parent,
                process_node.clone(),
                CausalEdgeKind::Spawned,
                observation,
                BTreeMap::new(),
            );
        }

        if let Some((event_node, edge_kind)) = self.event_node(observation) {
            self.add_edge(
                process_node.clone(),
                event_node.clone(),
                edge_kind,
                observation,
                BTreeMap::new(),
            );
            if let EndpointEvent::PolicyDecision {
                action,
                target: Some(target),
                decision,
                ..
            } = &observation.event
            {
                if let Some((target_node, target_edge_kind, target_edge_attributes)) =
                    self.policy_decision_target_node(target, observation.timestamp)
                {
                    let mut edge_attributes = target_edge_attributes;
                    insert_json(&mut edge_attributes, "policyAction", action);
                    insert_json(&mut edge_attributes, "policyDecision", decision);
                    self.add_edge(
                        process_node.clone(),
                        target_node.clone(),
                        target_edge_kind,
                        observation,
                        edge_attributes.clone(),
                    );
                    self.add_edge(
                        target_node.clone(),
                        event_node.clone(),
                        CausalEdgeKind::Related,
                        observation,
                        edge_attributes,
                    );
                    touched.push(target_node);
                }
            }
            self.add_temporal_edge(observation, &event_node);
            touched.push(event_node);
        } else {
            self.add_temporal_edge(observation, &process_node);
        }

        touched
    }

    fn identity_context_nodes(
        &mut self,
        observation: &EndpointObservation,
        process_node: &str,
    ) -> Vec<String> {
        let mut touched = Vec::new();
        let posture = string_field(
            &observation.metadata,
            &["posture", "postureState", "posture_state"],
        );

        if let Some(host_id) = normalized_identity_value(observation.host_id.as_deref()) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "host");
            insert_json(&mut attributes, "hostId", &host_id);
            let node_id = self.ensure_node(
                CausalNodeKind::Host,
                format!("host:{host_id}"),
                host_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::ObservedOn,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(user_id) = normalized_identity_value(observation.user_id.as_deref()) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "user");
            insert_json(&mut attributes, "userId", &user_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            let node_id = self.ensure_node(
                CausalNodeKind::User,
                format!("user:{user_id}"),
                user_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::RanAs,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(session_id) = normalized_identity_value(observation.session_id.as_deref()) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "session");
            insert_json(&mut attributes, "sessionId", &session_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(&mut attributes, "userId", &observation.user_id);
            insert_json(&mut attributes, "posture", &posture);
            let node_id = self.ensure_node(
                CausalNodeKind::Session,
                format!("session:{session_id}"),
                session_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::InSession,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(agent_id) = agent_id_field(&observation.metadata) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "agent");
            insert_json(&mut attributes, "agentId", &agent_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(&mut attributes, "sessionId", &observation.session_id);
            insert_json(&mut attributes, "posture", &posture);
            let node_id = self.ensure_node(
                CausalNodeKind::Agent,
                format!("agent:{agent_id}"),
                agent_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::UsedAgent,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(workload_id) = workload_id_field(&observation.metadata) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "workload");
            insert_json(&mut attributes, "workloadId", &workload_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(
                &mut attributes,
                "agentId",
                agent_id_field(&observation.metadata),
            );
            let node_id = self.ensure_node(
                CausalNodeKind::Workload,
                format!("workload:{workload_id}"),
                workload_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::UsedWorkload,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        if let Some(approval_id) = approval_id_field(&observation.metadata) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "identityKind", "approval");
            insert_json(&mut attributes, "approvalId", &approval_id);
            insert_json(&mut attributes, "hostId", &observation.host_id);
            insert_json(
                &mut attributes,
                "agentId",
                agent_id_field(&observation.metadata),
            );
            insert_json(
                &mut attributes,
                "workloadId",
                workload_id_field(&observation.metadata),
            );
            let node_id = self.ensure_node(
                CausalNodeKind::Approval,
                format!("approval:{approval_id}"),
                approval_id.clone(),
                observation.timestamp,
                attributes,
            );
            self.add_edge(
                node_id.clone(),
                process_node.to_string(),
                CausalEdgeKind::AuthorizedBy,
                observation,
                BTreeMap::new(),
            );
            touched.push(node_id);
        }

        touched
    }

    #[must_use]
    pub fn causal_path(&self, from: &str, to: &str) -> Option<Vec<String>> {
        if from == to {
            return Some(vec![from.to_string()]);
        }

        let mut queue = VecDeque::from([from.to_string()]);
        let mut seen = BTreeSet::from([from.to_string()]);
        let mut previous: BTreeMap<String, String> = BTreeMap::new();

        while let Some(node) = queue.pop_front() {
            for edge in self.graph.edges.iter().filter(|edge| edge.from == node) {
                if !seen.insert(edge.to.clone()) {
                    continue;
                }
                previous.insert(edge.to.clone(), node.clone());
                if edge.to == to {
                    return Some(reconstruct_path(from, to, &previous));
                }
                queue.push_back(edge.to.clone());
            }
        }

        None
    }

    fn process_node(&mut self, observation: &EndpointObservation) -> String {
        let key = observation
            .process
            .stable_key_for_observation(&observation.observation_id);
        if let Some(node_id) = self.process_nodes.get(&key).cloned() {
            self.touch_node(&node_id, observation.timestamp);
            return node_id;
        }

        let label = observation
            .process
            .image
            .clone()
            .or_else(|| observation.process.command_line.clone())
            .unwrap_or_else(|| key.clone());
        let mut attributes = BTreeMap::new();
        insert_json(&mut attributes, "pid", observation.process.pid);
        insert_json(&mut attributes, "ppid", observation.process.ppid);
        insert_json(
            &mut attributes,
            "processGuid",
            &observation.process.process_guid,
        );
        insert_json(
            &mut attributes,
            "parentProcessGuid",
            &observation.process.parent_process_guid,
        );
        insert_json(
            &mut attributes,
            "processIdentityStrength",
            if observation.process.has_durable_stable_key() {
                "durable"
            } else {
                "weak_observation_scoped"
            },
        );
        insert_json(
            &mut attributes,
            "processIdentityKey",
            if observation.process.has_durable_stable_key() {
                observation.process.stable_key()
            } else {
                observation.process.weak_stable_key()
            },
        );
        insert_json(
            &mut attributes,
            "commandLine",
            &observation.process.command_line,
        );
        insert_json(&mut attributes, "cwd", &observation.process.cwd);
        insert_json(&mut attributes, "signing", &observation.process.signing);
        insert_json(&mut attributes, "hostId", &observation.host_id);
        insert_json(&mut attributes, "userId", &observation.user_id);
        insert_json(&mut attributes, "sessionId", &observation.session_id);
        insert_json(
            &mut attributes,
            "agentId",
            agent_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "workloadId",
            workload_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "approvalId",
            approval_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "toolCallId",
            tool_call_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "posture",
            string_field(
                &observation.metadata,
                &["posture", "postureState", "posture_state"],
            ),
        );

        let node_id = self.ensure_node(
            CausalNodeKind::Process,
            key.clone(),
            label,
            observation.timestamp,
            attributes,
        );
        self.process_nodes.insert(key, node_id.clone());
        node_id
    }

    fn event_node(
        &mut self,
        observation: &EndpointObservation,
    ) -> Option<(String, CausalEdgeKind)> {
        match &observation.event {
            EndpointEvent::ProcessExec { image, args, .. } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "args", args);
                Some((
                    self.ensure_node(
                        CausalNodeKind::File,
                        format!("exec:{image}"),
                        image.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Executed,
                ))
            }
            EndpointEvent::FileAccess {
                operation, path, ..
            } => Some((
                self.ensure_node(
                    CausalNodeKind::File,
                    format!("file:{}", normalize_path_string(path)),
                    path.clone(),
                    observation.timestamp,
                    BTreeMap::new(),
                ),
                match operation {
                    FileOperation::Write
                    | FileOperation::Create
                    | FileOperation::Delete
                    | FileOperation::Rename
                    | FileOperation::Chmod => CausalEdgeKind::Wrote,
                    _ => CausalEdgeKind::Read,
                },
            )),
            EndpointEvent::NetworkFlow {
                host,
                port,
                protocol,
                url,
            } => {
                let normalized_host = normalize_hostname(host);
                let node_host = if normalized_host.is_empty() {
                    host.clone()
                } else {
                    normalized_host
                };
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "host", &node_host);
                insert_json(&mut attributes, "port", port);
                insert_json(&mut attributes, "protocol", protocol);
                insert_json(&mut attributes, "url", url);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Network,
                        format!("net:{node_host}:{port}"),
                        format!("{node_host}:{port}"),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Connected,
                ))
            }
            EndpointEvent::DnsLookup {
                query,
                record_type,
                answers,
                resolver,
                status,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "recordType", record_type);
                insert_json(&mut attributes, "answers", answers);
                insert_json(&mut attributes, "resolver", resolver);
                insert_json(&mut attributes, "status", status);
                Some((
                    self.ensure_node(
                        CausalNodeKind::DnsName,
                        format!(
                            "dns:{}:{}",
                            normalize_hostname(query),
                            record_type.as_deref().unwrap_or_default()
                        ),
                        query.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::ResolvedDns,
                ))
            }
            EndpointEvent::PackageScript {
                manager,
                package,
                phase,
                script,
                ..
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "manager", manager.as_str());
                insert_json(&mut attributes, "package", package);
                insert_json(&mut attributes, "phase", phase);
                insert_json(&mut attributes, "script", script);
                Some((
                    self.ensure_node(
                        CausalNodeKind::PackageScript,
                        format!("script:{}:{}:{script}", manager.as_str(), phase),
                        format!("{} {phase}", manager.as_str()),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::RanScript,
                ))
            }
            EndpointEvent::DylibLoad { path, .. } => Some((
                self.ensure_node(
                    CausalNodeKind::File,
                    format!("dylib:{}", normalize_path_string(path)),
                    path.clone(),
                    observation.timestamp,
                    BTreeMap::new(),
                ),
                CausalEdgeKind::LoadedLibrary,
            )),
            EndpointEvent::LaunchPersistence { path, label, .. } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "label", label);
                Some((
                    self.ensure_node(
                        CausalNodeKind::File,
                        format!("launch:{}", normalize_path_string(path)),
                        path.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::CreatedPersistence,
                ))
            }
            EndpointEvent::BrowserExtensionInstall {
                browser,
                extension_id,
                path,
                ..
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "browser", browser);
                insert_json(&mut attributes, "extensionId", extension_id);
                Some((
                    self.ensure_node(
                        CausalNodeKind::BrowserExtension,
                        format!(
                            "browser_extension:{browser}:{}",
                            normalize_path_string(path)
                        ),
                        path.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::InstalledExtension,
                ))
            }
            EndpointEvent::BrowserDownload {
                browser,
                path,
                source_url,
                content_hash,
                byte_count,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "browser", browser);
                insert_json(&mut attributes, "sourceUrl", source_url);
                insert_json(&mut attributes, "contentHash", content_hash);
                insert_json(&mut attributes, "byteCount", byte_count);
                Some((
                    self.ensure_node(
                        CausalNodeKind::BrowserDownload,
                        format!("download:{}", normalize_path_string(path)),
                        path.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Downloaded,
                ))
            }
            EndpointEvent::CredentialAccess { kind, path, name } => {
                let key = path
                    .clone()
                    .or_else(|| name.clone())
                    .unwrap_or_else(|| kind.as_str().to_string());
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "credentialKind", kind.as_str());
                insert_json(&mut attributes, "path", path);
                insert_json(&mut attributes, "name", name);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Credential,
                        format!("credential:{key}"),
                        key,
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::AccessedCredential,
                ))
            }
            EndpointEvent::ToolCall {
                tool_name,
                parameters,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "parameters", parameters);
                insert_json(
                    &mut attributes,
                    "toolCallId",
                    tool_call_id_field(&observation.metadata),
                );
                Some((
                    self.ensure_node(
                        CausalNodeKind::Tool,
                        format!("tool:{tool_name}"),
                        tool_name.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::InvokedTool,
                ))
            }
            EndpointEvent::PolicyDecision {
                action,
                target,
                decision,
                guard,
                severity,
            } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "target", target);
                insert_json(&mut attributes, "decision", decision);
                insert_json(&mut attributes, "guard", guard);
                insert_json(&mut attributes, "severity", severity);
                Some((
                    self.ensure_node(
                        CausalNodeKind::PolicyDecision,
                        format!(
                            "decision:{}:{}:{}",
                            action,
                            target.as_deref().unwrap_or_default(),
                            decision
                        ),
                        format!("{action} {decision}"),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::MadeDecision,
                ))
            }
            EndpointEvent::Other { category, fields } => {
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "fields", fields);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Other,
                        format!("other:{category}:{}", observation.observation_id),
                        category.clone(),
                        observation.timestamp,
                        attributes,
                    ),
                    CausalEdgeKind::Related,
                ))
            }
        }
    }

    fn policy_decision_target_node(
        &mut self,
        target: &str,
        timestamp: DateTime<Utc>,
    ) -> Option<(String, CausalEdgeKind, BTreeMap<String, serde_json::Value>)> {
        let target = target.trim();
        if target.is_empty() {
            return None;
        }
        if let Some((host, port, url)) = policy_decision_network_target(target) {
            let mut node_attributes = BTreeMap::new();
            insert_json(&mut node_attributes, "host", &host);
            insert_json(&mut node_attributes, "port", port);
            let mut edge_attributes = BTreeMap::new();
            insert_json(&mut edge_attributes, "host", &host);
            insert_json(&mut edge_attributes, "port", port);
            insert_json(&mut edge_attributes, "target", target);
            insert_json(&mut edge_attributes, "url", url);
            return Some((
                self.ensure_node(
                    CausalNodeKind::Network,
                    format!("net:{host}:{port}"),
                    format!("{host}:{port}"),
                    timestamp,
                    node_attributes,
                ),
                CausalEdgeKind::Connected,
                edge_attributes,
            ));
        }
        if !target.starts_with('/') && !target.starts_with("~/") {
            return None;
        }

        let mut edge_attributes = BTreeMap::new();
        insert_json(&mut edge_attributes, "target", target);
        if let Some(kind) = credential_kind_from_path(target) {
            let mut attributes = BTreeMap::new();
            insert_json(&mut attributes, "credentialKind", kind.as_str());
            insert_json(&mut attributes, "path", target);
            return Some((
                self.ensure_node(
                    CausalNodeKind::Credential,
                    format!("credential:{target}"),
                    target.to_string(),
                    timestamp,
                    attributes,
                ),
                CausalEdgeKind::AccessedCredential,
                edge_attributes,
            ));
        }

        Some((
            self.ensure_node(
                CausalNodeKind::File,
                format!("file:{}", normalize_path_string(target)),
                target.to_string(),
                timestamp,
                BTreeMap::new(),
            ),
            CausalEdgeKind::Read,
            edge_attributes,
        ))
    }

    fn add_temporal_edge(&mut self, observation: &EndpointObservation, node_id: &str) {
        let Some(session_id) = observation.session_id.as_deref() else {
            return;
        };
        if let Some(previous) = self.last_node_by_session.get(session_id).cloned() {
            if previous != node_id {
                self.add_edge(
                    previous,
                    node_id.to_string(),
                    CausalEdgeKind::TemporalNext,
                    observation,
                    BTreeMap::new(),
                );
            }
        }
        self.last_node_by_session
            .insert(session_id.to_string(), node_id.to_string());
    }

    fn ensure_node(
        &mut self,
        kind: CausalNodeKind,
        key: String,
        label: String,
        timestamp: DateTime<Utc>,
        attributes: BTreeMap<String, serde_json::Value>,
    ) -> String {
        let node_id = stable_id("node", [key.as_str()]);
        if let Some(existing) = self.graph.nodes.get_mut(&node_id) {
            existing.last_seen = timestamp;
            for (key, value) in attributes {
                existing.attributes.entry(key).or_insert(value);
            }
            return node_id;
        }

        self.graph.nodes.insert(
            node_id.clone(),
            CausalNode {
                node_id: node_id.clone(),
                kind,
                label,
                first_seen: timestamp,
                last_seen: timestamp,
                attributes,
            },
        );
        node_id
    }

    fn touch_node(&mut self, node_id: &str, timestamp: DateTime<Utc>) {
        if let Some(node) = self.graph.nodes.get_mut(node_id) {
            node.last_seen = timestamp;
        }
    }

    fn add_edge(
        &mut self,
        from: String,
        to: String,
        kind: CausalEdgeKind,
        observation: &EndpointObservation,
        mut attributes: BTreeMap<String, serde_json::Value>,
    ) {
        insert_json(&mut attributes, "eventKind", observation.event.kind_name());
        insert_json(&mut attributes, "hostId", &observation.host_id);
        insert_json(&mut attributes, "userId", &observation.user_id);
        insert_json(&mut attributes, "sessionId", &observation.session_id);
        insert_json(
            &mut attributes,
            "agentId",
            agent_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "workloadId",
            workload_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "approvalId",
            approval_id_field(&observation.metadata),
        );
        insert_json(
            &mut attributes,
            "toolCallId",
            tool_call_id_field(&observation.metadata),
        );
        let kind_key = format!("{kind:?}");
        let edge_id = stable_id(
            "edge",
            [
                from.as_str(),
                to.as_str(),
                kind_key.as_str(),
                observation.observation_id.as_str(),
            ],
        );
        if self.graph.edges.iter().any(|edge| edge.edge_id == edge_id) {
            return;
        }
        self.graph.edges.push(CausalEdge {
            edge_id,
            from,
            to,
            kind,
            timestamp: observation.timestamp,
            observation_id: observation.observation_id.clone(),
            attributes,
        });
    }
}

fn policy_decision_network_target(target: &str) -> Option<(String, u16, Option<String>)> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some((scheme, rest)) = trimmed.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => return None,
        };
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or(rest)
            .rsplit('@')
            .next()
            .unwrap_or(rest);
        let (host, port) = policy_decision_authority_host_port(authority, Some(default_port))?;
        return Some((host, port, Some(trimmed.to_string())));
    }

    policy_decision_authority_host_port(trimmed, None).map(|(host, port)| (host, port, None))
}

fn policy_decision_authority_host_port(
    authority: &str,
    default_port: Option<u16>,
) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() {
        return None;
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        let port = if let Some(port_text) = suffix.strip_prefix(':') {
            port_text.parse::<u16>().ok()?
        } else {
            default_port?
        };
        (host, port)
    } else if let Some((host, port_text)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host, port_text.parse::<u16>().ok()?)
    } else {
        (authority, default_port?)
    };

    let host = normalize_hostname(host);
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

fn credential_kind_from_path(path: &str) -> Option<CredentialKind> {
    let lower = path.to_ascii_lowercase();
    if lower.contains("/.ssh/")
        || lower.ends_with("/id_rsa")
        || lower.ends_with("/id_ed25519")
        || lower.ends_with("/id_ecdsa")
    {
        return Some(CredentialKind::SshKey);
    }
    if lower.ends_with("/.npmrc") || lower.contains("/.config/yarn/") {
        return Some(CredentialKind::PackageRegistryToken);
    }
    if lower.contains("/.aws/credentials")
        || lower.contains("/.config/gcloud/")
        || lower.contains("/.azure/")
    {
        return Some(CredentialKind::CloudCredential);
    }
    if lower.contains("cookies") || lower.contains("cookie") {
        return Some(CredentialKind::BrowserCookie);
    }
    if lower.contains("signing") && (lower.ends_with(".pem") || lower.ends_with(".key")) {
        return Some(CredentialKind::SigningKey);
    }
    if lower.contains("token") || lower.contains("api_key") || lower.contains("apikey") {
        return Some(CredentialKind::ApiToken);
    }
    None
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::super::super::process::EndpointProcess;
    use super::*;

    #[test]
    fn pid_only_process_identity_is_observation_scoped() {
        let mut recorder = CausalGraphRecorder::new();
        let first = observation_with_process(
            "obs-pid-reuse-1",
            EndpointProcess {
                pid: Some(4242),
                image: Some("/bin/sh".to_string()),
                command_line: Some("sh -c make".to_string()),
                ..EndpointProcess::default()
            },
        );
        let second = observation_with_process(
            "obs-pid-reuse-2",
            EndpointProcess {
                pid: Some(4242),
                image: Some("/bin/sh".to_string()),
                command_line: Some("sh -c make".to_string()),
                ..EndpointProcess::default()
            },
        );

        recorder.record_observation(&first);
        recorder.record_observation(&second);

        let process_nodes = recorder
            .graph()
            .nodes
            .values()
            .filter(|node| {
                node.kind == CausalNodeKind::Process
                    && node.attributes.get("pid").and_then(|value| value.as_u64()) == Some(4242)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            process_nodes.len(),
            2,
            "same PID without a durable process GUID must not merge process nodes"
        );
        assert!(process_nodes.iter().all(|node| {
            node.attributes
                .get("processIdentityStrength")
                .and_then(|value| value.as_str())
                == Some("weak_observation_scoped")
        }));
    }

    #[test]
    fn durable_process_guid_still_merges_observations() {
        let mut recorder = CausalGraphRecorder::new();
        let first = observation_with_process(
            "obs-guid-1",
            EndpointProcess {
                pid: Some(4242),
                process_guid: Some("proc-guid-4242".to_string()),
                image: Some("/bin/sh".to_string()),
                ..EndpointProcess::default()
            },
        );
        let second = observation_with_process(
            "obs-guid-2",
            EndpointProcess {
                pid: Some(4242),
                process_guid: Some("proc-guid-4242".to_string()),
                image: Some("/bin/sh".to_string()),
                ..EndpointProcess::default()
            },
        );

        recorder.record_observation(&first);
        recorder.record_observation(&second);

        let process_nodes = recorder
            .graph()
            .nodes
            .values()
            .filter(|node| {
                node.kind == CausalNodeKind::Process
                    && node.attributes.get("pid").and_then(|value| value.as_u64()) == Some(4242)
            })
            .collect::<Vec<_>>();
        assert_eq!(process_nodes.len(), 1);
        assert_eq!(
            process_nodes[0]
                .attributes
                .get("processIdentityStrength")
                .and_then(|value| value.as_str()),
            Some("durable")
        );
    }

    #[test]
    fn parent_process_placeholder_uses_canonical_process_identity_key() {
        let mut recorder = CausalGraphRecorder::new();
        let child = observation_with_process(
            "obs-child",
            EndpointProcess {
                pid: Some(200),
                ppid: Some(100),
                process_guid: Some("child-1".to_string()),
                parent_process_guid: Some("parent-1".to_string()),
                image: Some("/bin/child".to_string()),
                ..EndpointProcess::default()
            },
        );
        let parent = observation_with_process(
            "obs-parent",
            EndpointProcess {
                pid: Some(100),
                process_guid: Some("parent-1".to_string()),
                image: Some("/bin/parent".to_string()),
                ..EndpointProcess::default()
            },
        );

        recorder.record_observation(&child);
        recorder.record_observation(&parent);

        let graph = recorder.graph();
        let parent_nodes = graph
            .nodes
            .values()
            .filter(|node| {
                node.kind == CausalNodeKind::Process
                    && (node.label == "parent-1"
                        || node
                            .attributes
                            .get("processGuid")
                            .and_then(|value| value.as_str())
                            == Some("parent-1"))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            parent_nodes.len(),
            1,
            "parent placeholders and later parent observations must share one process node"
        );
        let parent_node = parent_nodes[0];
        assert_eq!(
            parent_node
                .attributes
                .get("processIdentityKey")
                .and_then(|value| value.as_str()),
            Some("guid:parent-1")
        );

        let child_nodes = graph
            .nodes
            .values()
            .filter(|node| {
                node.attributes
                    .get("processGuid")
                    .and_then(|value| value.as_str())
                    == Some("child-1")
            })
            .collect::<Vec<_>>();
        assert_eq!(child_nodes.len(), 1, "child process node must exist once");
        let child_node_id = child_nodes[0].node_id.as_str();
        assert!(graph.edges.iter().any(|edge| {
            edge.kind == CausalEdgeKind::Spawned
                && edge.from == parent_node.node_id
                && edge.to == child_node_id
        }));
    }

    #[test]
    fn shared_network_nodes_keep_policy_targets_on_edges() {
        let mut recorder = CausalGraphRecorder::new();
        let first = observation_with_event(
            "obs-network-decision-1",
            EndpointEvent::PolicyDecision {
                action: "network_extension_egress".to_string(),
                target: Some("https://API.Example.Invalid/v1".to_string()),
                decision: "blocked".to_string(),
                guard: Some("network_extension_content_filter".to_string()),
                severity: Some("high".to_string()),
            },
        );
        let second = observation_with_event(
            "obs-network-decision-2",
            EndpointEvent::PolicyDecision {
                action: "network_extension_egress".to_string(),
                target: Some("https://api.example.invalid/v2".to_string()),
                decision: "blocked".to_string(),
                guard: Some("network_extension_content_filter".to_string()),
                severity: Some("high".to_string()),
            },
        );

        recorder.record_observation(&first);
        recorder.record_observation(&second);

        let graph = recorder.graph();
        let network_nodes = graph
            .nodes
            .values()
            .filter(|node| {
                node.kind == CausalNodeKind::Network && node.label == "api.example.invalid:443"
            })
            .collect::<Vec<_>>();
        assert_eq!(network_nodes.len(), 1);
        let network_node = network_nodes[0];
        assert!(
            !network_node.attributes.contains_key("target"),
            "shared network nodes must not retain a stale per-decision target"
        );
        assert!(
            !network_node.attributes.contains_key("url"),
            "shared network nodes must not retain a stale per-decision URL"
        );

        let edge_targets = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.kind == CausalEdgeKind::Connected && edge.to == network_node.node_id
            })
            .filter_map(|edge| {
                edge.attributes
                    .get("target")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            edge_targets,
            BTreeSet::from([
                "https://API.Example.Invalid/v1".to_string(),
                "https://api.example.invalid/v2".to_string(),
            ])
        );
    }

    fn observation_with_process(
        observation_id: &str,
        process: EndpointProcess,
    ) -> EndpointObservation {
        EndpointObservation {
            observation_id: observation_id.to_string(),
            timestamp: Utc::now(),
            host_id: Some("host-1".to_string()),
            user_id: Some("user-1".to_string()),
            session_id: Some("session-1".to_string()),
            process,
            event: EndpointEvent::ProcessExec {
                image: "/bin/sh".to_string(),
                args: vec!["-c".to_string(), "make".to_string()],
                env: BTreeMap::new(),
            },
            metadata: BTreeMap::new(),
        }
    }

    fn observation_with_event(observation_id: &str, event: EndpointEvent) -> EndpointObservation {
        EndpointObservation {
            observation_id: observation_id.to_string(),
            timestamp: Utc::now(),
            host_id: Some("host-1".to_string()),
            user_id: Some("user-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: EndpointProcess {
                process_guid: Some("proc-1".to_string()),
                image: Some("/bin/sh".to_string()),
                ..EndpointProcess::default()
            },
            event,
            metadata: BTreeMap::new(),
        }
    }
}
