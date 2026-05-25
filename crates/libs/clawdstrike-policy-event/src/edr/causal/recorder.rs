use std::collections::{BTreeMap, BTreeSet, VecDeque};

use chrono::{DateTime, Utc};

use super::super::event::{EndpointEvent, EndpointObservation, FileOperation};
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
                format!("process:{parent_guid}"),
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
                process_node,
                event_node.clone(),
                edge_kind,
                observation,
                BTreeMap::new(),
            );
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
        let key = observation.process.stable_key();
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
                let mut attributes = BTreeMap::new();
                insert_json(&mut attributes, "protocol", protocol);
                insert_json(&mut attributes, "url", url);
                Some((
                    self.ensure_node(
                        CausalNodeKind::Network,
                        format!("net:{host}:{port}"),
                        format!("{host}:{port}"),
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
                    CausalEdgeKind::Related,
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
