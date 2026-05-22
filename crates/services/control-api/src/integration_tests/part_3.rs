#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_ingest_treats_retries_without_canonical_evidence_fields_as_idempotent() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let event = serde_json::json!({
        "eventId": "hunt-idempotent-evt-1",
        "tenantId": harness.tenant_id.to_string(),
        "source": "tetragon",
        "kind": "process_exec",
        "occurredAt": "2026-03-06T12:00:00Z",
        "ingestedAt": "2026-03-06T12:00:01Z",
        "severity": "medium",
        "verdict": "allow",
        "summary": "idempotent duplicate",
        "actionType": "process",
        "evidence": {
            "rawRef": "hunt-envelope:idempotent-evt-1",
            "envelopeHash": "idempotent-hash-1",
            "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1"
        },
        "attributes": {
            "process": "/usr/bin/idempotent"
        }
    });

    let first = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request_without_canonical_evidence(
            &harness,
            event.clone(),
        )),
    )
    .await;
    assert_eq!(first.0, StatusCode::OK);
    assert_eq!(first.1["eventId"], "hunt-idempotent-evt-1");
    assert!(
        first.1["issuer"].as_str().is_some(),
        "stored event should expose canonical issuer"
    );
    assert_eq!(first.1["signatureValid"], true);

    let second = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request_without_canonical_evidence(
            &harness, event,
        )),
    )
    .await;
    assert_eq!(second.0, StatusCode::OK);
    assert_eq!(second.1, first.1);

    let count: i64 = sqlx::query_scalar::query_scalar(
        "SELECT COUNT(*) FROM hunt_events WHERE tenant_id = $1 AND event_id = $2",
    )
    .bind(harness.tenant_id)
    .bind("hunt-idempotent-evt-1")
    .fetch_one(&harness.db)
    .await
    .expect("count idempotent hunt events");
    assert_eq!(count, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hunt_correlation_and_ioc_jobs_store_results() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    seed_hunt_events(&harness).await;

    let correlate_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/correlate".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "rules": [{
                "schema": "clawdstrike.hunt.correlation.v1",
                "name": "curl_then_ssh",
                "severity": "high",
                "description": "curl followed by ssh",
                "window": "10m",
                "conditions": [
                    {
                        "bind": "curl",
                        "source": "tetragon",
                        "action_type": "process",
                        "target_pattern": "curl"
                    },
                    {
                        "bind": "ssh",
                        "source": "tetragon",
                        "action_type": "process",
                        "target_pattern": "ssh",
                        "after": "curl",
                        "within": "5m"
                    }
                ],
                "output": {
                    "title": "curl followed by ssh",
                    "evidence": ["curl", "ssh"]
                }
            }],
            "query": {
                "sessionId": "session-1",
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(correlate_resp.0, StatusCode::OK);
    assert_eq!(correlate_resp.1["jobType"], "correlate");
    assert_eq!(
        correlate_resp.1["result"]["findings"][0]["evidenceEventIds"][0],
        "hunt-evt-1"
    );
    assert_eq!(
        correlate_resp.1["result"]["findings"][0]["evidenceEventIds"][1],
        "hunt-evt-2"
    );

    let ioc_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/ioc/match".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "indicators": ["evil.com"],
            "query": {
                "sessionId": "session-1",
                "limit": 10
            }
        })),
    )
    .await;
    assert_eq!(ioc_resp.0, StatusCode::OK);
    assert_eq!(ioc_resp.1["jobType"], "ioc_match");
    assert_eq!(ioc_resp.1["result"]["matches"][0]["eventId"], "hunt-evt-1");

    let job_id = ioc_resp.1["id"].as_str().expect("job id");
    let get_job_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/jobs/{job_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_job_resp.0, StatusCode::OK);
    assert_eq!(get_job_resp.1["status"], "completed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_read_model_routes_project_tenant_scoped_data() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let overview_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/overview".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(overview_resp.0, StatusCode::OK);
    assert_eq!(overview_resp.1["counts"]["principals"], 2);
    assert_eq!(overview_resp.1["counts"]["endpointAgents"], 1);
    assert_eq!(overview_resp.1["counts"]["runtimeAgents"], 1);
    assert_eq!(overview_resp.1["counts"]["swarms"], 1);
    assert_eq!(overview_resp.1["counts"]["projects"], 1);
    assert_eq!(overview_resp.1["counts"]["quarantinedPrincipals"], 1);
    assert_eq!(overview_resp.1["counts"]["stalePrincipals"], 1);
    assert_eq!(overview_resp.1["counts"]["activeResponseActions"], 1);
    assert_eq!(overview_resp.1["counts"]["openDetections"], 1);
    assert_eq!(
        overview_resp.1["recentResponseActions"][0]["actionId"],
        fixture.action_id.to_string()
    );
    assert_eq!(
        overview_resp.1["recentDetections"][0]["principalId"],
        fixture.principal_id.to_string()
    );

    let principals_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/principals".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principals_resp.0, StatusCode::OK);
    let principals = principals_resp.1.as_array().expect("principals list");
    assert_eq!(principals.len(), 2);
    let principal = principals
        .iter()
        .find(|item| item["principalId"] == fixture.principal_id.to_string())
        .expect("primary principal in list");
    assert_eq!(principal["endpointPosture"], "nominal");
    assert_eq!(principal["openResponseActionCount"], 1);
    assert_eq!(principal["swarmNames"], serde_json::json!(["Fleet East"]));
    assert_eq!(
        principal["projectNames"],
        serde_json::json!(["Payments Prod"])
    );
    assert_eq!(
        principal["capabilityGroupNames"],
        serde_json::json!(["Responders"])
    );

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(
        detail_resp.1["memberships"]
            .as_array()
            .expect("memberships")
            .len(),
        3
    );
    assert_eq!(detail_resp.1["effectivePolicy"]["resolutionVersion"], 4);
    let compiled_policy = detail_resp.1["compiledPolicyYaml"]
        .as_str()
        .expect("compiled policy yaml");
    assert!(compiled_policy.contains("mode: swarm"));
    assert!(compiled_policy.contains("region: east"));
    assert!(compiled_policy.contains("final: true"));
    assert_eq!(
        detail_resp.1["sourceAttachments"]
            .as_array()
            .expect("source attachments")
            .len(),
        3
    );
    assert_eq!(
        detail_resp.1["activeGrants"][0]["grantId"],
        fixture.grant_id.to_string()
    );
    assert_eq!(detail_resp.1["recentSessions"][0]["sessionId"], "session-1");

    let timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!(
            "/api/v1/console/timeline?principal_id={}",
            fixture.principal_id
        ),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    let timeline = timeline_resp.1.as_array().expect("timeline list");
    assert_eq!(timeline.len(), 2);
    assert_eq!(timeline[0]["eventId"], "console-hunt-2");
    assert_eq!(timeline[1]["eventId"], "console-hunt-1");

    let principal_timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!(
            "/api/v1/console/principals/{}/timeline",
            fixture.principal_id
        ),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principal_timeline_resp.0, StatusCode::OK);
    assert_eq!(
        principal_timeline_resp
            .1
            .as_array()
            .expect("principal timeline")
            .len(),
        2
    );

    let actions_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/response-actions".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(actions_resp.0, StatusCode::OK);
    let actions = actions_resp.1.as_array().expect("response actions list");
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0]["targetDisplayName"], "Planner MacBook");

    let graph_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}/graph", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(graph_resp.0, StatusCode::OK);
    assert_eq!(
        graph_resp.1["rootPrincipalId"],
        fixture.principal_id.to_string()
    );
    assert!(graph_resp.1["nodes"]
        .as_array()
        .expect("graph nodes")
        .iter()
        .any(|node| node["id"] == fixture.grant_id.to_string()));
    assert!(graph_resp.1["edges"]
        .as_array()
        .expect("graph edges")
        .iter()
        .any(|edge| edge["kind"] == "received_grant"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_principal_detail_rejects_unresolved_policy_refs() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    sqlx::query::query(
        r#"INSERT INTO policy_attachments (
               tenant_id,
               target_kind,
               priority,
               policy_ref,
               checksum_sha256,
               created_by
           ) VALUES ($1, 'tenant', 5, 'catalog/default', 'checksum-unresolved', 'integration')"#,
    )
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed unresolved policy attachment");

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::CONFLICT);
    let error = detail_resp.1["error"]
        .as_str()
        .expect("console policy error");
    assert!(
        error.contains("unresolved policy_ref`catalog/default`")
            || error.contains("unresolved policy_ref `catalog/default`")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn console_timeline_and_sessions_match_principal_aliases() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    sqlx::query::query(
        "UPDATE hunt_events SET principal_id = $3 WHERE tenant_id = $1 AND principal_id = $2",
    )
    .bind(harness.tenant_id)
    .bind(fixture.principal_id.to_string())
    .bind(&fixture.principal_stable_ref)
    .execute(&harness.db)
    .await
    .expect("rewrite hunt principal aliases");

    let detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{}", fixture.principal_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(detail_resp.0, StatusCode::OK);
    assert_eq!(detail_resp.1["recentSessions"][0]["sessionId"], "session-1");

    let timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!(
            "/api/v1/console/principals/{}/timeline",
            fixture.principal_id
        ),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    let timeline = timeline_resp.1.as_array().expect("principal timeline");
    assert_eq!(timeline.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fleet_operator_workflow_links_detection_response_case_hunt_graph_and_console() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let OperatorFlowFixture {
        agent_id,
        session_id,
        detection_raw_ref,
        response_raw_ref,
        principal_id,
        response_subject,
        grant_id,
        finding_id,
        case_id,
        action_id,
    } = seed_operator_flow_fixture(&harness).await;
    let mut subscriber = harness
        .nats
        .subscribe(response_subject.clone())
        .await
        .expect("subscribe response subject");
    harness.nats.flush().await.expect("nats flush");

    let finding_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/detections/findings/{finding_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(finding_resp.0, StatusCode::OK);
    assert_eq!(finding_resp.1["principal_id"], principal_id.to_string());
    assert_eq!(finding_resp.1["grant_id"], grant_id.to_string());
    assert_eq!(
        finding_resp.1["response_action_ids"],
        serde_json::json!([action_id.to_string()])
    );
    assert_eq!(
        finding_resp.1["evidence_refs"],
        serde_json::json!([detection_raw_ref])
    );

    let finding_list_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/detections/findings?principal_id={principal_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(finding_list_resp.0, StatusCode::OK);
    assert_eq!(
        finding_list_resp.1.as_array().expect("findings list").len(),
        1
    );

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(approve_resp.1["action"]["status"], "published");
    assert_eq!(approve_resp.1["deliveries"][0]["status"], "published");
    assert_eq!(
        approve_resp.1["deliveries"][0]["delivery_subject"],
        response_subject
    );

    let published_message = tokio::time::timeout(Duration::from_secs(5), subscriber.next())
        .await
        .expect("response action publish timeout")
        .expect("subscriber stream ended");
    let envelope: Value = serde_json::from_slice(&published_message.payload)
        .expect("response payload should be JSON");
    assert!(
        spine::verify_envelope(&envelope).expect("response action envelope should verify"),
        "response action payload must be a signed spine envelope"
    );
    assert_eq!(envelope["fact"]["actionId"], action_id.to_string());
    assert_eq!(
        envelope["fact"]["sourceDetectionId"],
        finding_id.to_string()
    );
    assert_eq!(envelope["fact"]["caseId"], case_id);
    assert_eq!(
        envelope["fact"]["actionType"],
        "policy_rule_diff_validation"
    );

    let overview_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/overview".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(overview_resp.0, StatusCode::OK);
    assert_eq!(overview_resp.1["counts"]["principals"], 1);
    assert_eq!(overview_resp.1["counts"]["endpointAgents"], 1);
    assert_eq!(overview_resp.1["counts"]["activeResponseActions"], 1);
    assert_eq!(overview_resp.1["counts"]["openDetections"], 1);
    assert_eq!(
        overview_resp.1["recentDetections"][0]["detectionId"],
        finding_id.to_string()
    );
    assert_eq!(
        overview_resp.1["recentResponseActions"][0]["actionId"],
        action_id.to_string()
    );

    let detection_event_id = "operator-flow-hunt-1";
    let detection_event_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(
            &harness,
            serde_json::json!({
                "eventId": detection_event_id,
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T13:00:00Z",
                "ingestedAt": "2026-03-06T13:00:01Z",
                "severity": "high",
                "verdict": "allow",
                "summary": "curl execution on Operator Endpoint triggered detection",
                "actionType": "process",
                "principal": {
                    "principalId": principal_id.to_string(),
                    "endpointAgentId": agent_id,
                    "principalType": "endpoint_agent"
                },
                "sessionId": session_id,
                "grantId": grant_id.to_string(),
                "detectionIds": [finding_id.to_string()],
                "target": {
                    "kind": "process",
                    "id": "2001",
                    "name": "curl"
                },
                "evidence": {
                    "rawRef": detection_raw_ref,
                    "envelopeHash": "hash-operator-flow-detection-1",
                    "issuer": "spiffe://tenant/acme-int",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/curl",
                    "pod": "operator-endpoint",
                    "url": "https://evil.example/payload"
                }
            }),
        )),
    )
    .await;
    assert_eq!(detection_event_resp.0, StatusCode::OK);

    let response_event_id = "operator-flow-hunt-2";
    let response_event_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/events/ingest".to_string(),
        Some(&harness.api_key),
        Some(signed_hunt_ingest_request(
            &harness,
            serde_json::json!({
                "eventId": response_event_id,
                "tenantId": harness.tenant_id.to_string(),
                "source": "response",
                "kind": "response_action_updated",
                "occurredAt": "2026-03-06T13:05:00Z",
                "ingestedAt": "2026-03-06T13:05:01Z",
                "severity": "medium",
                "verdict": "deny",
                "summary": "response action published for Operator Endpoint",
                "actionType": "policy_rule_diff_validation",
                "principal": {
                    "principalId": principal_id.to_string(),
                    "endpointAgentId": agent_id,
                    "principalType": "endpoint_agent"
                },
                "sessionId": session_id,
                "grantId": grant_id.to_string(),
                "responseActionId": action_id.to_string(),
                "detectionIds": [finding_id.to_string()],
                "target": {
                    "kind": "endpoint",
                    "id": agent_id,
                    "name": "Operator Endpoint"
                },
                "evidence": {
                    "rawRef": response_raw_ref,
                    "envelopeHash": "hash-operator-flow-response-1",
                    "issuer": "spiffe://tenant/acme-int",
                    "schemaName": "clawdstrike.sdr.fact.response_action.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "status": "published",
                    "message": "policy reload published"
                }
            }),
        )),
    )
    .await;
    assert_eq!(response_event_resp.0, StatusCode::OK);

    let update_case_resp = request_json(
        &harness.app,
        Method::PATCH,
        format!("/api/v1/cases/{case_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "status": "in_progress",
            "responseActionIds": [action_id.to_string()],
            "grantIds": [grant_id.to_string()]
        })),
    )
    .await;
    assert_eq!(update_case_resp.0, StatusCode::OK);
    assert_eq!(update_case_resp.1["status"], "in_progress");
    assert_eq!(
        update_case_resp.1["responseActionIds"],
        serde_json::json!([action_id.to_string()])
    );
    assert_eq!(
        update_case_resp.1["grantIds"],
        serde_json::json!([grant_id.to_string()])
    );

    let exercise_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/grants/{grant_id}/exercise"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "event_id": response_event_id,
            "session_id": session_id,
            "response_action_id": action_id.to_string(),
        })),
    )
    .await;
    assert_eq!(exercise_resp.0, StatusCode::OK);
    assert!(exercise_resp.1["edges"]
        .as_array()
        .expect("grant exercise edges")
        .iter()
        .any(|edge| edge["kind"] == "exercised_in_event"));

    let search_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/search".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "principalId": principal_id.to_string(),
            "limit": 10
        })),
    )
    .await;
    assert_eq!(search_resp.0, StatusCode::OK);
    assert_eq!(search_resp.1["total"], 2);
    assert_eq!(search_resp.1["events"][0]["eventId"], response_event_id);
    assert_eq!(search_resp.1["events"][1]["eventId"], detection_event_id);
    assert_eq!(
        search_resp.1["events"][0]["responseActionId"],
        action_id.to_string()
    );
    assert_eq!(
        search_resp.1["events"][0]["detectionIds"],
        serde_json::json!([finding_id.to_string()])
    );

    let timeline_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/timeline".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "sessionId": session_id,
            "limit": 10
        })),
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    assert_eq!(timeline_resp.1["groupedBy"], "session");
    assert_eq!(timeline_resp.1["events"][0]["eventId"], detection_event_id);
    assert_eq!(timeline_resp.1["events"][1]["eventId"], response_event_id);

    let raw_graph_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/principals/{principal_id}/delegation-graph"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(raw_graph_resp.0, StatusCode::OK);
    assert_eq!(
        raw_graph_resp.1["root_node_id"],
        format!("principal:{principal_id}")
    );
    assert!(raw_graph_resp.1["nodes"]
        .as_array()
        .expect("raw graph nodes")
        .iter()
        .any(|node| node["id"] == format!("grant:{grant_id}")));
    assert!(raw_graph_resp.1["nodes"]
        .as_array()
        .expect("raw graph nodes")
        .iter()
        .any(|node| node["id"] == format!("response_action:{action_id}")));
    assert!(raw_graph_resp.1["edges"]
        .as_array()
        .expect("raw graph edges")
        .iter()
        .any(|edge| edge["kind"] == "issued_grant"));
    assert!(raw_graph_resp.1["edges"]
        .as_array()
        .expect("raw graph edges")
        .iter()
        .any(|edge| edge["kind"] == "triggered_response_action"));

    let path_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/graph/paths?from=principal:{principal_id}&to=response_action:{action_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(path_resp.0, StatusCode::OK);
    assert_eq!(
        path_resp.1["root_node_id"],
        format!("principal:{principal_id}")
    );
    assert!(path_resp.1["edges"]
        .as_array()
        .expect("path edges")
        .iter()
        .any(|edge| edge["kind"] == "triggered_response_action"));

    for artifact_request in [
        serde_json::json!({
            "artifactKind": "detection",
            "artifactId": finding_id.to_string(),
            "summary": "Detection finding",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "ocsf": finding_resp.1["ocsf"].clone(),
                "evidenceRefs": finding_resp.1["evidence_refs"].clone()
            }
        }),
        serde_json::json!({
            "artifactKind": "response_action",
            "artifactId": action_id.to_string(),
            "summary": "Response action publication",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "status": "published",
                "caseId": case_id,
                "sourceDetectionId": finding_id.to_string()
            }
        }),
        serde_json::json!({
            "artifactKind": "graph_snapshot",
            "artifactId": format!("principal:{principal_id}->response_action:{action_id}"),
            "summary": "Principal to response-action graph path",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "graph": path_resp.1.clone()
            }
        }),
        serde_json::json!({
            "artifactKind": "fleet_event",
            "artifactId": detection_event_id,
            "summary": "Detection hunt event",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "eventId": detection_event_id,
                "rawRef": detection_raw_ref,
                "detectionIds": [finding_id.to_string()]
            }
        }),
        serde_json::json!({
            "artifactKind": "raw_envelope",
            "artifactId": detection_raw_ref,
            "summary": "Detection raw envelope",
            "metadata": {
                "principalId": principal_id.to_string(),
                "detectionId": finding_id.to_string(),
                "responseActionId": action_id.to_string(),
                "rawRef": detection_raw_ref,
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1"
            }
        }),
    ] {
        let artifact_resp = request_json(
            &harness.app,
            Method::POST,
            format!("/api/v1/cases/{case_id}/artifacts"),
            Some(&harness.api_key),
            Some(artifact_request),
        )
        .await;
        assert_eq!(artifact_resp.0, StatusCode::OK);
    }

    let export_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{case_id}/evidence/export"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "principalIds": [principal_id.to_string()],
            "detectionIds": [finding_id.to_string()],
            "responseActionIds": [action_id.to_string()],
            "includeRawEnvelopes": true,
            "includeOcsf": true,
            "retentionDays": 7
        })),
    )
    .await;
    assert_eq!(export_resp.0, StatusCode::OK);
    assert_eq!(export_resp.1["status"], "completed");
    assert_eq!(export_resp.1["artifactCounts"]["detection"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["response_action"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["graph_snapshot"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["fleet_event"], 1);
    assert_eq!(export_resp.1["artifactCounts"]["raw_envelope"], 1);
    let export_id = export_resp.1["exportId"].as_str().expect("export id");
    let export_path = export_resp.1["filePath"]
        .as_str()
        .expect("bundle file path");
    assert!(std::path::Path::new(export_path).exists());

    let bundle_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{export_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(bundle_resp.0, StatusCode::OK);
    assert_eq!(bundle_resp.1["status"], "completed");

    let case_detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{case_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(case_detail_resp.0, StatusCode::OK);
    assert_eq!(
        case_detail_resp.1["case"]["responseActionIds"],
        serde_json::json!([action_id.to_string()])
    );
    assert_eq!(
        case_detail_resp.1["case"]["grantIds"],
        serde_json::json!([grant_id.to_string()])
    );
    assert_eq!(
        case_detail_resp.1["artifacts"]
            .as_array()
            .expect("case artifacts")
            .len(),
        6
    );
    assert_eq!(
        case_detail_resp.1["evidenceBundles"]
            .as_array()
            .expect("case bundles")
            .len(),
        1
    );

    let case_timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{case_id}/timeline"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(case_timeline_resp.0, StatusCode::OK);
    let case_timeline = case_timeline_resp.1.as_array().expect("case timeline");
    let event_kinds = case_timeline
        .iter()
        .filter_map(|event| event["eventKind"].as_str())
        .collect::<Vec<_>>();
    assert!(event_kinds.contains(&"case_created"));
    assert!(event_kinds.contains(&"status_changed"));
    assert!(event_kinds.contains(&"case_updated"));
    assert!(event_kinds.contains(&"bundle_requested"));
    assert!(event_kinds.contains(&"bundle_completed"));
    assert_eq!(
        event_kinds
            .iter()
            .filter(|kind| **kind == "artifact_added")
            .count(),
        5
    );

    let principals_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/principals".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principals_resp.0, StatusCode::OK);
    let principals = principals_resp.1.as_array().expect("console principals");
    assert_eq!(principals.len(), 1);
    assert_eq!(principals[0]["principalId"], principal_id.to_string());
    assert_eq!(principals[0]["displayName"], "Operator Endpoint");

    let principal_detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{principal_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(principal_detail_resp.0, StatusCode::OK);
    assert_eq!(
        principal_detail_resp.1["principal"]["principalId"],
        principal_id.to_string()
    );
    assert_eq!(
        principal_detail_resp.1["activeGrants"][0]["grantId"],
        grant_id.to_string()
    );
    assert_eq!(
        principal_detail_resp.1["recentSessions"][0]["sessionId"],
        session_id
    );

    let console_actions_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/console/response-actions".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(console_actions_resp.0, StatusCode::OK);
    let console_actions = console_actions_resp
        .1
        .as_array()
        .expect("console response actions");
    assert_eq!(console_actions.len(), 1);
    assert_eq!(console_actions[0]["status"], "published");
    assert_eq!(console_actions[0]["targetDisplayName"], "Operator Endpoint");
    assert_eq!(
        console_actions[0]["sourceDetectionId"],
        finding_id.to_string()
    );

    let console_timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/timeline?principal_id={principal_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(console_timeline_resp.0, StatusCode::OK);
    let console_timeline = console_timeline_resp
        .1
        .as_array()
        .expect("console timeline");
    assert_eq!(console_timeline.len(), 2);
    assert_eq!(console_timeline[0]["eventId"], response_event_id);
    assert_eq!(
        console_timeline[0]["metadata"]["responseActionId"],
        action_id.to_string()
    );
    assert_eq!(
        console_timeline[0]["metadata"]["detectionIds"],
        serde_json::json!([finding_id.to_string()])
    );

    let console_graph_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/console/principals/{principal_id}/graph"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(console_graph_resp.0, StatusCode::OK);
    assert_eq!(
        console_graph_resp.1["rootPrincipalId"],
        principal_id.to_string()
    );
    assert!(console_graph_resp.1["nodes"]
        .as_array()
        .expect("console graph nodes")
        .iter()
        .any(|node| node["id"] == grant_id.to_string()));
    assert!(console_graph_resp.1["nodes"]
        .as_array()
        .expect("console graph nodes")
        .iter()
        .any(|node| node["id"] == action_id.to_string()));
    assert!(console_graph_resp.1["edges"]
        .as_array()
        .expect("console graph edges")
        .iter()
        .any(|edge| edge["kind"] == "triggered_response_action"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_list_filters_by_query_status_and_severity() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    for payload in [
        serde_json::json!({
            "title": "Endpoint archive case",
            "summary": "Retained archive investigation",
            "severity": "high",
            "status": "open",
            "tags": ["endpoint-evidence"]
        }),
        serde_json::json!({
            "title": "Closed phishing investigation",
            "summary": "Browser download credential theft",
            "severity": "low",
            "status": "closed",
            "tags": ["phishing"]
        }),
        serde_json::json!({
            "title": "Closed high impact investigation",
            "summary": "Credential theft",
            "severity": "high",
            "status": "closed",
            "tags": ["phishing"]
        }),
    ] {
        let case_resp = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/cases".to_string(),
            Some(&harness.api_key),
            Some(payload),
        )
        .await;
        assert_eq!(case_resp.0, StatusCode::OK);
    }

    let filtered_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/cases?q=phishing&status=closed&severity=low".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(filtered_resp.0, StatusCode::OK);
    let cases = filtered_resp.1.as_array().expect("case list");
    assert_eq!(cases.len(), 1);
    assert_eq!(cases[0]["title"], "Closed phishing investigation");
    assert_eq!(cases[0]["status"], "closed");
    assert_eq!(cases[0]["severity"], "low");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_bulk_status_transition_updates_selected_cases_and_timeline() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let mut case_ids = Vec::new();

    for payload in [
        serde_json::json!({
            "title": "Bulk transition primary",
            "summary": "selected for bulk closure",
            "severity": "high",
            "status": "open",
            "tags": ["bulk-lifecycle"]
        }),
        serde_json::json!({
            "title": "Bulk transition secondary",
            "summary": "also selected for bulk closure",
            "severity": "medium",
            "status": "in_progress",
            "tags": ["bulk-lifecycle"]
        }),
        serde_json::json!({
            "title": "Bulk transition untouched",
            "summary": "must remain open",
            "severity": "low",
            "status": "open",
            "tags": ["bulk-lifecycle"]
        }),
    ] {
        let case_resp = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/cases".to_string(),
            Some(&harness.api_key),
            Some(payload),
        )
        .await;
        assert_eq!(case_resp.0, StatusCode::OK);
        case_ids.push(
            case_resp.1["id"]
                .as_str()
                .expect("created case id")
                .to_string(),
        );
    }

    let bulk_request = Request::builder()
        .method(Method::PATCH)
        .uri("/api/v1/cases/bulk")
        .header("content-type", "application/json")
        .header("x-api-key", &harness.api_key)
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "caseIds": [case_ids[0], case_ids[1]],
                "status": "closed"
            }))
            .expect("serialize bulk body"),
        ))
        .expect("build bulk request");
    let bulk_response = harness
        .app
        .clone()
        .oneshot(bulk_request)
        .await
        .expect("bulk route request");
    let bulk_status = bulk_response.status();
    let bulk_bytes = to_bytes(bulk_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read bulk response body");
    assert_eq!(bulk_status, StatusCode::OK);
    let bulk_body = serde_json::from_slice::<Value>(&bulk_bytes).expect("bulk response json");
    let updated = bulk_body.as_array().expect("updated cases");
    assert_eq!(updated.len(), 2);
    assert!(updated.iter().all(|case| case["status"] == "closed"));

    let closed_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/cases?status=closed&q=bulk-lifecycle".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(closed_resp.0, StatusCode::OK);
    assert_eq!(closed_resp.1.as_array().expect("closed cases").len(), 2);

    let untouched_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{}", case_ids[2]),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(untouched_resp.0, StatusCode::OK);
    assert_eq!(untouched_resp.1["case"]["status"], "open");

    let timeline_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{}/timeline", case_ids[0]),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(timeline_resp.0, StatusCode::OK);
    let timeline = timeline_resp.1.as_array().expect("case timeline");
    assert!(timeline.iter().any(|event| {
        event["eventKind"] == "status_changed"
            && event["payload"]["previousStatus"] == "open"
            && event["payload"]["status"] == "closed"
            && event["payload"]["bulk"] == true
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn case_artifacts_require_verified_references_and_mark_annotations_untrusted() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_operator_flow_fixture(&harness).await;

    let missing_event_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "fleet_event",
            "artifactId": "missing-event",
            "summary": "spoofed event",
            "metadata": {
                "artifactClass": "verified_reference",
                "sourceTable": "hunt_events"
            }
        })),
    )
    .await;
    assert_eq!(missing_event_resp.0, StatusCode::NOT_FOUND);

    let missing_envelope_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "raw_envelope",
            "artifactId": "missing-envelope",
            "summary": "spoofed envelope",
            "metadata": {
                "artifactClass": "verified_reference",
                "sourceTable": "hunt_envelopes"
            }
        })),
    )
    .await;
    assert_eq!(missing_envelope_resp.0, StatusCode::NOT_FOUND);

    let missing_archive_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "endpoint_evidence_archive",
            "artifactId": "missing-archive",
            "summary": "spoofed archive",
            "metadata": {
                "artifactClass": "verified_reference",
                "sourceTable": "endpoint_evidence_archives"
            }
        })),
    )
    .await;
    assert_eq!(missing_archive_resp.0, StatusCode::NOT_FOUND);

    let bundle_export_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "bundle_export",
            "artifactId": "export-1",
            "summary": "should be rejected",
            "metadata": {}
        })),
    )
    .await;
    assert_eq!(bundle_export_resp.0, StatusCode::BAD_REQUEST);

    let archive = serde_json::json!({
        "schemaVersion": 1,
        "bundle": {
            "bundleId": "evidence_bundle-case-1",
            "graphSliceId": "graph_slice-case-1",
            "contentHash": "0xcontentcase"
        },
        "artifact": {
            "byteCount": 96
        },
        "graph": {
            "nodes": {
                "process:case": {
                    "nodeId": "process:case",
                    "kind": "process",
                    "label": "python"
                }
            },
            "edges": []
        },
        "receipts": []
    });
    let archive_hash = canonical_json_hash_for_test(&archive);
    let archive_id = "evidence_bundle_archive-case-1";
    let archive_raw_ref = format!("endpoint-evidence-bundle-archive:{archive_id}:{archive_hash}");
    let upload_archive_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hunt/evidence-bundle-archives".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "archiveId": archive_id,
            "archiveHash": archive_hash,
            "rawRef": archive_raw_ref,
            "bundleId": "evidence_bundle-case-1",
            "endpointAgentId": &fixture.agent_id,
            "eventId": format!("evidence-bundle-archive:{}:{archive_id}", &fixture.agent_id),
            "rawArtifactApprovalId": "approval-archive-case-1",
            "rawArtifactApprovalReasonHash": "0x3333333333333333",
            "archive": archive,
            "verification": {
                "verified": true,
                "archiveHashMatches": true
            },
            "retentionDays": 30,
            "metadata": {
                "source": "agent"
            }
        })),
    )
    .await;
    assert_eq!(upload_archive_resp.0, StatusCode::OK);

    let archive_artifact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "endpoint_evidence_archive",
            "artifactId": archive_id,
            "summary": "spoofed archive summary",
            "metadata": {
                "artifactClass": "operator_annotation",
                "sourceTable": "spoofed"
            }
        })),
    )
    .await;
    assert_eq!(archive_artifact_resp.0, StatusCode::OK);

    let response_action_artifact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "response_action",
            "artifactId": fixture.action_id.to_string(),
            "summary": "spoofed response summary",
            "metadata": {
                "artifactClass": "verified_reference",
                "status": "acknowledged",
                "sourceTable": "totally_fake"
            }
        })),
    )
    .await;
    assert_eq!(response_action_artifact_resp.0, StatusCode::OK);

    let note_artifact_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/artifacts", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "artifactKind": "note",
            "artifactId": "operator-note-1",
            "summary": "operator note",
            "metadata": {
                "artifactClass": "verified_reference",
                "message": "manual analyst note"
            }
        })),
    )
    .await;
    assert_eq!(note_artifact_resp.0, StatusCode::OK);

    let case_detail_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/cases/{}", fixture.case_id),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(case_detail_resp.0, StatusCode::OK);
    let artifacts = case_detail_resp.1["artifacts"]
        .as_array()
        .expect("case artifacts");

    let response_action_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact["artifactKind"] == "response_action"
                && artifact["artifactId"] == fixture.action_id.to_string()
        })
        .expect("response_action artifact");
    assert_eq!(
        response_action_artifact["summary"],
        format!(
            "policy_rule_diff_validation -> endpoint:{}",
            fixture.agent_id
        )
    );
    assert_eq!(
        response_action_artifact["metadata"]["artifactClass"],
        "verified_reference"
    );
    assert_eq!(
        response_action_artifact["metadata"]["sourceTable"],
        "response_actions"
    );
    assert_eq!(response_action_artifact["metadata"]["status"], "queued");

    let archive_artifact = artifacts
        .iter()
        .find(|artifact| {
            artifact["artifactKind"] == "endpoint_evidence_archive"
                && artifact["artifactId"] == archive_id
        })
        .expect("endpoint_evidence_archive artifact");
    assert_eq!(
        archive_artifact["summary"],
        "endpoint evidence archive evidence_bundle-case-1"
    );
    assert_eq!(
        archive_artifact["metadata"]["artifactClass"],
        "verified_reference"
    );
    assert_eq!(
        archive_artifact["metadata"]["sourceTable"],
        "endpoint_evidence_archives"
    );
    assert_eq!(
        archive_artifact["metadata"]["sourceFamily"],
        "endpoint_evidence_archive"
    );
    assert_eq!(archive_artifact["metadata"]["rawRef"], archive_raw_ref);
    assert_eq!(archive_artifact["metadata"]["archiveHash"], archive_hash);
    assert_eq!(
        archive_artifact["metadata"]["endpointAgentId"],
        fixture.agent_id
    );
    assert_eq!(
        archive_artifact["metadata"]["verification"]["verified"],
        true
    );
    assert_eq!(
        archive_artifact["metadata"]["archiveMetadata"]["source"],
        "agent"
    );

    let note_artifact = artifacts
        .iter()
        .find(|artifact| artifact["artifactKind"] == "note")
        .expect("note artifact");
    assert_eq!(
        note_artifact["metadata"]["artifactClass"],
        "operator_annotation"
    );
    assert_eq!(note_artifact["metadata"]["message"], "manual analyst note");

    let member_api_key = "cs_it_case_archive_member_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_api_key,
        "case-archive-member",
        &["write"],
    )
    .await;
    let denied_archive_download_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hunt/evidence-bundle-archives/{archive_id}/download"),
        Some(member_api_key),
        None,
    )
    .await;
    assert_eq!(denied_archive_download_resp.0, StatusCode::FORBIDDEN);

    let case_bundle_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/evidence/export", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "includeRawEnvelopes": true
        })),
    )
    .await;
    assert_eq!(case_bundle_resp.0, StatusCode::OK);
    assert_eq!(
        case_bundle_resp.1["artifactCounts"]["endpoint_evidence_archive"],
        1
    );
    assert_eq!(case_bundle_resp.1["artifactCounts"]["audit_event"], 2);
    let case_bundle_export_id = case_bundle_resp.1["exportId"]
        .as_str()
        .expect("case bundle export id");
    let bundle_exported_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.exported'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("bundle export should be audited");
    let bundle_exported_metadata: Value = bundle_exported_audit_row
        .try_get("metadata")
        .expect("bundle export audit metadata");
    assert_eq!(
        bundle_exported_audit_row
            .try_get::<String, _>("event_type")
            .expect("bundle export event type"),
        "case_evidence_bundle.exported"
    );
    assert_eq!(
        bundle_exported_audit_row
            .try_get::<i32, _>("quantity")
            .expect("bundle export quantity"),
        1
    );
    assert_eq!(bundle_exported_metadata["exportId"], case_bundle_export_id);
    assert_eq!(
        bundle_exported_metadata["caseId"],
        fixture.case_id.to_string()
    );
    assert_eq!(
        bundle_exported_metadata["artifactCounts"]["endpoint_evidence_archive"],
        1
    );
    assert_eq!(bundle_exported_metadata["artifactCounts"]["audit_event"], 2);
    assert_eq!(bundle_exported_metadata["actorType"], "service");
    assert_eq!(bundle_exported_metadata["actorRole"], "admin");
    assert!(bundle_exported_metadata["sha256"].as_str().is_some());
    assert!(bundle_exported_metadata["sizeBytes"].as_i64().is_some());
    assert!(bundle_exported_metadata.get("bundle").is_none());

    let admin_bundle_metadata_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{case_bundle_export_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(admin_bundle_metadata_resp.0, StatusCode::OK);
    assert_eq!(
        admin_bundle_metadata_resp.1["exportId"],
        case_bundle_export_id
    );
    let bundle_metadata_access_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.metadata_accessed'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("bundle metadata access should be audited");
    let bundle_metadata_access: Value = bundle_metadata_access_audit_row
        .try_get("metadata")
        .expect("bundle metadata access audit metadata");
    assert_eq!(
        bundle_metadata_access_audit_row
            .try_get::<String, _>("event_type")
            .expect("bundle metadata access event type"),
        "case_evidence_bundle.metadata_accessed"
    );
    assert_eq!(
        bundle_metadata_access_audit_row
            .try_get::<i32, _>("quantity")
            .expect("bundle metadata access quantity"),
        1
    );
    assert_eq!(bundle_metadata_access["exportId"], case_bundle_export_id);
    assert_eq!(
        bundle_metadata_access["caseId"],
        fixture.case_id.to_string()
    );
    assert_eq!(bundle_metadata_access["actorType"], "service");
    assert_eq!(bundle_metadata_access["actorRole"], "admin");
    assert!(bundle_metadata_access["sha256"].as_str().is_some());
    assert!(bundle_metadata_access["sizeBytes"].as_i64().is_some());
    assert!(bundle_metadata_access.get("bundle").is_none());

    let viewer_api_key = "cs_it_case_bundle_viewer_key";
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_api_key,
        "case-bundle-viewer",
        &["viewer"],
    )
    .await;
    let viewer_create_bundle_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/evidence/export", fixture.case_id),
        Some(viewer_api_key),
        Some(serde_json::json!({
            "includeRawEnvelopes": true
        })),
    )
    .await;
    assert_eq!(viewer_create_bundle_resp.0, StatusCode::FORBIDDEN);
    let denied_bundle_export_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.export_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied bundle export should be audited");
    let denied_bundle_export: Value = denied_bundle_export_row
        .try_get("metadata")
        .expect("denied bundle export audit metadata");
    assert_eq!(
        denied_bundle_export_row
            .try_get::<String, _>("event_type")
            .expect("denied bundle export event type"),
        "case_evidence_bundle.export_denied"
    );
    assert_eq!(
        denied_bundle_export_row
            .try_get::<i32, _>("quantity")
            .expect("denied bundle export quantity"),
        1
    );
    assert_eq!(denied_bundle_export["caseId"], fixture.case_id.to_string());
    assert_eq!(denied_bundle_export["actorType"], "service");
    assert_eq!(denied_bundle_export["actorRole"], "viewer");
    assert_eq!(denied_bundle_export["deniedReason"], "non_viewer_required");
    assert!(denied_bundle_export.get("bundle").is_none());

    let viewer_bundle_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/evidence-bundles/{case_bundle_export_id}"),
        Some(viewer_api_key),
        None,
    )
    .await;
    assert_eq!(viewer_bundle_resp.0, StatusCode::FORBIDDEN);

    let viewer_download_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/evidence-bundles/{case_bundle_export_id}/download"
        ))
        .header("x-api-key", viewer_api_key)
        .body(Body::empty())
        .expect("build viewer bundle download request");
    let viewer_download_response = harness
        .app
        .clone()
        .oneshot(viewer_download_request)
        .await
        .expect("viewer bundle download request");
    assert_eq!(viewer_download_response.status(), StatusCode::FORBIDDEN);
    let denied_bundle_metadata_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.metadata_access_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied bundle metadata access should be audited");
    let denied_bundle_metadata: Value = denied_bundle_metadata_row
        .try_get("metadata")
        .expect("denied bundle metadata audit metadata");
    assert_eq!(
        denied_bundle_metadata_row
            .try_get::<String, _>("event_type")
            .expect("denied bundle metadata event type"),
        "case_evidence_bundle.metadata_access_denied"
    );
    assert_eq!(
        denied_bundle_metadata_row
            .try_get::<i32, _>("quantity")
            .expect("denied bundle metadata quantity"),
        1
    );
    assert_eq!(denied_bundle_metadata["exportId"], case_bundle_export_id);
    assert_eq!(denied_bundle_metadata["actorType"], "service");
    assert_eq!(denied_bundle_metadata["actorRole"], "viewer");
    assert_eq!(
        denied_bundle_metadata["deniedReason"],
        "non_viewer_required"
    );
    assert!(denied_bundle_metadata.get("bundle").is_none());

    let denied_bundle_download_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.download_denied'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("denied bundle download should be audited");
    let denied_bundle_download: Value = denied_bundle_download_row
        .try_get("metadata")
        .expect("denied bundle download audit metadata");
    assert_eq!(
        denied_bundle_download_row
            .try_get::<String, _>("event_type")
            .expect("denied bundle download event type"),
        "case_evidence_bundle.download_denied"
    );
    assert_eq!(
        denied_bundle_download_row
            .try_get::<i32, _>("quantity")
            .expect("denied bundle download quantity"),
        1
    );
    assert_eq!(denied_bundle_download["exportId"], case_bundle_export_id);
    assert_eq!(denied_bundle_download["actorType"], "service");
    assert_eq!(denied_bundle_download["actorRole"], "viewer");
    assert_eq!(
        denied_bundle_download["deniedReason"],
        "non_viewer_required"
    );
    assert!(denied_bundle_download.get("bundle").is_none());

    let admin_download_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/evidence-bundles/{case_bundle_export_id}/download"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build admin bundle download request");
    let admin_download_response = harness
        .app
        .clone()
        .oneshot(admin_download_request)
        .await
        .expect("admin bundle download request");
    assert_eq!(admin_download_response.status(), StatusCode::OK);
    let admin_bundle_bytes = to_bytes(admin_download_response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read admin bundle body");
    let bundle_download_audit_row = sqlx::query::query(
        r#"SELECT event_type, quantity, metadata
           FROM usage_events
           WHERE tenant_id = $1
             AND event_type = 'case_evidence_bundle.downloaded'"#,
    )
    .bind(harness.tenant_id)
    .fetch_one(&harness.db)
    .await
    .expect("bundle download should be audited");
    let bundle_download_metadata: Value = bundle_download_audit_row
        .try_get("metadata")
        .expect("bundle download audit metadata");
    assert_eq!(
        bundle_download_audit_row
            .try_get::<String, _>("event_type")
            .expect("bundle download event type"),
        "case_evidence_bundle.downloaded"
    );
    assert_eq!(
        bundle_download_audit_row
            .try_get::<i32, _>("quantity")
            .expect("bundle download quantity"),
        1
    );
    assert_eq!(bundle_download_metadata["exportId"], case_bundle_export_id);
    assert_eq!(
        bundle_download_metadata["caseId"],
        fixture.case_id.to_string()
    );
    assert_eq!(bundle_download_metadata["actorType"], "service");
    assert_eq!(bundle_download_metadata["actorRole"], "admin");
    assert!(bundle_download_metadata["sha256"].as_str().is_some());
    assert!(bundle_download_metadata["sizeBytes"].as_i64().is_some());
    assert!(bundle_download_metadata.get("bundle").is_none());
    let audit_events_jsonl = zip_entry_text(&admin_bundle_bytes, "audit-events.jsonl");
    let audit_events = audit_events_jsonl
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event json line"))
        .collect::<Vec<_>>();
    assert_eq!(audit_events.len(), 2);
    assert!(audit_events.iter().any(|event| event["eventType"]
        == "endpoint_evidence_archive.raw_uploaded"
        && event["metadata"]["archiveId"] == archive_id
        && event["metadata"].get("archive").is_none()));
    assert!(audit_events.iter().any(|event| event["eventType"]
        == "endpoint_evidence_archive.raw_download_denied"
        && event["metadata"]["archiveId"] == archive_id
        && event["metadata"]["deniedReason"] == "admin_or_owner_required"
        && event["metadata"].get("archive").is_none()));

    let manifest_json = zip_entry_text(&admin_bundle_bytes, "manifest.json");
    let manifest: Value = serde_json::from_str(&manifest_json).expect("bundle manifest json");
    assert_eq!(manifest["metadata"]["artifactCounts"]["audit_event"], 2);

    let follow_up_bundle_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/cases/{}/evidence/export", fixture.case_id),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "includeRawEnvelopes": true
        })),
    )
    .await;
    assert_eq!(follow_up_bundle_resp.0, StatusCode::OK);
    assert_eq!(follow_up_bundle_resp.1["artifactCounts"]["audit_event"], 8);
    let follow_up_export_id = follow_up_bundle_resp.1["exportId"]
        .as_str()
        .expect("follow-up case bundle export id");
    let follow_up_download_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/evidence-bundles/{follow_up_export_id}/download"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build follow-up bundle download request");
    let follow_up_download_response = harness
        .app
        .clone()
        .oneshot(follow_up_download_request)
        .await
        .expect("follow-up bundle download request");
    assert_eq!(follow_up_download_response.status(), StatusCode::OK);
    let follow_up_bundle_bytes = to_bytes(follow_up_download_response.into_body(), 4 * 1024 * 1024)
        .await
        .expect("read follow-up bundle body");
    let follow_up_audit_events_jsonl =
        zip_entry_text(&follow_up_bundle_bytes, "audit-events.jsonl");
    let follow_up_audit_events = follow_up_audit_events_jsonl
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("follow-up audit event json line"))
        .collect::<Vec<_>>();
    assert_eq!(follow_up_audit_events.len(), 8);
    for expected_type in [
        "endpoint_evidence_archive.raw_uploaded",
        "endpoint_evidence_archive.raw_download_denied",
        "case_evidence_bundle.exported",
        "case_evidence_bundle.metadata_accessed",
        "case_evidence_bundle.export_denied",
        "case_evidence_bundle.metadata_access_denied",
        "case_evidence_bundle.download_denied",
        "case_evidence_bundle.downloaded",
    ] {
        assert!(
            follow_up_audit_events
                .iter()
                .any(|event| event["eventType"] == expected_type),
            "follow-up bundle should contain {expected_type}"
        );
    }
    assert!(follow_up_audit_events.iter().all(|event| event["metadata"]
        .as_object()
        .expect("audit event metadata object")
        .get("bundle")
        .is_none()));

    let export_from = (Utc::now() - chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let export_to = (Utc::now() + chrono::Duration::minutes(10))
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let csv_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/compliance/export?from={export_from}&to={export_to}&format=csv"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build case bundle CSV compliance export request");
    let csv_response = harness
        .app
        .clone()
        .oneshot(csv_request)
        .await
        .expect("case bundle CSV compliance export request");
    let csv_status = csv_response.status();
    let csv_bytes = to_bytes(csv_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read case bundle CSV compliance export body");
    assert_eq!(csv_status, StatusCode::OK);
    let csv_body = String::from_utf8(csv_bytes.to_vec()).expect("case bundle CSV export utf8");
    for expected_type in [
        "case_evidence_bundle.exported",
        "case_evidence_bundle.metadata_accessed",
        "case_evidence_bundle.export_denied",
        "case_evidence_bundle.metadata_access_denied",
        "case_evidence_bundle.download_denied",
        "case_evidence_bundle.downloaded",
    ] {
        assert!(
            csv_body.contains(expected_type),
            "CSV compliance export should contain {expected_type}"
        );
    }
    assert!(csv_body.contains(case_bundle_export_id));
    assert!(!csv_body.contains("\"bundle\""));

    let cef_request = Request::builder()
        .method(Method::GET)
        .uri(format!(
            "/api/v1/compliance/export?from={export_from}&to={export_to}&format=cef"
        ))
        .header("x-api-key", &harness.api_key)
        .body(Body::empty())
        .expect("build case bundle CEF compliance export request");
    let cef_response = harness
        .app
        .clone()
        .oneshot(cef_request)
        .await
        .expect("case bundle CEF compliance export request");
    let cef_status = cef_response.status();
    let cef_bytes = to_bytes(cef_response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read case bundle CEF compliance export body");
    assert_eq!(cef_status, StatusCode::OK);
    let cef_body = String::from_utf8(cef_bytes.to_vec()).expect("case bundle CEF export utf8");
    for expected_type in [
        "case_evidence_bundle.exported",
        "case_evidence_bundle.metadata_accessed",
        "case_evidence_bundle.export_denied",
        "case_evidence_bundle.metadata_access_denied",
        "case_evidence_bundle.download_denied",
        "case_evidence_bundle.downloaded",
    ] {
        assert!(
            cef_body.contains(expected_type),
            "CEF compliance export should contain {expected_type}"
        );
    }
    assert!(cef_body.contains(case_bundle_export_id));
    assert!(!cef_body.contains("\"bundle\""));
}

