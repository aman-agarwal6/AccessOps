package accessops_test

import rego.v1
import data.accessops

base := {"action": "execute", "subject": {"id": "operator-1", "kind": "human", "status": "active", "roles": ["operator"], "project_ids": ["Atlas"]}, "resource": {"id": "r1", "project": "Atlas", "owner_id": "owner-1"}, "request": {"requester_id": "requester-1", "action": "grant", "policy_version": "accessops-v1"}, "context": {"policy_version": "accessops-v1", "approval_valid": true}}

test_valid_operator if { accessops.allow with input as base }
test_cross_project_denied if { not accessops.allow with input as object.union(base, {"resource": {"project": "Pulse"}}) }
test_expired_approval_denied if { not accessops.allow with input as base with input.context.approval_valid as false }
test_missing_approval_denied if { not accessops.allow with input as base with input.context as {} }
test_stale_policy_denied if { not accessops.allow with input as base with input.request.policy_version as "old" }
test_disabled_identity_denied if { not accessops.allow with input as base with input.subject.status as "offboarded" }
test_agent_cannot_approve if { not accessops.allow with input as base with input.subject.kind as "agent" with input.action as "approve" with input.subject.roles as ["approver"] }
test_self_approval_denied if { not accessops.allow with input as base with input.action as "approve" with input.subject.roles as ["approver"] with input.request.requester_id as "operator-1" }
test_unknown_action_denied if { not accessops.allow with input as base with input.action as "change_policy" }
test_missing_input_denied if { not accessops.allow with input as {} }
test_agent_scoped_tool if { accessops.allow with input as base with input.subject.kind as "agent" with input.action as "agent_tool" with input.context as {"policy_version": "accessops-v1", "grant_active": true, "sponsor_active": true, "within_budget": true} }
test_agent_no_sponsor_denied if { not accessops.allow with input as base with input.subject.kind as "agent" with input.action as "agent_tool" with input.context as {"policy_version": "accessops-v1", "grant_active": true, "sponsor_active": false, "within_budget": true} }
test_containment_no_approval if { accessops.allow with input as base with input.request.action as "revoke" with input.context.approval_valid as false }
test_global_offboard_scope if { accessops.allow with input as base with input.resource as {} with input.request.action as "offboard" with input.context as {"identity_project_ids": ["Atlas"], "policy_version": "accessops-v1"} }
test_global_offboard_cross_project_denied if { not accessops.allow with input as base with input.resource as {} with input.request.action as "offboard" with input.context as {"identity_project_ids": ["Atlas", "Pulse"], "policy_version": "accessops-v1"} }

test_resource_read_entitlement if { accessops.allow with input as base with input.action as "resource_read" with input.context as {"policy_version": "accessops-v1", "grant_active": true, "sponsor_active": true, "within_budget": true} }
test_resource_read_revoked_denied if { not accessops.allow with input as base with input.action as "resource_read" with input.context as {"policy_version": "accessops-v1", "grant_active": false, "sponsor_active": true, "within_budget": true} }
test_resource_read_budget_denied if { not accessops.allow with input as base with input.action as "resource_read" with input.context as {"policy_version": "accessops-v1", "grant_active": true, "sponsor_active": true, "within_budget": false} }
test_resource_read_agent_sponsor_denied if { not accessops.allow with input as base with input.subject.kind as "agent" with input.action as "resource_read" with input.context as {"policy_version": "accessops-v1", "grant_active": true, "sponsor_active": false, "within_budget": true} }
