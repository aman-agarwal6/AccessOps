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

departure := {"action": "departure_close", "resource": {}, "subject": {"id": "reviewer", "kind": "human", "status": "active", "roles": ["approver"], "project_ids": ["Atlas"]}, "context": {"policy_version": "accessops-v1", "identity_project_ids": ["Atlas"], "case_owner_id": "owner"}}
test_independent_departure_reviewer if { accessops.allow with input as departure }
test_departure_owner_cannot_close if { not accessops.allow with input as departure with input.context.case_owner_id as "reviewer" }
test_departure_cross_scope_denied if { not accessops.allow with input as departure with input.context.identity_project_ids as ["Pulse"] }
test_departure_stale_policy_denied if { not accessops.allow with input as departure with input.context.policy_version as "old" }

intake := {"action": "departure_intake", "resource": null, "subject": {"id": "hr-feed", "kind": "service", "status": "active", "roles": ["hr_intake"], "project_ids": ["Atlas", "Pulse"]}, "request": null, "context": {"policy_version": "accessops-v1", "identity_project_ids": ["Atlas"]}}
intake_offboard := object.union(intake, {"action": "execute", "request": {"requester_id": "hr-feed", "action": "offboard", "policy_version": "accessops-v1"}})
test_hr_feed_opens_departure if { accessops.allow with input as intake }
test_hr_feed_contains_departure if { accessops.allow with input as intake_offboard }
test_hr_feed_cannot_grant if { not accessops.allow with input as intake_offboard with input.request.action as "grant" with input.context.approval_valid as true }
test_hr_feed_cannot_revoke_or_transfer if { not accessops.allow with input as intake_offboard with input.request.action as "revoke"; not accessops.allow with input as intake_offboard with input.request.action as "transfer" }
test_hr_feed_cannot_close_approve_request_or_read if { every action in ["departure_close", "approve", "request", "snapshot", "reconcile", "resource_read"] { not accessops.allow with input as intake with input.action as action with input.context.grant_active as true with input.context.sponsor_active as true with input.context.within_budget as true } }
test_hr_feed_outside_project_denied if { not accessops.allow with input as intake with input.context.identity_project_ids as ["Atlas", "Ledger"] }
test_inactive_hr_feed_denied if { not accessops.allow with input as intake with input.subject.status as "suspended" }
test_operator_cannot_use_intake if { not accessops.allow with input as intake with input.subject.kind as "human" with input.subject.roles as ["operator"] }
test_service_without_intake_role_denied if { not accessops.allow with input as intake_offboard with input.subject.roles as ["operator"] }
