package accessops

import rego.v1

default allow := false

policy_version := "accessops-v1"

active if { input.subject.status == "active" }
human if { input.subject.kind == "human" }
has_role(role) if { role in input.subject.roles }
in_project if { input.resource.project in input.subject.project_ids }
in_project if {
    not input.resource.project
    count(input.context.identity_project_ids) > 0
    every project in input.context.identity_project_ids { project in input.subject.project_ids }
}
version_matches if { input.context.policy_version == policy_version }

allow if {
    active
    human
    input.action == "snapshot"
    some role in ["operator", "approver", "auditor", "resource_owner"]
    has_role(role)
}

allow if {
    active
    human
    input.action == "request"
    has_role("resource_owner")
    input.subject.id == input.resource.owner_id
    in_project
    version_matches
}

allow if {
    active
    human
    input.action in ["request", "review"]
    has_role("operator")
    in_project
    version_matches
}

allow if {
    active
    human
    input.action == "approve"
    has_role("approver")
    in_project
    input.subject.id != input.request.requester_id
    version_matches
}

allow if {
    active
    human
    input.action == "approve"
    has_role("resource_owner")
    input.subject.id == input.resource.owner_id
    in_project
    input.subject.id != input.request.requester_id
    version_matches
}

allow if {
    active
    human
    input.action == "execute"
    has_role("operator")
    in_project
    input.request.action in ["grant", "transfer", "department_transfer"]
    input.context.approval_valid == true
    input.request.policy_version == policy_version
    version_matches
}

allow if {
    active
    human
    input.action == "execute"
    has_role("operator")
    in_project
    input.request.action in ["revoke", "offboard"]
    version_matches
}

allow if {
    active
    human
    input.action == "reconcile"
    has_role("operator")
    version_matches
}

allow if {
    active
    human
    input.action == "departure_close"
    has_role("approver")
    in_project
    input.subject.id != input.context.case_owner_id
    version_matches
}

allow if {
    active
    input.subject.kind == "agent"
    input.action == "agent_tool"
    in_project
    input.context.grant_active == true
    input.context.sponsor_active == true
    input.context.within_budget == true
    version_matches
}

# The signed HR feed is a service identity: it may open a departure case and
# contain it, nothing else.
allow if {
    active
    input.subject.kind == "service"
    input.action == "departure_intake"
    has_role("hr_intake")
    in_project
    version_matches
}

allow if {
    active
    input.subject.kind == "service"
    input.action == "execute"
    has_role("hr_intake")
    in_project
    input.request.action == "offboard"
    version_matches
}

reason := "allowed" if { allow } else := "policy_denied"

allow if {
    active
    input.subject.kind in ["human", "agent"]
    input.action == "resource_read"
    in_project
    input.context.grant_active == true
    input.context.sponsor_active == true
    input.context.within_budget == true
    version_matches
}

decision := {"allow": allow, "reason": reason, "policy_version": policy_version}
