# Controlled Response Engine & Containment Architecture

## 1. Overview & Operational Philosophy

In a high-stakes enterprise environment, automated response actions—such as severing network connectivity to a production database server or locking an executive's account—can cause catastrophic downtime if triggered incorrectly by false-positive alerts. 

The **AI Cyber Security War Room** implements a **Controlled Response Engine** governed by two foundational principles:
1. **Analyst In The Loop**: AI recommends response actions based on MITRE playbooks and risk severity, but **never** unilaterally executes containment without human approval.
2. **Deterministic Safety Policy (Simulation Mode)**: For academic and demonstration safety, all response actions in this project are strictly simulated. The system logs realistic execution output without modifying real host firewalls, altering local macOS routing tables, or disabling active operating system accounts.

```
[ AI Analyst Investigation / User Denial ]
                     │
                     ▼
        [ Recommended Response Actions ]
        - BLOCK_SOURCE_IP
        - ISOLATE_HOST
        - REVOKE_USER_SESSION
        - FORENSIC_SNAPSHOT
        - DISABLE_ACCOUNT
                     │
                     ▼
          [ Analyst Reviews Action ]
                     │
          [ Two-Step Confirmation Modal ]
          [ CANCEL ]        [ CONFIRM ACTION ]
                                    │
                                    ▼
                     [ ResponseEngine Executes ]
                     (Simulated Subsystem Driver)
                                    │
                     [ Response Record Updated ]
                      (status = 'EXECUTED')
                                    │
                     [ Immutable Audit Entry ]
                       (audit_logs table)
                                    │
                     [ Incident State Updated ]
                     (status = 'CONTAINED')
```

---

## 2. Supported Response Actions

Implemented in [`backend/app/services/response_engine.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/services/response_engine.py):

| Action Type | Target | Simulated Subsystem Driver | Execution Log Output |
|---|---|---|---|
| `BLOCK_SOURCE_IP` | IPv4 / IPv6 Address | Edge Firewall / Perimeter ACL | `[SIMULATED] Firewall rule deployed: DROP traffic from 198.51.100.45. Edge ACL updated.` |
| `ISOLATE_HOST` | Hostname / IP | Endpoint Detection & Response (EDR) | `[SIMULATED] Host srv-app-prod01 isolated via EDR agent. All non-management traffic dropped.` |
| `REVOKE_USER_SESSION` | Username | Identity Provider (IdP / Okta / Azure AD) | `[SIMULATED] Identity Provider: Revoked all active sessions and refresh tokens for user jdoe.` |
| `FORENSIC_SNAPSHOT` | Hostname | Hypervisor / Endpoint Agent | `[SIMULATED] Memory dump and volatile forensic artifacts captured for srv-app-prod01.` |
| `DISABLE_ACCOUNT` | Username | Active Directory / LDAP | `[SIMULATED] Account jdoe disabled in Active Directory. Password reset flag forced.` |

---

## 3. Two-Step Analyst Authorization Flow

The frontend response interface in [`src/app/incidents/[id]/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/incidents/%5Bid%5D/page.tsx) enforces a strict confirmation flow:

1. **Action Proposal**:
   - The UI lists all pending response actions recommended by the AI investigation or triggered by a user denial.
   - The analyst can also create a custom response action using the **[Staged Actions]** panel.
2. **Review Dialog**:
   - Clicking **[Execute]** triggers a high-visibility confirmation modal.
   - The modal details:
     - Action Type (e.g., `ISOLATE_HOST`)
     - Target (e.g., `srv-app-prod01`)
     - Analyst Rationale requirement
     - Explicit Warning: *"Simulation Mode Active. No actual host isolation will take place on your local machine."*
3. **Execution or Rejection**:
   - **`[CANCEL]`**: Dismisses the modal with no changes made.
   - **`[CONFIRM ACTION]`**: Dispatches `POST /api/responses/actions/{id}/execute`.
   - The backend sets `status = EXECUTED`, logs the simulation timestamp, and appends an entry to the `audit_logs` table.

---

## 4. State Machine Transition & Audit Verification

When containment actions are executed:
1. **Incident Status Transition**:
   - If containment actions are staged, incident status transitions to `CONTAINMENT_PENDING`.
   - Once the analyst executes the containment actions, the incident status transitions to `CONTAINED`.
2. **Forensic Audit Entry**:
   - An immutable record is created in `audit_logs`:
     ```json
     {
       "action": "RESPONSE_EXECUTED",
       "user_id": "soc_analyst",
       "incident_id": "INC-20261001-DEMO",
       "details": {
         "action_id": "c1f7b8...",
         "action_type": "ISOLATE_HOST",
         "target": "srv-app-prod01",
         "is_simulated": true,
         "execution_log": "[SIMULATED] Host srv-app-prod01 isolated via EDR agent."
       }
     }
     ```
3. **UI Feedback**:
   - The Incident Details page renders the response badge as `EXECUTED` with a timestamp and audit trail linkage.
