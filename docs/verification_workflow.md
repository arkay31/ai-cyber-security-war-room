# Human-in-the-Loop User Verification Workflow

## 1. Overview & Operational Problem

In a Security Operations Center (SOC), distinguishing between a legitimate employee performing off-hours administrative tasks and an adversary using compromised credentials is one of the most critical challenges. Immediately isolating an executive's laptop or revoking access for a sysadmin during production maintenance causes severe business disruption. Conversely, assuming an anomalous login is benign leads to catastrophic data breaches.

The **AI Cyber Security War Room** resolves this dilemma through a dedicated **Human-in-the-Loop (HITL) User Verification Engine**.

```
[ Suspicious User Activity Detected ]
                 │
                 ▼
[ SOC Analyst Reviews AI Investigation ]
                 │
                 ▼
[ Analyst Clicks "Verify User" ]
                 │
                 ▼
[ Verification Request Generated ]
(UUID Challenge Token + 15m Expiration)
                 │
                 ▼
[ User Receives Link / Opens Portal ]
        (/verify/[challengeId])
                 │
                 ▼
[ User Authenticates with PIN (e.g., 1234) ]
                 │
        ┌────────┴────────┐
        ▼                 ▼
[ YES, IT WAS ME ]   [ NO, I DID NOT DO THIS ]
        │                 │
        ▼                 ▼
[ USER_CONFIRMED ]   [ USER_DENIED ]
(Remains Open for    (Risk Auto-Escalated to 100.0,
 Analyst Decision)    Immediate Containment Proposed)
```

---

## 2. Verification Request Generation

When an analyst identifies suspicious activity involving a valid user account (e.g., user `jdoe` executing privilege escalation on server `srv-app-prod01` from IP `198.51.100.45`):

1. **Analyst Action**: Clicks **[Verify User]** in the Incident Details panel ([`/incidents/[id]`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/incidents/%5Bid%5D/page.tsx)).
2. **Safe Summary Generation**: The backend automatically synthesizes a safe, non-technical description of the activity suitable for an employee:
   > *"Privilege escalation attempt detected on server srv-app-prod01 (originating IP: 198.51.100.45) on Oct 01, 2026 at 14:15 UTC."*
3. **Database Record**: Created in `verification_requests` with:
   - `challenge_id`: Cryptographic UUID token.
   - `status`: `PENDING`.
   - `expires_at`: 15 minutes from creation.
   - `delivery_method`: `DEMO_PORTAL` (faculty demonstration) or simulated push.
4. **State Machine Transition**: The incident transitions from `INVESTIGATING` to `AWAITING_USER_VERIFICATION`.

---

## 3. The User Verification Portal (`/verify/[challengeId]`)

The portal is implemented in [`src/app/verify/[challengeId]/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/verify/%5BchallengeId%5D/page.tsx). It is optimized for both desktop browsers and mobile devices (via demo QR code or shared link).

### Portal Workflow:
1. **Challenge Lookup**: Loads the challenge record via `GET /api/verification/{challenge_id}`.
2. **Authentication Step**: The user must provide authentication before viewing or responding to the prompt. In demo mode, a default PIN (`1234`) is accepted.
3. **Safe Activity Presentation**:
   - Organization: Corporate Security Operations Center
   - Event Timestamp
   - Affected Host / Service
   - Non-technical question: *"Did you perform this activity?"*
4. **Response Actions**:
   - **`[YES, IT WAS ME]`**: User confirms they initiated the activity.
   - **`[NO, I DID NOT DO THIS]`**: User explicitly denies authorizing the activity.

---

## 4. Verification Outcomes & State Transitions

### Outcome A: User Confirms Activity (`YES_IT_WAS_ME`)
- **Status Update**: Verification record becomes `CONFIRMED`. Incident status transitions to `USER_CONFIRMED`.
- **SOC Impact**:
  - The incident **does NOT automatically close** (preventing an attacker from coercing an employee or hijacking a session to dismiss an alert).
  - The SOC Analyst is presented with two explicit buttons in the Incident UI:
    - **`[MARK AS LEGITIMATE]`**: Analyst validates that the activity was authorized and approved maintenance, resolving the incident.
    - **`[CONTINUE INVESTIGATION]`**: Analyst notes policy violations or proceeds with deeper investigation despite user confirmation.

### Outcome B: User Denies Activity (`NO_I_DID_NOT_DO_THIS`)
- **Status Update**: Verification record becomes `DENIED`. Incident status transitions to `USER_DENIED`.
- **SOC Impact**:
  - **Immediate Escalation**: Incident severity escalates to `CRITICAL` and composite risk score is pinned to `100.0`.
  - **Automated Containment Staging**: The platform stages urgent response actions:
    1. Revoke active user session (`REVOKE_USER_SESSION` for `jdoe`).
    2. Isolate compromised endpoint (`ISOLATE_HOST` for `srv-app-prod01`).
    3. Block adversary IP (`BLOCK_SOURCE_IP` for `198.51.100.45`).
  - Response actions require analyst confirmation before simulated execution.

### Outcome C: Challenge Expiration (`EXPIRED`)
- If 15 minutes elapse without a response, the challenge status moves to `EXPIRED`.
- The incident status transitions to `VERIFICATION_EXPIRED`.
- The platform flags the incident as unverified and alerts the SOC analyst that identity confirmation failed.

---

## 5. Demonstration Mode & Faculty Review

To demonstrate this workflow seamlessly without requiring enterprise SMS or MDM push credentials:
1. When **[Verify User]** is clicked on the incident page, an interactive banner displays:
   - Challenge ID
   - Direct clickable link (`http://localhost:3000/verify/<challengeId>`)
   - An interactive button: **[Open Demo User Portal]**
2. Faculty can open this link in an Incognito window, second tab, or on a mobile device on the same local network.
3. The analyst dashboard dynamically reflects the user's action upon page refresh or subsequent polling.
