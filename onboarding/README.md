# Onboarding: access laydown

<p align="center"><sub>Living document · review when a group, system or approval step changes</sub></p>

> [!IMPORTANT]
> **Two accounts, two jobs.**
> 1. **Standard account** for daily work: basic AD group, plus L03 regular (Nutanix dev admin).
> 2. **a-account** for production admin work: L03-admin, L02-admin and the Nutanix admin groups, used only through CyberArk PAM.

## 1. Purpose and scope

Every new team member gets one standard account in the basic AD group on day one. Anyone who needs admin rights also gets a separate a-account, held in CyberArk PAM. This guide lists what each account grants and the steps to set them up.

It is for the manager who requests access, Cyber Security who approves it, the Infra team who grants it, and the new hire who checks it works.

## 2. Account model

Daily work and production admin work use two separate accounts. The one exception is Nutanix dev admin, which the standard account gets through the L03 regular group.

| Account | Used for | Groups | How it is used |
|---|---|---|---|
| Standard account | Email, Teams, daily tools, read-only views | Basic AD group, L03 regular | Normal sign-in |
| a-account (admin) | Changes to servers, AD, Nutanix, SCCM | L03-admin, L02-admin, Nutanix admin groups | Checked out through CyberArk PAM only |

Creating the a-account also creates a CyberArk account tied to the regular account. The user signs in to CyberArk with the regular account; the a-account password and PAM sessions are there.

## 3. Basic AD group (every new hire)

Adding the standard account to the basic AD group grants all of the access below in one step.

| System | Access level |
|---|---|
| Azure DevOps | Access |
| SharePoint | Access |
| ServiceNow | ITIL role |
| Microsoft Defender | Read only |
| Entra ID | Read only |
| Azure | Read only |
| Loop | Access, mostly collaboration workspaces |
| DNS server | Read only |

Nothing in this group can change production systems. Production changes need the a-account.

## 4. Admin access

Each level (L01 to L03) has a regular group for the standard account and an admin group for the a-account. Nutanix user admin uses its own groups. L02 regular, L01 regular and L01-admin exist but grant nothing yet.

| Group | Put on | Grants |
|---|---|---|
| L03 regular | Standard account | Nutanix dev admin |
| L03-admin | a-account | Domain admin, SCCM admin |
| L02 regular | Standard account | Nothing assigned yet |
| L02-admin | a-account | Local admin on all servers (GPO), SCCM read only, Nutanix VM ops, Nutanix backup admin |
| L01 regular | Standard account | Nothing assigned yet |
| L01-admin | a-account | Nothing assigned yet |
| Nutanix admin groups | a-account | Nutanix user admin |

> [!NOTE]
> Nutanix does not support nested groups, so roles are mapped to groups directly on Nutanix. The VM ops and backup admin roles are assigned to L02-admin on Nutanix itself, and the Nutanix admin groups were created for user admin. The a-account must be a **direct member** of each group. Adding it to L03-admin does not give Nutanix access.

L02-admin's local admin on servers comes from a GPO that adds an AD group to each server's local Administrators group.

All admin sessions start from CyberArk, signed in with the regular account.

## 5. Onboarding checklist

The a-account comes first. No access is granted until Cyber Security approves the RITM.

| # | Step | Owner |
|---|---|---|
| 1 | Create the a-account (this also creates the CyberArk account on the regular account) | Manager or Cyber |
| 2 | Open a General Question RITM in ServiceNow, assigned to the Infra team, listing the groups needed | Manager |
| 3 | Ask Cyber Security for approval on the RITM | Infra team |
| 4 | After approval: add the regular account to the basic AD group, and L03 regular if Nutanix dev admin is needed | Infra team |
| 5 | After approval: add the a-account to the approved admin groups (L03-admin, L02-admin, each Nutanix admin group directly) | Infra team |
| 6 | Run the day-one checks (section 6) and report results on the RITM | New hire |

## 6. Day-one checks

The new hire confirms each line and reports any failure on the RITM.

- [ ] Standard account: sign in to Azure DevOps, SharePoint and Loop
- [ ] Standard account: ServiceNow opens with the ITIL role
- [ ] Standard account: Defender, Entra ID, Azure and DNS open read only (no edit options)
- [ ] Standard account: Nutanix dev opens with admin rights (if L03 regular)
- [ ] a-account: sign in to CyberArk with the regular account and start an a-account session
- [ ] a-account: AD and SCCM consoles open with admin rights, and local admin works on a server
- [ ] a-account: Nutanix opens with user admin, VM ops and backup admin rights

## 7. Changes, offboarding and open items

On a role change or exit, remove the a-account from every group in section 4, including each Nutanix admin group by hand (no nesting means none is removed by another). Then disable the a-account in CyberArk and AD, and remove the standard account from the basic AD group and L03 regular.

Open items to fill in:

- [ ] Exact name of the basic AD group
- [ ] Names of the Nutanix admin groups
- [ ] Names of the GPO and the AD group that give L02-admin server local admin
