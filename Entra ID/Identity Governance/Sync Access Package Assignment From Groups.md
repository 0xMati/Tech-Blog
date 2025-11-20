# Sync Azure AD Groups to Access Packages Assignment using Microsoft Graph PowerShell
🗓️ Published: 2024-11-19

This script automates the assignment of users to **Entra ID / Azure AD Access Packages** based on **group membership**.  
It is designed for Identity Governance environments where Access Packages must stay aligned with security groups or business role groups.

## Goal

Keep Access Package assignments synchronized with the membership of Azure AD groups:

- Each line in `GroupsToAccessPackage.txt` (starting from line 2) contains the name of a group.
- For each group, the script:
  - Finds the Azure AD group with this **exact displayName**
  - Finds an Access Package with the **same displayName**
  - Retrieves the **first assignment policy** of that Access Package
  - Retrieves all **user members** of the group
  - Creates an **adminAdd** assignment request for each user

This ensures that Access Package assignments match group membership automatically.

## Input File Format

`GroupsToAccessPackage.txt` (line 1 is ignored):

```
## Group list to Sync with Access Package
MyGroup1
Group2
CustomGroup3
```

Each group listed must also have an Access Package with the **same name**.

## What the Script Does

### ✔ Reads the list of group names from a text file  
### ✔ Connects to Microsoft Graph with the required scopes  
### ✔ For each group:
- Resolves the group object in Azure AD  
- Resolves the Access Package with the same name  
- Retrieves its assignment policies  
- Detects valid user members (robust resolution using Get-MgUser)  
- Creates `adminAdd` assignment requests for each user  

### ✔ Includes:
- Color-coded logs (INFO / OK / WARN / FAIL)  
- Variable cleanup at each loop to avoid cross-contamination  
- Defensive code to handle missing groups, APs, or policies  
- Graceful skipping in case of errors  

## Required Graph Permissions

The script uses:

- `EntitlementManagement.ReadWrite.All`  
- `Group.Read.All`
- `GroupMember.Read.All`
- `User.Read.All`

Example:

```powershell
Connect-MgGraph -Scopes "EntitlementManagement.ReadWrite.All","Group.Read.All","GroupMember.Read.All","User.Read.All"
```

## How to Run

Place the script in:

```
C:\Temp\ManageAccessPackagewithGraph\AssignGroupMembersToAccessPackage.ps1
```

And the group list in:

```
C:\Temp\ManageAccessPackagewithGraph\GroupsToAccessPackage.txt
```

Then run:

```powershell
.\AssignGroupMembersToAccessPackage.ps1
```

## 📦 Use Cases

- Align Access Packages with security groups  
- Automate onboarding/offboarding scenarios  
- Maintain compliance baselines  
- Support role-based assignment flows  

## Full Script below

```powershell
#################################################################################
# Manage Access Package assignments from group membership
# For each group name listed in GroupsToAccessPackage.txt (from line 2),
# this script:
#   - Finds the Entra ID group with the same displayName
#   - Finds the Access Package with the same displayName
#   - Uses the first assignment policy of the Access Package
#   - Assigns all user members of the group to the Access Package via adminAdd
#################################################################################

cls
$ErrorActionPreference = 'Stop'

#################################################################################
# Fancy logging helpers
#################################################################################

function T {
    # Returns a simple timestamp
    (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
}

function INFO($message) {
    Write-Host ("[{0}] [INFO ] {1}" -f (T), $message) -ForegroundColor Cyan
}

function OK($message) {
    Write-Host ("[{0}] [ OK  ] {1}" -f (T), $message) -ForegroundColor Green
}

function WARN($message) {
    Write-Host ("[{0}] [WARN ] {1}" -f (T), $message) -ForegroundColor Yellow
}

function ERR($message) {
    Write-Host ("[{0}] [FAIL ] {1}" -f (T), $message) -ForegroundColor Red
}

#################################################################################
# Check required modules presence
#################################################################################

# Modules required for the script to run properly
$requiredModules = @(
    'Microsoft.Graph',                    # meta-module (optional but recommended)
    'Microsoft.Graph.Authentication',     # for Connect-MgGraph / Get-MgContext
    'Microsoft.Graph.Users',              # Get-MgUser
    'Microsoft.Graph.Groups',             # Get-MgGroup, Get-MgGroupMember
    'Microsoft.Graph.Identity.Governance' # Access Packages / Entitlement Management
)

INFO "Checking required Microsoft Graph modules..."

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        WARN ("Required module '{0}' is not available. Install it with: Install-Module {0} -Scope AllUsers" -f $mod)
    }
    else {
        OK ("Module '{0}' detected on this system." -f $mod)
    }
}

#################################################################################
# Required modules (install once if needed)
#################################################################################
<# 
Install-Module Microsoft.Graph -Scope AllUsers -Force
Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force
Install-Module Microsoft.Graph.Users -Scope AllUsers -Force
Install-Module Microsoft.Graph.Groups -Scope AllUsers -Force
Install-Module Microsoft.Graph.Identity.Governance -Scope AllUsers -Force
#>

# Import the main modules (commented auto-loading should works fine)
<# 
Import-Module Microsoft.Graph
Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Groups
Import-Module Microsoft.Graph.Identity.Governance
#>

#################################################################################
# Connect to Microsoft Graph
#################################################################################

INFO "Connecting to Microsoft Graph..."
# Scopes:
# - EntitlementManagement.ReadWrite.All : manage access package assignments
# - Group.Read.All / GroupMember.Read.All : read groups and their members
# - User.Read.All : read user details
Connect-MgGraph -Scopes "EntitlementManagement.ReadWrite.All","Group.Read.All","GroupMember.Read.All","User.Read.All"

try {
    $ctx = Get-MgContext
    OK ("Connected as: {0}" -f $ctx.Account)
}
catch {
    WARN "Connected to Graph, but unable to read context details."
}

#################################################################################
# Input file configuration
#################################################################################

$groupsFile = "C:\Temp\ManageAccessPackagewithGraph\GroupsToAccessPackage.txt"

INFO ("Using groups list file: {0}" -f $groupsFile)

if (-not (Test-Path $groupsFile)) {
    ERR ("Input file not found: {0}" -f $groupsFile)
    return
}

# Read all lines from file
$lines = Get-Content $groupsFile
if (-not $lines -or $lines.Count -lt 2) {
    WARN "File exists but contains no group names (need at least 2 lines: header + one group)."
    return
}

# Skip the first line (header), take group names starting from line 2
$groupNames = $lines | Select-Object -Skip 1

INFO ("Found {0} group name(s) in the file." -f $groupNames.Count)

#################################################################################
# Main loop: for each group name, sync group members to the matching Access Package
#################################################################################

foreach ($rawGroupName in $groupNames) {

    # Trim and validate group name
    $groupName = $rawGroupName.Trim()
    if ([string]::IsNullOrWhiteSpace($groupName)) {
        WARN "Encountered an empty line in the group list, skipping."
        continue
    }

    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkGray
    INFO ("Processing group name: '{0}'" -f $groupName)

    # Reset variables for this iteration to avoid re-using previous values
    $group        = $null
    $ap           = $null
    $policy       = $null
    $members      = $null
    $userMembers  = @()
    $params       = $null

    #############################################################################
    # 1) Find Entra ID group with this displayName
    #############################################################################

    try {
        INFO ("Looking for Entra ID group with displayName = '{0}'..." -f $groupName)
        $group = Get-MgGroup -Filter "displayName eq '$groupName'"
    }
    catch {
        ERR ("Error while querying group '{0}': {1}" -f $groupName, $_.Exception.Message)
        continue
    }

    $groupCount = @($group).Count

    if ($groupCount -eq 0) {
        WARN ("No group found with displayName = '{0}'. Skipping this entry." -f $groupName)
        continue
    }

    if ($groupCount -gt 1) {
        WARN ("Multiple groups found with this name. Using the first one.")
    }

    $group = @($group)[0]

    if (-not $group.Id) {
        ERR ("Group object has no Id after selection. Something is wrong, skipping this group.")
        continue
    }

    OK ("Group found: {0} (Id: {1})" -f $group.DisplayName, $group.Id)

    #############################################################################
    # 2) Find Access Package with the same displayName
    #############################################################################

    try {
        INFO ("Looking for Access Package with displayName = '{0}'..." -f $groupName)
        $ap = Get-MgEntitlementManagementAccessPackage `
            -Filter "displayName eq '$groupName'" `
            -ExpandProperty "assignmentPolicies"
    }
    catch {
        ERR ("Error while querying Access Package '{0}': {1}" -f $groupName, $_.Exception.Message)
        continue
    }

    $apCount = @($ap).Count

    if ($apCount -eq 0) {
        WARN ("No Access Package found with displayName = '{0}'. Skipping this group." -f $groupName)
        continue
    }

    if ($apCount -gt 1) {
        WARN ("Multiple Access Packages found with this name. Using the first one.")
    }

    $ap = @($ap)[0]

    if (-not $ap.Id) {
        ERR ("Access Package object has no Id after selection. Something is wrong, skipping this group.")
        continue
    }

    OK ("Access Package found: {0} (Id: {1})" -f $ap.DisplayName, $ap.Id)

    if (-not $ap.AssignmentPolicies -or @($ap.AssignmentPolicies).Count -eq 0) {
        ERR ("No assignment policies found on Access Package '{0}'. Cannot proceed." -f $ap.DisplayName)
        continue
    }

    # For now, use the first assignment policy for this AP
    $policy = @($ap.AssignmentPolicies)[0]

    if (-not $policy.Id) {
        ERR ("Selected assignment policy has no Id. Cannot proceed for this group.")
        continue
    }

    OK ("Using assignment policy: {0} (Id: {1})" -f $policy.DisplayName, $policy.Id)

    #############################################################################
    # 3) Get group members and resolve real user objects
    #############################################################################

    try {
        INFO ("Retrieving members for group '{0}'..." -f $group.DisplayName)
        $members = Get-MgGroupMember -GroupId $group.Id -All
    }
    catch {
        ERR ("Error while retrieving members for group '{0}': {1}" -f $group.DisplayName, $_.Exception.Message)
        continue
    }

    if (-not $members) {
        WARN ("Group '{0}' has no members. Nothing to assign." -f $group.DisplayName)
        continue
    }

    # Resolve each member Id as a user (if possible)
    foreach ($m in $members) {
        if (-not $m.Id) {
            WARN "Encountered a member without Id. Skipping this entry."
            continue
        }

        try {
            # If this succeeds, the directory object is a user
            $u = Get-MgUser -UserId $m.Id -ErrorAction Stop
            $userMembers += $u
        }
        catch {
            # Not a user (could be group, service principal, etc.)
            WARN ("Member {0} is not a user (or cannot be resolved as user). Skipping." -f $m.Id)
        }
    }

    if (-not $userMembers -or $userMembers.Count -eq 0) {
        WARN ("Group '{0}' has no resolvable user members. Nothing to assign." -f $group.DisplayName)
        continue
    }

    INFO ("Resolved {0} user member(s) in group '{1}' to assign to Access Package '{2}'." -f $userMembers.Count, $group.DisplayName, $ap.DisplayName)

    #############################################################################
    # 4) For each user member, create an adminAdd assignment request
    #############################################################################

    foreach ($user in $userMembers) {

        # Defensive: ensure we have a valid Id
        if (-not $user.Id) {
            WARN "Encountered a user object without Id. Skipping this entry."
            continue
        }

        $targetId = $user.Id
        $upn      = $user.UserPrincipalName

        if ($upn) {
            INFO ("Creating adminAdd assignment request for user {0} ({1})..." -f $upn, $targetId)
        }
        else {
            INFO ("Creating adminAdd assignment request for user Id {0}..." -f $targetId)
        }

        # Reset params per user to avoid re-use issues
        $params = @{
            requestType = "adminAdd"
            assignment  = @{
                targetId           = $targetId
                assignmentPolicyId = $policy.Id
                accessPackageId    = $ap.Id
            }
        }

        try {
            $request = New-MgEntitlementManagementAssignmentRequest -BodyParameter $params
            OK ("Request created. Id: {0} | State: {1} | Status: {2}" -f $request.Id, $request.State, $request.Status)
        }
        catch {
            ERR ("Error while creating assignment request for user {0}: {1}" -f $targetId, $_.Exception.Message)
        }
    }

    OK ("Finished processing group '{0}'." -f $group.DisplayName)
}

Write-Host ""
OK "Script completed. All groups from the file have been processed."


```