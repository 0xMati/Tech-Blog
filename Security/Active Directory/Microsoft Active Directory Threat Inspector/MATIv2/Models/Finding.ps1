# Models\Finding.ps1
# MATIv2 - Microsoft Active Directory Threat Inspector v2
# Standard finding model used across all rules and reporters.

class MATIFinding {
    [string]$Id            # Rule ID, e.g. MATI-CONFIG-001
    [string]$Category      # Category derived from rule folder, e.g. Config, Kerberos
    [string]$Severity      # Critical | High | Medium | Low | Informational
    [string]$Title         # Short human-readable title
    [string]$Description   # Detailed explanation of the finding
    [string]$Remediation   # Recommended remediation steps
    [string]$ObjectDN      # Distinguished Name of the affected AD object
    [string]$Domain        # DNS domain name (e.g. corp.contoso.com)
    [string]$RuleFile      # Source rule file name (auto-populated by engine)
    [hashtable]$Details    # Structured key-value details (flexible)
    [int]$Weight           # Scoring weight (auto-populated from rule or severity default)
    [datetime]$Timestamp   # When the finding was generated

    MATIFinding() {
        $this.Timestamp = [datetime]::UtcNow
        $this.Details   = @{}
    }
}

function New-MATIFinding {
    <#
    .SYNOPSIS
        Creates a new MATIFinding object with the given parameters.
    .DESCRIPTION
        Factory function to create findings from rules. Rules call this function
        from their Condition scriptblock to report detected issues.
    #>
    [CmdletBinding()]
    [OutputType([MATIFinding])]
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Critical','High','Medium','Low','Informational')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Description = '',
        [string]$Remediation = '',
        [string]$ObjectDN    = '',
        [string]$Domain      = '',
        [string]$RuleFile    = '',
        [hashtable]$Details  = @{},
        [int]$Weight         = -1
    )

    $finding            = [MATIFinding]::new()
    $finding.Id         = $Id
    $finding.Category   = $Category
    $finding.Severity   = $Severity
    $finding.Title      = $Title
    $finding.Description = $Description
    $finding.Remediation = $Remediation
    $finding.ObjectDN   = $ObjectDN
    $finding.Domain     = $Domain
    $finding.RuleFile   = $RuleFile
    $finding.Details    = $Details

    # If no explicit weight, derive from severity
    if ($Weight -ge 0) {
        $finding.Weight = $Weight
    } else {
        $finding.Weight = switch ($Severity) {
            'Critical'      { 15 }
            'High'          { 7  }
            'Medium'        { 3  }
            'Low'           { 1  }
            'Informational' { 0  }
        }
    }

    return $finding
}
