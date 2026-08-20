#Requires -Version 5.1
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ServicePrincipalName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$DomainController,

    [ValidateRange(5,60)]
    [int]$EventWaitSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Intentionally hard-coded. Do not parameterize or expand for this validation.
$AllowedAccounts = @('svc_sql_lab')
$TargetAccount = 'svc_sql_lab'

if ($TargetAccount -notin $AllowedAccounts) {
    throw 'Scope guard failed: target account is not allowlisted.'
}
if ($AllowedAccounts.Count -ne 1 -or $AllowedAccounts[0] -cne 'svc_sql_lab') {
    throw 'Scope guard failed: allowlist was modified.'
}

$account = Get-ADUser -Identity $TargetAccount -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes
$registeredSpns = @($account.ServicePrincipalName)
if ($registeredSpns.Count -eq 0) {
    throw "The allowlisted account has no registered SPNs."
}
if ($ServicePrincipalName -cnotin $registeredSpns) {
    throw "Scope guard failed: supplied SPN is not registered to svc_sql_lab."
}

$startUtc = [DateTime]::UtcNow
$client = $env:COMPUTERNAME
$requester = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Requests one service ticket via the Windows Kerberos provider. The object is
# neither serialized nor exported, and no ticket bytes are accessed.
$token = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken($ServicePrincipalName)
try {
    Start-Sleep -Seconds $EventWaitSeconds
}
finally {
    if ($token -is [System.IDisposable]) {
        $token.Dispose()
    }
    Remove-Variable token -ErrorAction SilentlyContinue
}

$endUtc = [DateTime]::UtcNow
$events = Get-WinEvent -ComputerName $DomainController -FilterHashtable @{
    LogName = 'Security'
    Id = 4769
    StartTime = $startUtc.ToLocalTime()
    EndTime = $endUtc.AddSeconds(5).ToLocalTime()
}

$matches = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $fields = @{}
    foreach ($node in $xml.Event.EventData.Data) {
        $fields[[string]$node.Name] = [string]$node.'#text'
    }

    if ($fields.ServiceName -ceq $ServicePrincipalName) {
        [pscustomobject]@{
            ProofCondition       = '4769 exact-SPN match'
            TimeCreatedUtc       = $event.TimeCreated.ToUniversalTime().ToString('o')
            DomainController     = $DomainController
            EventId              = $event.Id
            ServiceName          = $fields.ServiceName
            Requester            = $fields.TargetUserName
            ClientAddress        = $fields.IpAddress
            TicketEncryptionType = $fields.TicketEncryptionType
            Status               = $fields.Status
            TicketOptions        = $fields.TicketOptions
            ValidationHost       = $client
            ValidationIdentity   = $requester
            WindowStartUtc       = $startUtc.ToString('o')
            WindowEndUtc         = $endUtc.ToString('o')
        }
    }
}

if (@($matches).Count -ne 1) {
    throw "Proof condition not met: expected exactly one matching 4769 event, found $(@($matches).Count). Stop and review auditing, cache state, DC selection, and time sync."
}

$matches
