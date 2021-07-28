$global:fqdn = "your_fqdn"
$global:token = 'your_configuration_token' 

###################################################################################################################################

$code = @"
public class SSLHandler
{public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });}
}
"@
Add-Type -TypeDefinition $code

function Get-LeAccounts {
    Param (
        [string]$orderBy   = "Username",
        [string]$Direction = "Ascending",
        [string]$Count     = "5000",
        [string]$Include   = "none"
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $Body = @{
        orderBy     = $orderBy
        direction   = $Direction
        count       = $Count
        include     = $Include 
    } 

    $Parameters     = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/Accounts'
        Headers     = $Header
        Method      = 'GET'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
$Response.items 
}

function Set-LeAccountStatus {
    Param (
        [string]$id,
        [switch]$disable
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLHandler]::GetSSLHandler()

    if($disable.IsPresent){
        $status = $false
    }else{
        $status = $true
    }

    $Header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $Body = $status | ConvertTo-Json

    $Parameters     = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/Accounts/' + $id + '/enabled'
        Headers     = $Header
        Method      = 'PUT'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
$Response.items 
}


Foreach ($user in (Get-LeAccounts | Where {$_.enabled -eq $false})){
    Set-LeAccountStatus -id $user.id
}

