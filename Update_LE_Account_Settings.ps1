$global:fqdn = "your_fqdn"
$global:token = 'your_configuration_token' 

$code = @"
public class SSLHandler
{public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });}
}
"@
Add-Type -TypeDefinition $code


function Get-LeAccounts {
    Param (
        [string]$orderBy = "Username",
        [string]$Direction = "Ascending",
        [string]$Count = "50",
        [string]$Include = "none"
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
        orderBy   = $orderBy
        direction = $Direction
        count     = $Count
        include   = $Include 
    } 

    $Parameters = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/Accounts'
        Headers     = $Header
        Method      = 'GET'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

function Set-LeAccount {
    Param (
        [string]$accountId,
        [string]$password,
        [string]$username,
        [string]$domainId
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
        passwordHasChanged   = $true
        password = $password
        username = $username
        domainId = $domainId
    } | ConvertTo-Json

    $Parameters = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/Accounts/' + $accountId
        Headers     = $Header
        Method      = 'PUT'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
    $Response.items 
}

#   Get the account information for the account you want to change
$a = Get-LeAccounts | Where {$_.username -like "abc"}

#   Update the account with the settings you want
Set-LeAccount -accountId $a.id -password "NewPassword123" -username "NewUsername123" -domainId "NewDomain123"
