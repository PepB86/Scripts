$password = Read-Host -AsSecureString "Enter password"

$global:nrOfUsers = "262" 
$global:fqdn = "your_fqdn"
$global:token = 'your_configuration_token' 
$global:naming = "TestUser"
$global:domainID = "lgnv"
$global:UPN = "@your.domain"
$global:adPath = "OU=TestUsers,DC=your,DC=domain"
 
function New-LeUser {
    Param (
        [string]$username,
        [string]$domainID,
        [string]$password
    )
 
    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
 
    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true; }
    
    $user = @{
        username = $username
        domainID = $domainID
        password = $password
    } | ConvertTo-Json
 
    $header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }
 
    $params = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/accounts'
        Headers     = $header
        Method      = 'POST'
        Body        = $user
        ContentType = 'application/json'
    }
 
    $Response = Invoke-RestMethod @params
    $Response.id
}
 
function Get-Usernames {
    Param (
        [Parameter(Mandatory = $true)]
        [int]$Start,
        [Parameter(Mandatory = $true)]
        [int]$End
    )
  
    $Start..$End | % {
        $Number = ($Start++).ToString('00')
        $Name = $global:naming + $Number
        [array]$Counts += $Name }
    Return $Counts
}
 
foreach ($User in (Get-Usernames 1 $global:nrOfUsers)) {

    $UPN = $User + $global:UPN 
    New-ADUser -Name "$User" -SamAccountName "$User" -UserPrincipalName "$UPN" -Path $global:adPath -ScriptPath "LoginPI.Logon.exe https://$global:fqdn" -AccountPassword $password -Enabled $true
    New-LeUser -username $User -domainID $global:domainID -password ($Password | ConvertFrom-SecureString )
 
} 

