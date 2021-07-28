$global:fqdn = "your_fqdn"
$global:token = 'your_configuration_token' 

####################################################################################################################

$code = @"
public class SSLHandler
{public static System.Net.Security.RemoteCertificateValidationCallback GetSSLHandler()
    {return new System.Net.Security.RemoteCertificateValidationCallback((sender, certificate, chain, policyErrors) => { return true; });}
}
"@
Add-Type -TypeDefinition $code

function Get-Tests {
    Param (
        [string]$orderBy   = "Name",
        [string]$Direction = "Ascending",
        [string]$Count     = "50",
        [string]$Include   = "all"
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
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/Tests'
        Headers     = $Header
        Method      = 'GET'
        body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @Parameters
$Response.items 
}

function Copy-Test {
    Param (
         $Test    
    )
 
    $Type=$test.'$type'
    $Name=(New-Guid).Guid
    $Description="Copy of " + $test.description
    $ConnectorID=$test.environment.connectorConfiguration.connector.id
    $connectorParameterValues = $test.environment.connectorConfiguration.connectorParameterValues
    [array]$AccountGroups=$test.environment.accountGroups.groupId
    [array]$LauncherGroups=$test.environment.launcherGroups.id

    $connectorParameters = $null
    foreach ($value in $connectorParameterValues) {
            $connectorParameters += [pscustomobject]@{Key=$value.value;Value=$value.key;}
            $connectorParameters=@($connectorParameters)
        }
    $connectorParameterValues = $connectorParameters

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
 
    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true; }
    
    $Body = [ordered]@{
        '$type'                     = "$Type"
        Name                        = $Name
        Description                 = $Description
        ConnectorID                 = $ConnectorID
        ConnectorParameterValues    = $connectorParameterValues
        AccountGroups               = $AccountGroups
        LauncherGroups              = $LauncherGroups
    } | ConvertTo-Json
 
    $header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $params = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/tests'
        Headers     = $header
        Method      = 'POST'
        Body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @params
$Response.id
}

function Update-Test {
    Param (
         $Oldtest,
         $Newtest    
    )
 
    $Type=$Oldtest.'$type'
    $Name=$Newtest.name
    $Description=$Newtest.description
    $ConnectorID=$Oldtest.environment.connectorConfiguration.connector.id
    $connectorParameterValues = $Oldtest.environment.connectorConfiguration.connectorParameterValues
    
    [array]$AccountGroups=$Oldtest.environment.accountGroups.groupId
    [array]$LauncherGroups=$Oldtest.environment.launcherGroups.id

    $connectorParameters = $null
    foreach ($value in $connectorParameterValues) {
            $connectorParameters += [pscustomobject]@{Key=$value.value;Value=$value.key;}
            $connectorParameters=@($connectorParameters)
        }
    $connectorParameterValues = $connectorParameters

    $steps=$null 
    Foreach($item in $Oldtest.workload.steps){
        if($item.'$type' -eq "AppInvocation"){ 
            $steps += [pscustomobject]@{'$type'=$item.'$type';ApplicationId=$item.Application.id;IsEnabled=$item.isEnabled;}
        }
        if($item.'$type' -eq "Delay"){
            $steps += [pscustomobject]@{'$type'=$item.'$type';delayInSeconds=$item.delayInSeconds;IsEnabled=$item.isEnabled;}
        }
        $steps=@($steps)
    }

    
    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
 
    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true; }
    

    if($Type -eq "ApplicationTest"){

        if(($Oldtest.Thresholds) -ne $null){        
            Foreach ($Threshold in $Oldtest.Thresholds){
                Update-Threshold -TestId $Newtest.id -Threshold $Threshold
            }
        }

        if(($Oldtest.alertConfigurations.threshold) -ne $null){        
            Foreach ($Threshold in $Oldtest.alertConfigurations.threshold){
                Update-Threshold -TestId $Newtest.id -Threshold $Threshold
            }
        }

        if($Oldtest.emailRecipient -eq $null){$Oldtest.emailRecipient = "noreply@test.com"}
        $Body = [ordered]@{
            '$type' = "$Type"
            isEmailEnabled = $Oldtest.isEmailEnabled
            emailRecipient = $Oldtest.emailRecipient
            includeSuccessfulApplications = $Oldtest.includeSuccessfulApplications
            state = $Oldtest.state
            name = $Name
            description = $Oldtest.description
            ConnectorID = $ConnectorID
            ConnectorParameterValues = $connectorParameterValues
            AccountGroups = $AccountGroups
            LauncherGroups = $LauncherGroups
            steps = $steps
        } | ConvertTo-Json
    }

    if($Type -eq "LoadTest"){
        $Body = [ordered]@{
            '$type' = "$Type"
            numberOfSessions = $Oldtest.numberOfSessions
            rampUpDurationInMinutes = $Oldtest.rampUpDurationInMinutes
            testDurationInMinutes = $Oldtest.testDurationInMinutes
            name = $Name
            description = $Oldtest.description
            ConnectorID = $ConnectorID
            ConnectorParameterValues = $connectorParameterValues
            AccountGroups = $AccountGroups
            LauncherGroups = $LauncherGroups
            steps = $steps
        } | ConvertTo-Json
    }

    if($Type -eq "ContinuousTest"){
        $Body = [ordered]@{
            '$type' = "$Type"
            scheduleType = $Oldtest.scheduleType
            intervalInMinutes = $Oldtest.scheduleIntervalInMinutes
            numberOfSessions = $Oldtest.numberOfSessions
            takeScriptScreenshots = $Oldtest.takeScriptScreenshots
            repeatCount = $Oldtest.repeatCount
            isRepeatEnabled = $Oldtest.isRepeatEnabled
            isEnabled = $Oldtest.isEnabled
            restartOnComplete = $Oldtest.restartOnComplete
            name = $Name
            description = "description"
            connectorID = $ConnectorID
            connectorParameterValues = $connectorParameterValues
            accountGroups = $AccountGroups
            launcherGroups = $LauncherGroups
            steps = $steps
        } | ConvertTo-Json
    }

    $header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $params = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/tests/' + $Newtest.id
        Headers     = $header
        Method      = 'PUT'
        Body        = $Body
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @params
$Response.id
}

function Update-Threshold{
    Param (
         $TestId,
         $Threshold,
         $NewThreshold          
    )
 
    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
 
    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true; }
 
 
     $header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }   
    
    if($Threshold.'$type' -eq "AppThreshold"){
        $Body = [ordered]@{
            applicationId = $Threshold.applicationId
            timer = $Threshold.timer
            isEnabled = $Threshold.isEnabled
            value = $Threshold.value
        } | ConvertTo-Json

        $params = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/tests/' + $TestId + '/thresholds'
        Headers     = $header
        Method      = 'POST'
        Body        = $Body
        ContentType = 'application/json'
        }

    }

    if($Threshold.'$type' -eq "SessionThreshold"){
        
        $NewThreshold = (Get-Tests | Where {$_.id -eq $NewTestId}).thresholds | Where {$_.type -eq $Threshold.type}
                      
        $Body = [ordered]@{
            isEnabled = $Threshold.isEnabled
            value = $Threshold.value
        } | ConvertTo-Json

        $params = @{
        Uri         = 'https://' + $global:fqdn + '/publicApi/v4/tests/' + $TestId + '/thresholds/' + $NewThreshold.id
        Headers     = $header
        Method      = 'PUT'
        Body        = $Body
        ContentType = 'application/json'
        }

    }

    $Response = Invoke-RestMethod @params
$Response.id
}

$Response = Get-Tests | Out-GridView -OutputMode Single
if($Response -eq $Null){Exit}

$NewTestId = Copy-Test $Response

$New = Get-Tests | Where {$_.id -eq $NewTestId}

Update-Test -OldTest $Response -Newtest $New
