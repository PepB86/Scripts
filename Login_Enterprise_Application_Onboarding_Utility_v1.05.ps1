
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()


$Form = New-Object system.Windows.Forms.Form
$Form.ClientSize = New-Object System.Drawing.Point(1500, 800)
$Form.text = "Login Enterprise Application Onboarding Utility"
$Form.TopMost = $false


$Label3 = New-Object system.Windows.Forms.Label
$Label3.text = "i"
$Label3.AutoSize = $true
$Label3.width = 25
$Label3.height = 8
$Label3.location = New-Object System.Drawing.Point(210, 115)
$Label3.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 7, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic -bor [System.Drawing.FontStyle]::Underline))
$Label3ToolTip = New-Object system.Windows.Forms.ToolTip
$Label3ToolTip.ToolTipTitle = "FQDN"
$Label3ToolTip.isBalloon = $true
$Label3Tooltip.SetToolTip($Label3, 'Please enter the Fully Qualified Domain Name (FQDN) of your Login Enterprise appliance. For example loginenterprise.domain.local')


$Label4 = New-Object system.Windows.Forms.Label
$Label4.text = "i"
$Label4.AutoSize = $true
$Label4.width = 25
$Label4.height = 10
$Label4.location = New-Object System.Drawing.Point(210, 150)
$Label4.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 7, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic -bor [System.Drawing.FontStyle]::Underline))
$Label4ToolTip = New-Object system.Windows.Forms.ToolTip
$Label4ToolTip.ToolTipTitle = "API Token"
$Label4ToolTip.isBalloon = $true
$Label4ToolTip.SetToolTip($Label4, 'Please enter the V4 API Token which you can generate through the Login Enterprise Web Console. You can create a token under "External Notifications > Public API"  ')

$Label5 = New-Object system.Windows.Forms.Label
$Label5.text = "Scan the shortcuts on the local machine for applications"
$Label5.AutoSize = $true
$Label5.width = 300
$Label5.height = 40
$Label5.location = New-Object System.Drawing.Point(370, 45)
$Label5.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Label1 = New-Object system.Windows.Forms.Label
$Label1.text = "FQDN"
$Label1.AutoSize = $true
$Label1.width = 25
$Label1.height = 10
$Label1.location = New-Object System.Drawing.Point(155, 118)
$Label1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)


$Label2 = New-Object system.Windows.Forms.Label
$Label2.text = "API Token"
$Label2.AutoSize = $true
$Label2.width = 25
$Label2.height = 10
$Label2.location = New-Object System.Drawing.Point(130, 153)
$Label2.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)


$TextBox1 = New-Object system.Windows.Forms.TextBox
$TextBox1.multiline = $false
$TextBox1.width = 607
$TextBox1.height = 20
$TextBox1.location = New-Object System.Drawing.Point(240, 115)
$TextBox1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic))
$TextBox1.Text = "loginenterprise.domain.local"
$TextBox1.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#c0c0c0")

$TextBox2 = New-Object system.Windows.Forms.TextBox
$TextBox2.multiline = $false
$TextBox2.width = 607
$TextBox2.height = 20
$TextBox2.location = New-Object System.Drawing.Point(240, 150)
$TextBox2.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic))
$TextBox2.Text = "DFEG_p1LBkX-bZG1LdDUVhh1ex2_9HQVVGScg2weD1R"
$TextBox2.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#c0c0c0")

$Scan = New-Object system.Windows.Forms.Button
$Scan.text = "Scan"
$Scan.width = 100
$Scan.height = 55
$Scan.location = New-Object System.Drawing.Point(240, 25)
$Scan.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Create = New-Object system.Windows.Forms.Button
$Create.text = "Create"
$Create.width = 100
$Create.height = 60
$Create.enabled = $false
$Create.location = New-Object System.Drawing.Point(880, 114)
$Create.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10)

$Groupbox1 = New-Object system.Windows.Forms.Groupbox
$Groupbox1.height = 80
$Groupbox1.width = 1455
$Groupbox1.text = "Step 1"
$Groupbox1.location = New-Object System.Drawing.Point(23, 10)
$Groupbox1.Anchor = 'top,left,right'

$Groupbox2 = New-Object system.Windows.Forms.Groupbox
$Groupbox2.height = 100
$Groupbox2.width = 1455
$Groupbox2.text = "Step 2"
$Groupbox2.Anchor = 'top,left,right'
$Groupbox2.location = New-Object System.Drawing.Point(23, 90)


$DataGridView1 = New-Object system.Windows.Forms.DataGridView
$DataGridView1.width = 1455
$DataGridView1.height = 575
$DataGridView1.Anchor = 'top,right,bottom,left'
$DataGridView1.location = New-Object System.Drawing.Point(23, 205)
$dataGridView1.SelectionMode = [System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$DataGridView1.AutoSizeColumnsMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::AllCells


$Form.controls.AddRange(@($TextBox1, $TextBox2, $Scan, $Create, $DataGridView1, $Label1, $Label2, $Label3, $Label4, $Label5, $Groupbox1, $Groupbox2))



$TextBox1.Add_Click{
    $TextBox1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Regular))
    $TextBox1.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#000000")
    
    if (($TextBox1.Text -eq '') -or ($TextBox1.Text -eq "Where are we going with this?") -or ($TextBox1.Text -eq "FQDN") -or ($TextBox1.Text -eq "loginenterprise.domain.local")) {  
        $TextBox1.Clear()
    }
}

$TextBox1.Add_Leave{
    if ($TextBox1.Text -eq '') {
        $TextBox1.Text = "loginenterprise.domain.local"
        $TextBox1.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic))
        $TextBox1.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#c0c0c0")
    }
}

$TextBox2.Add_Click{
    $TextBox2.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Regular))
    $TextBox2.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#000000")
    
    if (($TextBox2.Text -eq '') -or ($TextBox2.Text -eq "Give me all your tokes!!!!!") -or ($TextBox2.Text -eq "FQDN") -or ($TextBox2.Text -eq "DFEG_p1LBkX-bZG1LdDUVhh1ex2_9HQVVGScg2weD1R")) {  
        $TextBox2.Clear()
    }
}

$TextBox2.Add_Leave{
    if ($TextBox2.Text -eq '') {
        $TextBox2.Text = "DFEG_p1LBkX-bZG1LdDUVhh1ex2_9HQVVGScg2weD1R"
        $TextBox2.Font = New-Object System.Drawing.Font('Microsoft Sans Serif', 10, [System.Drawing.FontStyle]([System.Drawing.FontStyle]::Italic))
        $TextBox2.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#c0c0c0")
    }
}

$Label3.Add_Click{
    $Label3Tooltip.SetToolTip($Label3, 'Please enter the Fully Qualified Domain Name (FQDN) of your Login Enterprise appliance. For example loginenterprise.domain.local')
}

$Label4.Add_Click{
    $Label4ToolTip.SetToolTip($Label4, 'Please enter the V4 API Token which you can generate through the Login Enterprise Web Console. You can create a token under "External Notifications > Public API"  ')
}

$ScanResult = $null

$Scan.Add_Click( { 
        $Global:ScanResult = "1"
        $Create.enabled = $true
    
        $DataGridView1.Rows.Clear()
        $DataGridView1.ColumnCount = 4
        $DataGridView1.ColumnHeadersVisible = $true
        $DataGridView1.Columns[0].Name = "LongName"
        $DataGridView1.Columns[1].Name = "Cmdline"
        $DataGridView1.Columns[2].Name = "Path"
        $DataGridView1.Columns[3].Name = "Name"

        $localapps = Get-Shortcuts "$env:appdata\microsoft\windows\start menu\", 'C:\ProgramData\Microsoft\Windows\Start Menu'
        foreach ($row in $localapps) {

            $Data = @(@($row.LongName, $row.Cmdline, $row.Path, $row.Name))    
            $DataGridView1.Rows.Add($Data)
        }

    })

$Create.Add_Click( {
        $global:url = 'https://' + $Textbox1.Text + '/publicApi/v4/applications'
        $global:token = ($TextBox2.text) 

        if ($Global:ScanResult -eq $null ) { 
         

            $DataGridView1.Rows.Clear()
            $DataGridView1.ColumnCount = 1
            $DataGridView1.Columns[0].Name = "O oh!"
        
            $ScanMessage = "How about scanning first?"
            $Data = @(@($ScanMessage))
            $DataGridView1.Rows.Add($Data)
        
        } 
        if (($TextBox1.Text -eq '') -or ($TextBox1.Text -eq "Where are we going with this?") -or ($TextBox1.Text -eq "FQDN") -or ($TextBox1.Text -eq "loginenterprise.domain.local")) {      
            $TextBox1.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#000000")
            $TextBox1.Text = "Where are we going with this?"

        }

        if (($TextBox2.Text -eq '') -or ($TextBox2.Text -eq "Give me all your tokes!!!!!") -or ($TextBox2.Text -eq "DFEG_p1LBkX-bZG1LdDUVhh1ex2_9HQVVGScg2weD1R")) {      
            $TextBox2.ForeColor = [System.Drawing.ColorTranslator]::FromHtml("#000000")
            $TextBox2.Text = "Give me all your tokes!!!!!"

        }
    
        Else {
        
            $selection = ForEach ($row in $DataGridView1.SelectedRows) {
            
                $Objects = @{
                    LongName = $row.cells[0].Value
                    Cmdline  = $row.cells[1].Value
                    Path     = $row.cells[2].Value
                    Name     = $row.cells[3].Value
                }
                New-Object PSObject -Property $Objects
            }
        
            $DataGridView1.Rows.Clear()
            $DataGridView1.ColumnCount = 5
            $DataGridView1.Columns[4].Name = "Result"
            $Selection | Add-Member result $null
            $Selection | Add-Member id $null
        

            foreach ($app in $selection) {
                $app.id = try {
                    New-LeApplication -commandline $app.Cmdline -name $app.LongName -description $app.name 
                }
                catch [System.Net.WebException] {
                    "Application with identical name " + $app.name + " already exists"
                }
                catch {
                    "An error occurred that could not be resolved."
                }

                if ($app.id -match ("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$")) {
                    $app.result = "Succeeded"    
                }
                else {
                    $app.result = $app.id            
                }


                $Data = @(@($app.LongName, $app.Cmdline, $app.Path, $app.Name, $app.result))
                $DataGridView1.Rows.Add($Data)   
            
            }

        }
    })

# this is only required for older version of PowerShell/.NET
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

function Get-Shortcuts {
    Param (
        [array]$Paths
    )
    $ErrorActionPreference = "SilentlyContinue"
    foreach ($Path in $Paths) {
        $Shortcuts += Get-ChildItem -Recurse $Path -Include *.lnk
    }
    $Shell = New-Object -ComObject WScript.Shell
 
    
    $Apps = foreach ($Shortcut in $Shortcuts) {
        if ($Shell.CreateShortcut($Shortcut).targetpath -ne "") {
            $Properties = @{
                Cmdline  = $Shell.CreateShortcut($Shortcut).targetpath
                Name     = $Shell.CreateShortcut($Shortcut).targetpath | Split-Path -Leaf | ForEach-Object { $_.trim("EXE") } | ForEach-Object { $_.trim("exe") } | ForEach-Object { $_.trim(".") }
                LongName = $Shortcut.BaseName
                Path     = $Shortcut.FullName

            }
            New-Object PSObject -Property $Properties
        }	      
    }
    
    Return $Apps | Sort-Object Path
}
         

function Get-LeApplications {
    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
        

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true; }

    $Header = @{
        Authorization = "Bearer $global:token"
    }

    $Body = @{
        orderBy   = "Name"
        direction = "Ascending"
        count     = "50"
        include   = "none" 
    } 

    $Parameters = @{
        Uri     = $global:url
        Headers = $Header
        body    = $body

    }

    $applications = Invoke-RestMethod @Parameters
    return $Applications.items 
}


function New-LeApplication {
    Param (
        [string]$commandline,
        [string]$name,
        [string]$description
    )

    # this is only required for older version of PowerShell/.NET
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11
        

    # WARNING: ignoring SSL/TLS certificate errors is a security risk
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true; }

    $application = @{
        '$type'     = "WindowsApp"
        commandline = $commandline
        id          = New-Guid
        name        = $name
        description = $description
    } | ConvertTo-Json

    $header = @{
        "Accept"        = "application/json"
        "Authorization" = "Bearer $global:token"
    }

    $params = @{
        Uri         = $global:url
        Headers     = $header
        Method      = 'POST'
        Body        = $application
        ContentType = 'application/json'
    }

    $Response = Invoke-RestMethod @params
    $Response.id
}



[void]$Form.ShowDialog()