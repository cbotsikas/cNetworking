#
# This module was written to provide the ability to add Windows Firewall rules
# using Desired State Configuration on Windows Server 2008 R2 servers.
#
# This module is modelled off the community xFirewall DSC Resource which is
# part of the xNetworking module.
# (https://gallery.technet.microsoft.com/scriptcenter/xNetworking-Module-818b3583)



# DSC uses the Get-TargetResource cmdlet to fetch the status of the resource instance specified in the parameters for the target machine
Function Get-TargetResource 
{    
    [OutputType([Hashtable])]
    param
    (        
        # Localized, user-facing name of the Firewall Rule being created        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,
        
        # Enable or disable the supplied configuration        
        [ValidateSet("Yes", "No")]
        [string]$Enabled,

        # Direction of the connection        
        [ValidateSet("In", "Out")]
        [string]$Direction,

        # Specifies one or more profiles to which the rule is assigned        
        [ValidateSet("Any", "Public", "Private", "Domain")]
        [string]$Profiles,

        # Local IP used for the filter        
        $LocalIP,

        # Remote IP used for the filter        
        $RemoteIP,

        # Path and file name of the program for which the rule is applied        
        [string]$Program,

        # Local Port used for the filter
        $LocalPort,

        # Remote Port used for the filter
        $RemotePort,

        # IP Protocol used for the filter
        $Protocol,

        # Permit or Block the supplied configuration 
        [ValidateSet("Bypass", "Allow", "Block")]
        $Action,

        # Ensure the presence/absence of the resource
        [ValidateSet("Present", "Absent")]
        [String]$Ensure
    )

    Write-Verbose "GET: Get Rules for the specified DisplayName[$DisplayName]"
    $FirewallRules = Get-cLegacyFWRule -DisplayName $DisplayName

    if (!($FirewallRules.'Rule Name'))
    {        
        Write-Verbose "GET: Firewall Rule does not exist"

        $ReturnValue = @{
            Ensure = "Absent"
        }

        return $ReturnValue
    }

    foreach ($FirewallRule in (($FirewallRules | Sort)[0]))
    {
        $RuleName = $FirewallRule.'Rule Name'
        Write-Verbose "GET: Firewall rule found. Adding rule [$RuleName] to return object as [Rule $i : $RuleName]" -Verbose
        $ReturnValue = @{
            DisplayName  = $FirewallRule.'Rule Name'
            Enabled      = $FirewallRule.Enabled
            Direction    = $FirewallRule.Direction
            Profiles     = $FirewallRule.Profiles
            LocalIP      = $FirewallRule.LocalIP
            RemoteIP     = $FirewallRule.RemoteIP
            Program      = $FirewallRule.Program
            LocalPort    = $FirewallRule.LocalPort
            RemotePort   = $FirewallRule.RemotePort
            Protocol     = $FirewallRule.Protocol
            Action       = $FirewallRule.Action
            Ensure       = "Present"
        }
    }

    return $ReturnValue
}










# DSC uses Set-TargetResource cmdlet to create, delete or configure the resource instance on the target machine
Function Set-TargetResource 
{   
    param 
    (        
        # Localized, user-facing name of the Firewall Rule being created        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$DisplayName,
        
        # Enable or disable the supplied configuration        
        [ValidateSet("Yes", "No")]
        [String]$Enabled = "Yes",

        # Direction of the connection        
        [ValidateSet("In", "Out")]
        [String]$Direction = "In",

        # Specifies one or more profiles to which the rule is assigned        
        [ValidateSet("Any", "Public", "Private", "Domain")]
        [String]$Profiles = "Any",

        # Local IP used for the filter        
        $LocalIP = "Any",

        # Remote IP used for the filter        
        $RemoteIP = "Any",

        # Path and file name of the program for which the rule is applied        
        [String]$Program,

        # Local Port used for the filter
        $LocalPort,

        # Remote Port used for the filter
        $RemotePort,

        # IP Protocol used for the filter
        $Protocol,

        # Permit or Block the supplied configuration 
        [ValidateSet("Bypass", "Allow", "Block")]
        [String]$Action,

        # Ensure the presence/absence of the resource
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present"
    )
    
    If (!($Action)) {$Action = "Allow"}
    
    Write-Verbose "SET: Get Rules for the specified DisplayName [$DisplayName]"
    $FirewallRules = Get-cLegacyFWRule -DisplayName $DisplayName
    
    $exists = If ($FirewallRules.'Rule Name') {$true} Else {$false}
    
    if ($Ensure -eq "Present")
    {        
        Write-Verbose "SET: We want the firewall rule to exist since Ensure is set to $Ensure"
        if ($exists)
        {
            # Ensure the existing rule matches what we want
            Write-Verbose "SET: Checking for multiple rules with the same Displayname [$DisplayName]"
            If ($FirewallRules.Count -gt 1) {
                Write-Verbose "SET: Multiple rules found. Removing all rules before creating a new rule"
                $DeleteCommand = @(netsh advfirewall firewall delete rule name=$DisplayName)
            }
            
            Write-Verbose "SET: Check firewall rule for valid properties"
            foreach ($FirewallRule in $FirewallRules)
            {
                Write-Verbose "SET: Check each defined parameter against the existing firewall rule [$($FirewallRule.'Rule Name')]"
                if (Test-RuleHasProperties -FirewallRule $FirewallRule `
                                           -DisplayName $DisplayName `
                                           -Enabled $Enabled `
                                           -Direction $Direction `
                                           -Profiles $Profiles `
                                           -LocalIP $LocalIP `
                                           -RemoteIP $RemoteIP `
                                           -Program $Program `
                                           -LocalPort $LocalPort `
                                           -RemotePort $RemotePort `
                                           -Protocol $Protocol `
                                           -Action $Action)
                {
                    # Do nothing, firewall rule is correct
                }
                else
                {
                    # Remove firewall rule and create new rule with correct parameters
                    Write-Verbose "SET: Removing existing firewall rule [$DisplayName] to recreate one based on desired configuration"
                    $DeleteCommand = @(netsh advfirewall firewall delete rule name=$DisplayName)

                    $AddCommand = Add-cLegacyFWRule
                    If ($AddCommand -like "Ok*") {Write-Verbose "SET: The firewall rule [$DisplayName] was added"}
                }
            }     
        }        
        else
        {
            # Create the rules due to '$Ensure -eq "Present"'
            Write-Verbose "SET: We want the firewall rule [$DisplayName] to exist, but it does not"

            $AddCommand = Add-cLegacyFWRule
            If ($AddCommand -like "Ok*") {Write-Verbose "SET: The firewall rule [$DisplayName] was added"}
        }
    }    
    elseif ($Ensure -eq "Absent")
    {
        Write-Verbose "SET: We do not want the firewall rule to exist"        
        if ($exists)
        {
            # Remove the existing rule due to '$Ensure -eq "Absent"'
            Write-Verbose "SET: We do not want the firewall rule to exist, but it does. Removing the Rule(s)"
            $DeleteCommand = @(netsh advfirewall firewall delete rule name=$DisplayName)
            If ($DeleteCommand -like "*Deleted*rule*") {Write-Verbose "SET: The firewall rule with Displayname [$Displayname] was deleted"}
        }        
        else
        {
            # Do Nothing
            Write-Verbose "SET: We do not want the firewall rule to exist, and it does not"
        }           
    }
}










# DSC uses Test-TargetResource cmdlet to check the status of the resource instance on the target machine
Function Test-TargetResource
{ 
    [OutputType([Boolean])]
    param
    (        
        # Localized, user-facing name of the Firewall Rule being created        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]$DisplayName,
        
        # Enable or disable the supplied configuration        
        [ValidateSet("Yes", "No")]
        [String]$Enabled = "Yes",

        # Direction of the connection        
        [ValidateSet("In", "Out")]
        [String]$Direction = "In",

        # Specifies one or more profiles to which the rule is assigned        
        [ValidateSet("Any", "Public", "Private", "Domain")]
        [String]$Profiles = "Any",

        # Local IP used for the filter        
        $LocalIP = "Any",

        # Remote IP used for the filter        
        $RemoteIP = "Any",

        # Path and file name of the program for which the rule is applied        
        [String]$Program,

        # Local Port used for the filter
        $LocalPort,

        # Remote Port used for the filter
        $RemotePort,

        # IP Protocol used for the filter
        $Protocol,

        # Permit or Block the supplied configuration 
        [ValidateSet("Bypass", "Allow", "Block")]
        [String]$Action,

        # Ensure the presence/absence of the resource
        [ValidateSet("Present", "Absent")]
        [String]$Ensure = "Present"
    )
    
    Write-Verbose "TEST: Find rules with specified parameters"
    $FirewallRules = Get-cLegacyFWRule -DisplayName $DisplayName
    
    if (!($FirewallRules.'Rule Name'))
    {        
        Write-Verbose "TEST: Firewall Rule does not exist"

        $ReturnValue = (($Ensure -eq "Present") -eq $false)

        return $ReturnValue
    }


    $exists = $true
    $valid = $true
    foreach ($FirewallRule in $FirewallRules)
    {
        Write-Verbose "TEST: Check each defined parameter against the existing firewall rule [$($firewallRule.'Rule Name')]"
        if (Test-RuleHasProperties -FirewallRule $FirewallRule `
                                   -DisplayName $DisplayName `
                                   -Enabled $Enabled `
                                   -Direction $Direction `
                                   -Profiles $Profiles `
                                   -LocalIP $LocalIP `
                                   -RemoteIP $RemoteIP `
                                   -Program $Program `
                                   -LocalPort $LocalPort `
                                   -RemotePort $RemotePort `
                                   -Protocol $Protocol `
                                   -Action $Action )
        {
            
        }
        else
        {
            $valid = $false
        }
    }

    # Returns whether or not $exists complies with $Ensure
    $ReturnValue = ($valid -and $exists -eq ($Ensure -eq "Present"))

    Write-Verbose "TEST: Returning $ReturnValue"
    
    return $ReturnValue
}





#region HelperFunctions

######################
## Helper Functions ##
######################



# Function to validate if the supplied Rule adheres to all parameters set
Function Test-RuleHasProperties
{
    param (
        [Parameter(Mandatory)]
        $FirewallRule,
        [String]$DisplayName,
        [String]$Enabled,
        [String]$Direction,
        $Profiles,
        $LocalIP,
        $RemoteIP,
        [String]$Program,
        $LocalPort,
        $RemotePort,
        $Protocol,
        [String]$Action
    )

    $desiredConfigurationMatch = $true

    if ($DisplayName -and ($FirewallRule.'Rule Name' -ne $DisplayName))
    {
        Write-Verbose "Function: Test-RuleHasProperties: DisplayName property value - $FirewallRule.'Rule Name' does not match desired state - $DisplayName"

        $desiredConfigurationMatch = $false
    }

    if ($Enabled -and ($FirewallRule.Enabled -ne $Enabled))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Enabled property value - $($FirewallRule.Enabled) does not match desired state - $Enabled"

        $desiredConfigurationMatch = $false
    }

    if ($Direction -and ($FirewallRule.Direction -ne $Direction))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Direction property value - $($FirewallRule.Direction) does not match desired state - $Direction"

        $desiredConfigurationMatch = $false
    }

    if ($Profiles -eq "Any")
    {
        if ($Profiles -and ($FirewallRule.Profiles -ne "Domain,Private,Public"))
        {
            Write-Verbose "Function: Test-RuleHasProperties: Profiles property value - $($FirewallRule.Profiles) does not match desired state - $Profiles"
            
            $desiredConfigurationMatch = $false
        }
    }
    elseif ($Profiles -and ($FirewallRule.Profiles -ne $Profiles))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Profiles property value - $($FirewallRule.Profiles) does not match desired state - $Profiles"
        
        $desiredConfigurationMatch = $false
    }

    if ($LocalIP -and ($FirewallRule.LocalIP -ne $LocalIP))
    {
        Write-Verbose "Function: Test-RuleHasProperties: LocalIP property value - $($FirewallRule.LocalIP) does not match desired state - $LocalIP"

        $desiredConfigurationMatch = $false
    }

    if ($RemoteIP -and ($FirewallRule.RemoteIP -ne $RemoteIP))
    {
        Write-Verbose "Function: Test-RuleHasProperties: RemoteIP property value - $($FirewallRule.RemoteIP) does not match desired state - $RemoteIP"

        $desiredConfigurationMatch = $false
    }

    if ($Program -and ($FirewallRule.Program -ne $Program))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Program property value - $($FirewallRule.Program) does not match desired state - $Program"

        $desiredConfigurationMatch = $false
    }

    if ($LocalPort -and ($FirewallRule.LocalPort -ne $LocalPort))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Program property value - $($FirewallRule.LocalPort) does not match desired state - $LocalPort"

        $desiredConfigurationMatch = $false
    }

    if ($RemotePort -and ($FirewallRule.RemotePort -ne $RemotePort))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Program property value - $($FirewallRule.RemotePort) does not match desired state - $RemotePort"

        $desiredConfigurationMatch = $false
    }

    if ($Protocol -and ($FirewallRule.Protocol -ne $Protocol))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Program property value - $($FirewallRule.Protocol) does not match desired state - $Protocol"

        $desiredConfigurationMatch = $false
    }

    if ($Action -and ($FirewallRule.Action -ne $Action))
    {
        Write-Verbose "Function: Test-RuleHasProperties: Action property value - $($FirewallRule.Action) does not match desired state - $Action"

        $desiredConfigurationMatch = $false
    }

    Write-Verbose "Function: Test-RuleHasProperties returning $desiredConfigurationMatch"
    return $desiredConfigurationMatch
}




Function Get-cLegacyFWRule {
Param ([string]$DisplayName)
    $Output = @(netsh advfirewall firewall show rule name="$DisplayName" dir=in verbose)
    $Object = New-Object -Type PSObject
    $Output | Where {$_ -match '^([^:]+):\s*(\S.*)$' } | Foreach -Begin {
        $FirstRun = $true
        $HashProps = @{}
    } -Process {
        if (($Matches[1] -eq 'Rule Name') -and (!($FirstRun))) {
            New-Object -TypeName PSCustomObject -Property $HashProps
            $HashProps = @{}
        } 
        $HashProps.$($Matches[1]) = $Matches[2]
        $FirstRun = $false
    } -End {
        New-Object -TypeName PSCustomObject -Property $HashProps
    }
}



Function Add-cLegacyFWRule {
    # Set the Firewall rule based on specified parameters
    
    $RunCommand = "netsh advfirewall firewall add rule"
    If ($Displayname)         {$RunCommand += " name=`"$Displayname`""}
    If ($Direction)           {$RunCommand += " dir=$Direction"}
    If ($Action)              {$RunCommand += " action=$Action"}
    If ($Enabled)             {$RunCommand += " enable=$Enabled"}
    If ($LocalIP -ne "Any")   {$RunCommand += " localip=$LocalIP"}
    If ($RemoteIP -ne "Any")  {$RunCommand += " remoteip=$RemoteIP"}
    If ($Profiles)            {$RunCommand += " profile=$Profiles"}
    If ($Program)             {$RunCommand += " program=`"$Program`""}
    If ($LocalPort)           {$RunCommand += " localport=`"$LocalPort`""}
    If ($RemotePort)          {$RunCommand += " remoteport=`"$RemotePort`""}
    If ($Protocol)            {$RunCommand += " protocol=$Protocol"}

    $retVal = Invoke-Expression -Command:$RunCommand

    return $retVal
}

# endregion

Export-ModuleMember -Function *-TargetResource
