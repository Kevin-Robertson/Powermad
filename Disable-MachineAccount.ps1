function Disable-MachineAccount
{
    <#
    .SYNOPSIS
    This function disables a machine account added with New-MachineAccount. This function should be used with the same
    user that created the machine account.

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    Machine accounts added with New-MachineAccount cannot be deleted with an unprivileged user. Although users
    can remove systems from a domain that they added using ms-DS-MachineAccountQuota, the machine account in AD is
    just left in a disabled state. This function provides that ability. Ideally cleanup is performed after
    elevating privilege.

    Note that this function does not accept credentials.

    .PARAMETER Credential
    Credentials for account that was used to create the machine account.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain. This parameter is mandatory on a non-domain attached system.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER MachineAccount
    The username of the machine account that will be disabled.

    .EXAMPLE
    Disable-MachineAccount -MachineAccount iamapc

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
    )

    if(!$DomainController)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $DomainController = $current_domain.DomainControllers[0].Name
            $Domain = $current_domain.Name
        }
        catch
        {
            Write-Output "[-] domain controller not located"
            throw
        }

    }

    if(!$Domain)
    {

        try
        {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            Write-Output "[-] $error_message"
            throw
        }

    }

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=$machine_account,CN=Computers"
        $DC_array = $Domain.Split(".")

        ForEach($DC in $DC_array)
        {
            $distinguished_name += ",DC=$DC"
        }

    }
    else 
    {
        $distinguished_name = "$DistinguishedName"
    }

    Write-Verbose "[+] Distinguished Name=$distinguished_name"

    if($Credential)
    {
        $account = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$credential.GetNetworkCredential().Password)
    }
    else
    {
        $account = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$distinguished_name"
    }

    if(!$account.InvokeGet("AccountDisabled"))
    {

        try 
        {
            $account.InvokeSet("AccountDisabled","True")
            $account.SetInfo()
            Write-Output "[+] $machine_account has been disabled"
        }
        catch
        {
            $error_message = $_.Exception.Message
            $error_message = $error_message -replace "`n",""
            Write-Output "[-] $error_message"
        }

    }
    else
    {
        Write-Output "[-] $machine_account is already disabled"   
    }
    
}