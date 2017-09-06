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

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain.

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
        [parameter(Mandatory=$true)][String]$MachineAccount
    )

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$Domain)
    {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }

    if(!$DistinguishedName)
    {

        $distinguished_name = "CN=$machine_account,CN=Computers"

        $DCArray = $Domain.Split(".")

        ForEach($DC in $DCArray)
        {
            $distinguished_name += ",DC=$DC"
        }

    }
    else 
    {
        $distinguished_name = "$DistinguishedName"
    }

    $account = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$distinguished_name"

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