function Get-MachineAccountAttribute
{
    <#
    .SYNOPSIS
    This function can return values populated in machine account attributes.

    .DESCRIPTION
    This function is primarily for use with New-MachineAccount and Set-MachineAccountAttribute.
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER Credential
    Credentials for LDAP.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain. This parameter is mandatory on a non-domain attached system. Note this parameter
    requires a DNS domain name and not a NetBIOS version.

    .PARAMETER DomainController
    Domain controller to target. This parameter is mandatory on a non-domain attached system.

    .PARAMETER MachineAccount
    The username of the machine account that will be modified.

    .PARAMETER Attribute
    The machine account attribute.

    .EXAMPLE
    Get-MachineAccountAttribute -MachineAccount payroll -Attribute description

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
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
    )

    if(!$DomainController)
    {

        try
        {
            $DomainController = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers[0].Name
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
        $account = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
    }

    try
    {
        $output = $account.InvokeGet($Attribute)
    }
    catch
    {
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        Write-Output "[-] $error_message"
    }

    return $output
}