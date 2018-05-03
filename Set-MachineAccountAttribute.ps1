function Set-MachineAccountAttribute
{
    <#
    .SYNOPSIS
    This function can populate an attribute for an account that was added through New-MachineAccount. Write
    access to the attribute is required. This function should be used with the same user that created the
    machine account.

    .DESCRIPTION
    The user account that creates a machine account is granted write access to some attributes. These attributes
    can be leveraged to help an added machine account blend in better or change values that were restricted by
    validation when the account was created.

    Here is a list of some of the usual write access enabled attributes:

    AccountDisabled
    description
    displayName
    DnsHostName
    ServicePrincipalName
    userParameters
    userAccountControl
    msDS-AdditionalDnsHostName
    msDS-AllowedToActOnBehalfOfOtherIdentity
    SamAccountName
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER Credential
    Credentials for account that was used to create the machine account.

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

    .PARAMETER Value
    The machine account attribute value.

    .EXAMPLE
    Set-MachineAccountAttribute -MachineAccount payroll -Attribute description -Value "Payroll app server"

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
        [parameter(Mandatory=$true)]$Value,
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
        $account.InvokeSet($Attribute,$Value)
        $account.SetInfo()
        Write-Output "[+] $attribute updated"
    }
    catch
    {
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        Write-Output "[-] $error_message"
    }

}