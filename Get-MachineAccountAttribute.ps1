function Get-MachineAccountAttribute
{
    <#
    .SYNOPSIS
    This function can return values populated in machine account attributes.

    .DESCRIPTION
    This function is primarily for use with New-MachineAccount and Set-MachineAccountAttribute.
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain.

    .PARAMETER MachineAccount
    The username of the machine account that will be modified.

    .PARAMETER Attribute
    The machine account attribute.

    .PARAMETER Value
    The machine account attribute value.

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
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$true)][String]$Attribute
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