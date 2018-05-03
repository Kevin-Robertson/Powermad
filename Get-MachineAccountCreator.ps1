function Get-MachineAccountCreator
{
    <#
    .SYNOPSIS
    This function leverages the ms-DS-CreatorSID property on machine accounts to return a list
    of usernames or SIDs and the associated machine account. The ms-DS-CreatorSID property is only
    populated when a machine account is created by an unprivileged user. Note that SIDs will be returned
    over usernames if SID to username lookups fail through System.Security.Principal.SecurityIdentifier.

    .DESCRIPTION
    This function can be used to see how close a user is to a ms-DS-MachineAccountQuota before
    using New-MachineAccount.
    
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

    .EXAMPLE
    Get-MachineAccountCreator

    .EXAMPLE
    $user_account_password = ConvertTo-SecureString 'Spring2018!' -AsPlainText -Force
    $user_account_creds = New-Object System.Management.Automation.PSCredential('domain\user',$user_account_password)
    Get-MachineAccountCreator -Credential $user_account_creds

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
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

    if(!$DistinguishedName)
    {
        $distinguished_name = "CN=Computers"
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

    try
    {

        if($Credential)
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainController/$distinguished_name",$Credential.UserName,$credential.GetNetworkCredential().Password)
        }
        else
        {
            $directory_entry = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$DomainController/$distinguished_name"
        }
        
        $machine_account_searcher = New-Object DirectoryServices.DirectorySearcher 
        $machine_account_searcher.SearchRoot = $directory_entry  
        $machine_accounts = $machine_account_searcher.FindAll() | where-object {$_.properties.objectcategory -match "CN=computer"}  
        $creator_object_list = @()
                                                    
        ForEach($account in $machine_accounts)
        {
            $creator_SID_object = $account.properties."ms-ds-creatorsid"

            if($creator_SID_object)
            {
                $creator_SID = (New-Object System.Security.Principal.SecurityIdentifier($creator_SID_object[0],0)).Value
                $creator_object = New-Object PSObject

                try
                {
                    $creator_username = (New-Object System.Security.Principal.SecurityIdentifier($creator_SID)).Translate([System.Security.Principal.NTAccount]).value
                    Add-Member -InputObject $creator_object -MemberType NoteProperty -Name Creator $creator_username
                }
                catch
                {
                    Add-Member -InputObject $creator_object -MemberType NoteProperty -Name Creator $creator_SID
                }
                
                Add-Member -InputObject $creator_object -MemberType NoteProperty -Name "Machine Account" $account.properties.samaccountname[0]
                $creator_object_list += $creator_object
                $creator_SID_object = $null
            }

        }

    }
    catch
    {
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        Write-Output "[-] $error_message"
        throw
    }

    Write-Output $creator_object_list | Sort-Object -property @{Expression = {$_.Creator}; Ascending = $false}, "Machine Account" | Format-Table -AutoSize
}