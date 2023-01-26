#Requires -RunAsAdministrator
#Requires -Version 5.0
<#
    .SYNOPSIS
        Powershell script to grant Task Scheduler permissions for specific task folders to a non-privileged local group of users. 
    .DESCRIPTION
        Set-TaskSDBinary.ps1 Written April 2021
        DEPENDENCIES:
            - Elevated Session
            - Powershell >=5.0
            - Invoke-CommandAs
    .EXAMPLE
        Set-TaskSDBinary.ps1 -TaskFolderName "MyTasks" -LocalUserGroup "Remote Desktop Users"
    .PARAMETER
    .INPUTS
        [String]TaskFolderName (Sub-folder inside Task Scheduler)
        [String]LocalUserGroup (to Authorize)
    .OUTPUTS
        None
    .NOTES
        TODO:
            - Finish sanity checks
            - Draft function to update permissions 
            - Fix following error:
                A Using variable cannot be retrieved. A Using variable can be used only with Invoke-Command, Start-Job, or
                InlineScript in the script workflow. When it is used with Invoke-Command, the Using variable is valid only if the
                script block is invoked on a remote computer.
                At line:1 char:32
                + Invoke-CommandAs -ScriptBlock {write-host $using:ChildTaskRegKeys}
                +                                ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                + CategoryInfo          : InvalidOperation: (:) [], RuntimeException
                + FullyQualifiedErrorId : UsingWithoutInvokeCommand
                
    .LINK
        
#>

[CmdletBinding()]
param(
    [Parameter(Position=0,Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String] $TaskFolderName,
    [Parameter(Position=1,Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String] $LocalUserGroup
)

## VERIFICATION STEPS
# Verify that registry key exists for task
$TaskRegKeyStatus = $(Test-Path -Path $("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" + $TaskFolderName))
# Verify that task folder exists
$TaskFolderStatus = $(Test-Path -Path $("C:\Windows\System32\Tasks\" + $TaskFolderName))
If (($TaskRegKeyStatus -eq $False) -or ($TaskFolderStatus -eq $False)){
    Write-Error -Message "Specified TaskFolderName doesn't exist, please double check the name & retry."
    Exit 1
}
# Verify that local user group exists
$LocalUserGroupStatus = $(If ((Get-LocalGroup | Where-object {$_.Name -eq $LocalUserGroup}).count -gt 0){$True}else{$False})
If ($LocalUserGroupStatus -eq $False){
    Write-Error -Message "Specified LocalUserGroup doesn't exist, please double check the name & retry."
    Exit 2
}

## INSTALL DEPENDENCIES
# Install Invoke-CommandAs if missing
If ($null -eq $(Get-InstalledModule -Name Invoke-CommandAs)){
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Force -Name Invoke-CommandAs -AllowClobber
    If ($? -eq $False){
        Write-Error -Message "Required Invoke-CommandAs dependency failed to download & install. ` Please try checking your internet connection or installing manually."
        Exit 3
    }
}

## DEFINE FUNCTIONS
Function New-TempDir {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    $TempPath = $(Join-Path $parent $name)
    New-Item -ItemType Directory -Path $TempPath
}

Function Update-FolderACL {
param(
    [Parameter(Position=0,Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String] $Folder,
    [Parameter(Position=1,Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String] $Group
)
    $ACL = Get-ACL $Folder
    $ACLEntry = New-Object System.Security.AccessControl.FileSystemAccessRule("$Group", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $ACL.SetAccessrule($ACLEntry)
    Set-ACL $Folder $ACL
}

Function Update-RegistrySDBin {
    Param (
        [Parameter(Position=0,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $RegKey,
        [Parameter(Position=1,Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Group
    )
    $TempFolder = New-TempDir
    Invoke-CommandAs -ScriptBlock {
        Param(
            $RegKey,
            $Group,
            $TempFolder
        )
        $TaskSDBin = ((get-itemProperty $RegKey).sd); `
        $TaskSDDL = ([wmiclass]"Win32_SecurityDescriptorHelper").BinarySDToSDDL($TaskSDBin).SDDL; `
        $PathToFolder = $TempFolder; `
        $securityDescriptor = Get-Acl -Path $PathToFolder; `
        $securityDescriptor.SetSecurityDescriptorSddlForm($TaskSDDL); `
        Set-Acl -Path $PathToFolder -AclObject $securityDescriptor; `
        $ACL = Get-ACL $PathToFolder; `
        $ACLEntry = New-Object System.Security.AccessControl.FileSystemAccessRule("$Group", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"); `
        $ACL.SetAccessrule($ACLEntry); `
        Set-ACL $PathToFolder $ACL; `
        $securityDescriptor = Get-Acl -Path $PathToFolder; `
        $FolderSDBin = ([wmiclass]"Win32_SecurityDescriptorHelper").SDDLToBinarySD($securityDescriptor.Sddl).BinarySD; `
        Set-ItemProperty -Path $RegKey -Name SD -Value $FolderSDBin; `
    } -AsSystem -ArgumentList $RegKey,$Group,$($TempFolder.FullName)
    Remove-Item -Path $TempFolder.FullName
}

## DEFINE VARIABLES
# Define parent directory
$TaskFolder = $("C:\Windows\System32\Tasks\" + $TaskFolderName)
# Define parent registry key
$TaskRegKey = $("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\" + $TaskFolderName)
# Retrieve all child task folders
$ChildTaskFolders = Get-ChildItem -Path $TaskFolder -Recurse 
# Retrieve all child task registry keys
$ChildTaskRegKeys = Get-ChildItem -Path $TaskRegKey -Recurse

## UPDATE FOLDER ACLs
Update-FolderACL -Folder $TaskFolder -Group $LocalUserGroup
# Update Child Folders
ForEach ($childfolder in $ChildTaskFolders){
    Update-FolderACL -Folder $childfolder.FullName -Group $LocalUserGroup
}

## UPDATE REGISTRY SDBINARIES
Update-RegistrySDBin -RegKey $TaskRegKey -Group $LocalUserGroup
# Update Child RegKeys
ForEach ($childkey in $ChildTaskRegKeys){
    Update-RegistrySDBin -RegKey $childkey.PSPath -Group $LocalUserGroup
}