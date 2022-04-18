#check for CQDPowerShell module to read data from CQD
if (!(Get-Module MSTeamsCQD -ListAvailable))
{
    # module not found
    Write-Warning 'Cannot find required module MSTeamsCQD, trying to install in current user context...'
    try
    {
        Install-Module MSTeamsCQD -ErrorAction Stop -Scope CurrentUser
    }
    catch
    {
        Write-Error 'Could not install PowerShell module MSTeamsCQD. This module is required for this action. Please install module manually from PowerShell Gallery or run Install-Module MSTeamsCQD.'
        break
    }
}


$ListOfDimensionsRaw = "
AllStreams.First UserType
AllStreams.Second UserType
AllStreams.Meeting Id
AllStreams.Conference Id
AllStreams.Organizer UPN
AllStreams.First UPN
AllStreams.Second UPN
AllStreams.Stream Direction
AllStreams.First Subnet
AllStreams.Second Subnet
AllStreams.Media Type
AllStreams.Start Time
AllStreams.End Time
AllStreams.Used Dns Resolve Cache
AllStreams.Session Type
AllStreams.Media Failure Type
AllStreams.Call Classification
AllStreams.Classification Reason

AllStreams.First User Agent Category
AllStreams.Second User Agent Category
AllStreams.First User Agent
AllStreams.Second User Agent
AllStreams.Transport
AllStreams.First Connectivity Ice
AllStreams.Second Connectivity Ice
AllStreams.First IP Address
AllStreams.Second IP Address
AllStreams.First Link Speed
AllStreams.Second Link Speed
AllStreams.First Port
AllStreams.Second Port
AllStreams.First Reflexive Local IP
AllStreams.Second Reflexive Local IP
AllStreams.First Relay IP
AllStreams.Second Relay IP
AllStreams.First Relay Port
AllStreams.Second Relay Port
AllStreams.First VPN
AllStreams.Second VPN
AllStreams.Applied Bandwidth Source
AllStreams.Bandwidth Est
AllStreams.Mediation Server Bypass Flag
AllStreams.First Cdr Connectivity Type
AllStreams.Second Cdr Connectivity Type
AllStreams.First Local Media Relay Address
AllStreams.Second Local Media Relay Address
AllStreams.First Remote Media Relay Address
AllStreams.Second Remote Media Relay Address
AllStreams.First Local Address Type
AllStreams.Second Local Address Type
AllStreams.First Remote Address Type
AllStreams.Second Remote Address Type
AllStreams.First Transport Protocol
AllStreams.Second Transport Protocol
SecondTenantDataEndpoint.First Reflexive Local IP Network
SecondTenantDataEndpoint.Second Reflexive Local IP Network



AllStreams.First PSTN Country Region
AllStreams.Second PSTN Country Region
AllStreams.PSTN Trunk FQDN
AllStreams.PSTN Carrier Name
AllStreams.PSTN Call Type
AllStreams.PSTN Connectivity Type
AllStreams.PSTN Final SIP Code Phrase
AllStreams.PSTN Call End Sub Reason
AllStreams.PSTN Event Type
AllStreams.PSTN Event Info Time
AllStreams.PSTN MP Location
AllStreams.PSTN Call End Reason

AllStreams.First Phone Number
AllStreams.Second Phone Number

AllStreams.Call Queue Identity
AllStreams.Auto Attendant Identity
AllStreams.Scheduling Source App Id
"

$ListOfDimensions = $ListOfDimensionsRaw.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)



$ListOfMeasuresRaw = "
Measures.Total Call Count
Measures.Avg Packet Loss Rate
Measures.Avg Packet Loss Rate Max
Measures.Avg Packet Utilization
Measures.Avg Jitter
Measures.Avg Jitter Max
"
$ListOfMeasures = $ListOfMeasuresRaw.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)




$SiteIPsRaw = "
192.168.0.0
192.168.10.0
"
$SiteIPs = $SiteIPsRaw.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)






$FUnionGroup = "subnets"
$CustomFilter = @()



# Adding filters
for ($i = 0; $i -le ($SiteIPs.length - 1); $i += 1) {
    $SiteIPs[$i]

    $F1 = New-Object pscustomobject
    $F1 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.First Subnet"
    $F1 | Add-Member -Type NoteProperty -Name FValue -Value $SiteIPs[$i]
    $F1 | Add-Member -Type NoteProperty -Name Op -Value 0
    $F1 | Add-Member -Type NoteProperty -Name FUnionGroup -Value $FUnionGroup
    $CustomFilter += $F1
    $F2 = New-Object pscustomobject
    $F2 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.Second Subnet"
    $F2 | Add-Member -Type NoteProperty -Name FValue -Value $SiteIPs[$i]
    $F2 | Add-Member -Type NoteProperty -Name Op -Value 0
    $F2 | Add-Member -Type NoteProperty -Name FUnionGroup -Value $FUnionGroup
    $CustomFilter += $F2

}

Get-CQDData -StartDate 04/06/2022 -EndDate 04/06/2022 -Dimensions $ListOfDimensions -Measures $ListOfMeasures -ShowQuery $True -CustomFilter $CustomFilter -OutputType datatable | Out-GridView