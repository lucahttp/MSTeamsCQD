# (c)2018 Microsoft Corporation. All rights reserved. This document is provided "as-is." Information and views expressed in this document,
# including URL and other Internet Web site references, may change without notice. You bear the risk of using it.
# This document does not provide you with any legal rights to any intellectual property in any Microsoft product.
# You may copy and use this document for your internal, reference purposes. You may modify this document for your internal purposes
#
################################################
# CQD POWERSHELL ##############################
# JUSTW/SETHHA #
# QUERY CQD DIRECT FROM POWERSHELL AND EXPORT #
# #
# Modified by
# Luca Sain
################################################

# Date: 30/03/2022
# Features added
# added UNION filter to perform more advanced queries with AND/OR statements



[CmdletBinding()]
param(
  # Non Dynamic params go here #
)
###############################
# BEGIN JWT DECODE FUNCTIONS #
###############################
function Convert-64String ([string]$datai) {
  $datai = $datai.Replace('-', '+').Replace('_', '/')
  switch ($datai.Length % 4) {
    0 { break }
    2 { $datai += '==' }
    3 { $datai += '=' }
    default { throw New-Object ArgumentException ('datai') }
  }
  return [System.Convert]::FromBase64String($datai)
}
#
function Decode-JWT ([string]$rawToken) {
  $Tokenparts = $rawToken.Split('.');
  $headers = [System.Text.Encoding]::UTF8.GetString((Convert-64String $Tokenparts[0]))
  $claims = [System.Text.Encoding]::UTF8.GetString((Convert-64String $Tokenparts[1]))
  $signature = (Convert-64String $Tokenparts[2])

  $customObject = [pscustomobject]@{
    headers   = ($headers | ConvertFrom-Json)
    claims    = ($claims | ConvertFrom-Json)
    signature = $signature
  }

  #Write-Verbose -Message ("JWT`r`n.headers: {0}`r`n.claims: {1}`r`n.signature: {2}`r`n" -f $headers,$claims,[System.BitConverter]::ToString($signature))
  return $customObject
}
#
function Get-JWTData {
  [CmdletBinding()]
  param
  (
    # Param1 help description
    [Parameter(Mandatory = $true)]
    [string]$Token,
    [switch]$Recurse
  )

  if ($Recurse) {
    $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Token))
    $DecodedJwt = Decode-JWT -rawToken $decoded
  }
  else {
    $DecodedJwt = Decode-JWT -rawToken $Token
  }
  #Write-Host("Token Values") -ForegroundColor Green
  #Write-Host ($DecodedJwt | Select headers,claims | ConvertTo-Json)
  return $DecodedJwt
}
#############################
# END JWT DECODE FUNCTIONS #
#############################



###############################
# BEGIN AAD AUTH FUNCTIONS #
###############################


####Function to Get the JWT Token VIA OAuth
function Get-CQDToken ([string]$client_id) {

  if ($CQDVer -eq "V2") {
    $CQDUri = "https://cqd.lync.com/spd/"
    $V2Token = $true
  }
  else {
    $CQDUri = "https://cqd.teams.microsoft.com/spd/"
    $V3Token = $true
  }


  
  Add-Type -AssemblyName System.Web
  $resourceUrl = $WebResource
  $redirectUrl = $CQDUri
  $nonce = [guid]::NewGuid().GUID
  $url = "https://login.microsoftonline.com/common/oauth2/authorize?response_type=token&redirect_uri=" +
  [System.Web.HttpUtility]::UrlEncode($redirectUrl) +
  "&client_id=$client_id" +
  "&prompt=none" + "&nonce=$nonce" + "&resource=" + [System.Web.HttpUtility]::UrlEncode($WebResource)


  Add-Type -AssemblyName System.Windows.Forms

  $form = New-Object -TypeName System.Windows.Forms.Form -Property @{ Width = 440; Height = 640 }
  $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{ Width = 420; Height = 600; Url = ($url) }
  $DocComp = {
    $Global:uri = $web.Url.AbsoluteUri
    #Write-Host $Global:uri
    if ($Global:Uri -match "error=[^&]*|access_token=[^&]*") { $form.Close() }
  }

  $web.ScriptErrorsSuppressed = $true
  $web.Add_DocumentCompleted($DocComp)
  $form.Controls.Add($web)
  $form.Add_Shown({ $form.Activate() })
  $form.ShowDialog() | Out-Null



  $Script:TokenLifeTime = [Web.HttpUtility]::ParseQueryString(($web.Url -replace '^.*?(expires_in.+)$', '$1'))['expires_in']
  #Write-Host $TokenLifeTime
  $Script:Token = [Web.HttpUtility]::ParseQueryString(($web.Url -replace '^.*?(access_token.+)$', '$1'))['access_token']
  # Write-Host $Token
  
  
  return ('Bearer {0}' -f $Script:Token)
 
}

#Function to connect to CQD Via AzureAD
function Connect-CqdOnline {
  if ($CQDVer -eq "V2") {
    $UriVar = "https://repository.cqd.lync.com/clientconfiguration"
  }
  else {
    $UriVar = "https://cqd.teams.microsoft.com/repository/clientconfiguration"
  }

  $ClientConfigUri = $UriVar
  $Script:Configuration = Invoke-RestMethod -Uri $ClientConfigUri -Method Get -SessionVariable WebSession -UserAgent "CQDPowerShell V2.0"
  $Script:WebResource = $Configuration.AuthLoginResource
  $Script:AADBearerToken = Get-CQDToken $Configuration.AuthWebAppClientId
  $Script:WebSession = $WebSession
  $Script:RepositoryApiBaseUrl = $Script:Configuration.RepositoryApiBaseUrl
  $WebSession.headers.Add('Authorization', $AADBearerToken)
  $ProvisioningStatus = Invoke-RestMethod -Uri ('{0}tenant/provision' -f $RepositoryApiBaseUrl) -Method Get -WebSession $Script:WebSession -UserAgent "CQDPowerShell V2.0"
  if ($ProvisioningStatus.Status -ne 'Provisioned') {
    throw ('CQD Not Provisioned for TenantId {0}. Stopping...' -f $ProvisioningStatus.TenantId)
  }
  $Script:DataServiceBaseUrl = Invoke-RestMethod -Uri ('{0}tenant/dataservice' -f $Script:RepositoryApiBaseUrl) -WebSession $Script:WebSession -Method Get -UserAgent "CQDPowerShell V2.0"
  
}
Export-ModuleMember -Function Connect-CqdOnline

#Function to validate if token exists or is valid and unexpired
function CheckToken {
  #Check to see if Token already exists
  if ($Script:AADBearerToken -eq $null) {
    Connect-CqdOnline
  }
  else {
    #Check Token
    $JWTDecoded = Get-JWTData $Script:Token
    $JWTI = $JWTDecoded.claims.iat
    $JWTE = $JWTDecoded.claims.exp
    $NowTimeUTC = Get-Date

    $origin = New-Object -Type DateTime -ArgumentList 1970, 1, 1, 0, 0, 0, 0
    $JWTIssuedTime = $origin.AddSeconds($JWTI)
    $JWTExpireTime = $origin.AddSeconds($JWTE)
    #Write-Host $JWTIssuedTime $JWTExpireTime

    if ($CQDVer -eq "V2") {

      if ($JWTDecoded.claims.aud -eq "https://cqd.lync.com") {
        if ($NowTimeUTC.ToUniversalTime() -gt $JWTExpireTime) {
          Write-Host "Token Expired"
          Connect-CqdOnline
        }
      }
      else {
        write-host "Wrong Token, Expecting V2"
        Connect-CqdOnline 
      }
    }
    elseif ($CQDVer -eq "V3") {
      if ($JWTDecoded.claims.aud -eq "https://cqd.teams.microsoft.com") {
        if ($NowTimeUTC.ToUniversalTime() -gt $JWTExpireTime) {
          Write-Host "Token Expired"
          Connect-CqdOnline
        }
      }
      else {
        write-host "Wrong Token, Expecting V3"
        Connect-CqdOnline 
      }

    }

  


  }

}

###############################
# END AAD AUTH FUNCTIONS #
###############################

#Function to get Array list of Dimensions available in CQD Cube
function Get-CQDDimensions {
  $DimensionsCheck = GetParams "Dimensions"
  return $DimensionsCheck

}
Export-ModuleMember -Function Get-CQDDimensions

function Get-CQDMeasures {
  $MeasuresCheck = GetParams "Measures"
  return $MeasuresCheck
}
Export-ModuleMember -Function Get-CQDMeasures

##Generate Dynamic List of CQD Measures and Dimensions
function GetParams ([string]$ParamType) {


  CheckToken

  $CubeRequest = Invoke-WebRequest -Uri ('{0}CubeStructure' -f $DataServiceBaseUrl) -WebSession $WebSession -Method Get -UserAgent "CQDPowerShell V2.0"
  $List = ConvertFrom-Json $CubeRequest

  $D = $List.Dimensions
  $Meas = $List.Measurements
  $Dimensions = @()
  $Measures = @()
  foreach ($i in $D) {
    $Dimensions += $i.Category
    $Dimensions += $i.Attributes


  }

  foreach ($a in $Meas) {
    $Measures += $a.Category
    $Measures += $a.Attributes

  }

  if ($ParamType -eq "Dimensions") {
    $DimensionName = $Dimensions.DataModelName

    $Di = @()
    foreach ($O in $DimensionName) {

      $O = $O.Replace("[", "")
      $O = $O.Replace("]", "")
      $Di += $O
    }
    return $Di
  }
  elseif ($ParamType -eq "Measures") {
    $MeasureName = $Measures.DataModelName
    $Mi = @()
    foreach ($M in $MeasureName) {
      $M = $M.Replace("[", "")
      $M = $M.Replace("]", "")
      $Mi += $M
    }
    return $Mi
  }


}


#Function for handling start-end date
function ProcessDateRange {

  $TS = New-TimeSpan $StartDate $EndDate
  if ($TS.Days -lt 0) {
    $DateErrorStartEnd = 'Error in Timerange. Confirm StartDate is BEFORE EndDate'
    Write-Host $DateErrorStartEnd
    throw $DateErrorStartEnd
  }
  $i = $TS.Days
  if 
($StartDate -eq $EndDate)
  { $DateList = @($EndDate) }
  else {    
    $DateList = @($EndDate)
    do {

      $DateList += $EndDate.AddDays(-$i)
      $i --

    }

    while ($i -ne 0)
  }



  foreach ($D in $DateList) {

    $DateF += "[" + $D.ToString('yyyy-MM-dd') + "],"

  }

  return $DateF
}
#Function to obtain days of week
function GetDaysofWeek {

  foreach ($DofWT in $Weekdays) {

    $DofW += "[" + $DofWT + "],"

  }
  return $DofW
}



function BuildWeekFilter {
  param(
    [Parameter()] [array]$TimeInput
  )

  # Create list containing "start of weeks'" (Sun) for last 6 month
  $endDay = Get-Date
  $startDay = (Get-Date).AddMonths(-6)
  $cqdLastSixMonthWeeks = @()
  for ($i = $startDay; $i -lt $endDay; $i = $i.AddDays(1)) {
    if (($i.DayOfWeek).ToString() -eq "Sunday") {
      $cqdLastSixMonthWeeks += $i.ToString("yyyy-MM-dd")
    }
  }

  # Initialize variable that will keep final list of "start of weeks'"
  $cqdWeeks = @()

  # There are two cases:
  # 1. Month is provided as an input e.g. "09" for Sep. Must be in this format. length of 2
  # 2. Start of week is provided as an input e.g. "2017-09-18". Must be in this format. length of 10
  $TimeInput | ForEach-Object {
    if ($_.Length -eq 2) {
      $tempMonth = $_
      $cqdLastSixMonthWeeks | ForEach-Object {
        if ($_ -like "*-$($tempMonth)-*") { $cqdWeeks += $_ }
      }
    }
    elseif ($_.Length -eq 10) {
      $cqdWeeks += $_
    }
  }

  # Create hash table representing CQD Week filter
  $cqdFilterWeek = @{}

  $Caption = ""
  $Value = ""
  $cqdWeeks | ForEach-Object { $Caption += "$($_) | " }
  $cqdWeeks | ForEach-Object { $Value += "[$($_)]," }

  $cqdFilterWeek.Add("DataModelName", "[AllStreams].[Week]")
  $cqdFilterWeek.Add("Caption", $Caption)
  $cqdFilterWeek.Add("Value", $Value)
  $cqdFilterWeek.Add("Operand", 0)
  $cqdFilterWeek.Add("UnionGroup", "")

  # Return Json object representing CQD Week filter
  return ($cqdFilterWeek | ConvertTo-Json)

}

#Function for creating UA Category Filter
function BuildUACategoryFilter {
  param(
    [Parameter()] [array]$UACategory
  )

  # Create hash table representing CQD UA Category filter
  $cqdFilterUACategory = @{}

  $Caption = ""
  $Value = ""
  $UACategory | ForEach-Object { $Caption += "$($_) | " }
  $Caption | ForEach-Object {
    $Length = $Caption.Trim().Length
    $Caption = $Caption.Trim().Substring(0, $Length - 1)
    $Caption = $Caption.Trim()
  }

  $UACategory | ForEach-Object { $Value += "[$($_)]," }
  $Value | ForEach-Object {
    $Length = $Value.Trim().Length
    $Value = $Value.Trim().Substring(0, $Length - 1)
    $Value = $Value.Trim()
  }

  $cqdFilterUACategory.Add("DataModelName", "[AllStreams].[Second User Agent Category]")
  $cqdFilterUACategory.Add("Caption", $Caption)
  $cqdFilterUACategory.Add("Value", $Value)
  $cqdFilterUACategory.Add("Operand", 0)
  $cqdFilterUACategory.Add("UnionGroup", "")

  # Return Json object representing CQD UA Category filter
  return ($cqdFilterUACategory | ConvertTo-Json)
}

#Function for creating Media Type Filter
function BuildMediaTypeFilter {
  param(
    [Parameter()] [array]$MediaType
  )

  # Create hash table representing CQD Media Type filter
  $cqdFilterMediaType = @{}

  $Caption = ""
  $Value = ""
  $MediaType | ForEach-Object { $Caption += "$($_) | " }
  $Caption | ForEach-Object {
    $Length = $Caption.Trim().Length
    $Caption = $Caption.Trim().Substring(0, $Length - 1)
    $Caption = $Caption.Trim()
  }

  $MediaType | ForEach-Object { $Value += "[$($_)]," }
  $Value | ForEach-Object {
    $Length = $Value.Trim().Length
    $Value = $Value.Trim().Substring(0, $Length - 1)
    $Value = $Value.Trim()
  }

  $cqdFilterMediaType.Add("DataModelName", "[AllStreams].[Media Type]")
  $cqdFilterMediaType.Add("Caption", $Caption)
  $cqdFilterMediaType.Add("Value", $Value)
  $cqdFilterMediaType.Add("Operand", 0)
  $cqdFilterMediaType.Add("UnionGroup", "")

  # Return Json object representing CQD Media Type filter
  return ($cqdFilterMediaType | ConvertTo-Json)
}

#Function for Server Pair Filter
function BuildIsServerPairFilter {
  param(
    [Parameter()] [array]$IsServerPair
  )

  # Create hash table representing CQD Is Server Pair filter
  $cqdFilterIsServerPair = @{}

  $Caption = ""
  $Value = ""
  $IsServerPair | ForEach-Object { $Caption += "$($_) | " }
  $Caption | ForEach-Object {
    $Length = $Caption.Trim().Length
    $Caption = $Caption.Trim().Substring(0, $Length - 1)
    $Caption = $Caption.Trim()
  }

  $IsServerPair | ForEach-Object { $Value += "[$($_)]," }
  $Value | ForEach-Object {
    $Length = $Value.Trim().Length
    $Value = $Value.Trim().Substring(0, $Length - 1)
    $Value = $Value.Trim()
  }

  $cqdFilterIsServerPair.Add("DataModelName", "[AllStreams].[Is Server Pair]")
  $cqdFilterIsServerPair.Add("Caption", $Caption)
  $cqdFilterIsServerPair.Add("Value", $Value)
  $cqdFilterIsServerPair.Add("Operand", 0)
  $cqdFilterIsServerPair.Add("UnionGroup", "")

  # Return Json object representing CQD Is Server Pair filter
  return ($cqdFilterIsServerPair | ConvertTo-Json)
}

#Function for Transport Filter (TCP,UDP)
function BuildTransportFilter {
  param(
    [Parameter()] [array]$Transport
  )

  # Create hash table representing CQD transport filter
  $cqdFilterTransport = @{}

  $Caption = ""
  $Value = ""
  $Transport | ForEach-Object { $Caption += "$($_) | " }
  $Caption | ForEach-Object {
    $Length = $Caption.Trim().Length
    $Caption = $Caption.Trim().Substring(0, $Length - 1)
    $Caption = $Caption.Trim()
  }

  $Transport | ForEach-Object { $Value += "[$($_)]," }
  $Value | ForEach-Object {
    $Length = $Value.Trim().Length
    $Value = $Value.Trim().Substring(0, $Length - 1)
    $Value = $Value.Trim()
  }

  $cqdFilterTransport.Add("DataModelName", "[AllStreams].[Transport]")
  $cqdFilterTransport.Add("Caption", $Caption)
  $cqdFilterTransport.Add("Value", $Value)
  $cqdFilterTransport.Add("Operand", 0)
  $cqdFilterTransport.Add("UnionGroup", "")

  # Return Json object representing CQD transport filter
  return ($cqdFilterTransport | ConvertTo-Json)
}

#Function for building all Filters
function FilterCreation {

  #Build MonthYear Array From Input

  foreach ($MonthYearI in $MonthYear) {
    $MonthYearParams += "[" + $MonthYearI + "],"

  }

  $Filters = New-Object system.Data.DataTable "Filters"
  $FilterName = New-Object system.Data.DataColumn FilterName, ([string])
  $FilterValue = New-Object system.Data.DataColumn FilterValue, ([string])
  $FilterCaption = New-Object system.Data.DataColumn FilterCaption, ([string])
  $FilterOperand = New-Object system.Data.DataColumn FilterOperand, ([string])
  $FilterUnionGroup = New-Object system.Data.DataColumn FilterUnionGroup, ([string])

  #Add the Columns
  $Filters.columns.Add($FilterName)
  $Filters.columns.Add($FilterValue)
  $Filters.columns.Add($FilterCaption)
  $Filters.columns.Add($FilterOperand)
  $Filters.columns.Add($FilterUnionGroup)


  if ($Weekdays -ne $null) {
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Day Of Week" 
    $row.FilterValue = "$DaysofWeekList" 
    $row.FilterCaption = "NA" 
    $row.FilterOperand = "0" 
    $row.FilterUnionGroup = "" 
    $Filters.Rows.Add($row)
  }


  if ($MonthYear -ne $null) {
    #Create a row
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Month Year" 
    $row.FilterValue = "$MonthYearParams" 
    $row.FilterCaption = "NA" 
    $row.FilterOperand = "0" 
    $row.FilterUnionGroup = "" 
    $Filters.Rows.Add($row)
  }



  if ($StartDate -ne $null -and $EndDate -ne $null) {

    $EndDateV = ProcessDateRange
    #Create a row
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Date"
    $row.FilterValue = "$EndDateV" 
    $row.FilterCaption = "NA" 
    $row.FilterOperand = "0" 
    $row.FilterUnionGroup = "" 
    $Filters.Rows.Add($row)  

  }

  if ($Week -ne $null) {
    $WeekV = (BuildWeekFilter $Week) | ConvertFrom-Json
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Week"
    $row.FilterValue = $WeekV.Value
    $row.FilterCaption = "NA" 
    $row.FilterOperand = $WeekV.Operand 
    $row.FilterUnionGroup = $WeekV.UnionGroup 
    $Filters.Rows.Add($row)  
  }

  if ($UACategory -ne $null) {
    $UACategoryV = (BuildUACategoryFilter $UACategory) | ConvertFrom-Json
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Second User Agent Category"
    $row.FilterValue = $UACategoryV.Value
    $row.FilterCaption = "NA" 
    $row.FilterOperand = $UACategoryV.Operand 
    $row.FilterUnionGroup = $UACategoryV.UnionGroup 
    $Filters.Rows.Add($row)  
  }

  if ($MediaType -ne $null) {
    $MediaTypeV = (BuildMediaTypeFilter $MediaType) | ConvertFrom-Json
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Media Type"
    $row.FilterValue = $MediaTypeV.Value
    $row.FilterCaption = "NA" 
    $row.FilterOperand = $MediaTypeV.Operand 
    $row.FilterUnionGroup = $MediaTypeV.UnionGroup 
    $Filters.Rows.Add($row)  
  }

  if ($IsServerPair -ne $null) {
    $IsServerPairV = (BuildIsServerPairFilter $IsServerPair) | ConvertFrom-Json
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Is Server Pair"
    $row.FilterValue = $IsServerPairV.Value
    $row.FilterCaption = "NA" 
    $row.FilterOperand = $IsServerPairV.Operand 
    $row.FilterUnionGroup = $IsServerPairV.UnionGroup 
    $Filters.Rows.Add($row)  
  }

  if ($Transport -ne $null) {
    $TransportV = (BuildTransportFilter $Transport) | ConvertFrom-Json
    $row = $Filters.NewRow()
    $row.FilterName = "AllStreams.Transport"
    $row.FilterValue = $TransportV.Value
    $row.FilterCaption = "NA" 
    $row.FilterOperand = $TransportV.Operand 
    $row.FilterUnionGroup = $TransportV.UnionGroup 
    $Filters.Rows.Add($row)  
  }

  if ($null -ne $CustomFilter) {
    foreach ($F in $CustomFilter) {
      $row = $Filters.NewRow()
      $row.FilterName = $F.FName
      $row.FilterValue = $F.FValue
      $row.FilterCaption = ""
      $row.FilterOperand = $F.Op
      $row.FilterUnionGroup = $F.FUnionGroup
      $Filters.Rows.Add($row)

    }
  }

  return $Filters

}


function Get-CQDData {
  [CmdletBinding()]
  param(




    [Parameter(Mandatory = $false, Position = 3)]
    [array]$Transport = $null,

    [Parameter(Mandatory = $false, Position = 4)]
    [string]$OutPutFilePath = $null,

    [Parameter(Mandatory = $false, Position = 5)]
    [nullable[datetime]]$StartDate = $null,

    [Parameter(Mandatory = $false, Position = 6)]
    [nullable[datetime]]$EndDate = $null,

    [Parameter(Mandatory = $false, Position = 7)]
    [array]$MonthYear = $null,

    [Parameter(Mandatory = $false, Position = 8)]
    [array]$Weekdays = $null,

    [Parameter(Mandatory = $True, Position = 9)]
    [ValidateSet("CSV", "DataTable")]
    [string]$OutPutType,

    [Parameter(Mandatory = $false, Position = 10)]
    [array]$Week = $null,

    [Parameter(Mandatory = $false, Position = 11)]
    [array]$UACategory = $null,

    [Parameter(Mandatory = $false, Position = 12)]
    [array]$MediaType = $null,

    [Parameter(Mandatory = $false, Position = 13)]
    [ValidateSet("Client : Client", "Client : Server", "Server : Server")]
    [array]$IsServerPair = $null,

    [Parameter(Mandatory = $false, Position = 14)]
    [bool]$ShowQuery = $false,
    
    [Parameter(Mandatory = $false, Position = 15)]
    [switch] $OverWriteOutput,
  
    [Parameter(Mandatory = $false, Position = 16)]
    [pscustomobject] $CustomFilter,
  
    [Parameter(Mandatory = $false, Position = 17)]
    [switch] $LargeQuery,

    [Parameter(Mandatory = $false, Position = 18)]
    [ValidateSet("V2", "V3")]
    [string]$CQDVer = "V3"

  

  )


  dynamicparam {


    # Set the dynamic parameters' name for Dimensions and Measures
    $DimensionParameter = 'Dimensions'
    $MeasuresParameter = 'Measures'


    # Create the dictionary
    $RuntimeParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

    # Create the collection of attributes
    $DimensionAttributeCollection = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
    $AttributeCollectionMeasures = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

    # Create and set the parameters' attributes
    $DimensionParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $DimensionParameterAttribute.Mandatory = $true
    $DimensionParameterAttribute.Position = 1

    $MeasuresParameterAttribute = New-Object System.Management.Automation.ParameterAttribute
    $MeasuresParameterAttribute.Mandatory = $true
    $MeasuresParameterAttribute.Position = 2

    # Add the attributes to the attributes collection
    $DimensionAttributeCollection.Add($DimensionParameterAttribute)
    $AttributeCollectionMeasures.Add($MeasuresParameterAttribute)

    # Generate and set the ValidateSet
    $DimensionarrSet = GetParams "Dimensions"
    $MeasuresarrSet = GetParams "Measures"
    $DimensionsValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute ($DimensionarrSet)
    $MeasuresValidateSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute ($MeasuresarrSet)

    # Add the ValidateSet to the attributes collection
    $DimensionAttributeCollection.Add($DimensionsValidateSetAttribute)
    $AttributeCollectionMeasures.Add($MeasuresValidateSetAttribute)

    # Create and return the dynamic parameter
    $DimensionsRuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter ($DimensionParameter, [array], $DimensionAttributeCollection)
    $MeasuresRuntimeParameter = New-Object System.Management.Automation.RuntimeDefinedParameter ($MeasuresParameter, [array], $AttributeCollectionMeasures)

    $RuntimeParamDictionary.Add($DimensionParameter, $DimensionsRuntimeParameter)
    $RuntimeParamDictionary.Add($MeasuresParameter, $MeasuresRuntimeParameter)
    return $RuntimeParamDictionary

  }

  begin {
    # Bind the parameter to a friendly variable
    $Dims = $PsBoundParameters[$DimensionParameter]
    $Measures = $PsBoundParameters[$MeasuresParameter]



  }

  process {

    try {
      Write-Host "Working...."

      #Check for Null CSV Path if CSV Chosen output
      if ($OutPutType -eq "CSV" -and $OutPutFilePath -eq "") {
        while ($OutPutFilePath -eq "" -or $OutPutFilePath -eq $null) {
          Write-Host "You must specify an output path when using CSV output type"
          Write-Host "Enter CSV Output Path:" -NoNewline
          $OutputFilePath = Read-Host
        }
        if ($OutputFilePath -eq $null) { Exit-PSSession }
      }

      $DimFixed = @()
      $DimSimple = @()
      $MeasureFixed = @()
      $MeasureSimple = @()
      ###Fix Dimension Brackets
      foreach ($DimShort in $Dims) {
        $Dim1 = $DimShort.Split(".")
        $DimSimple += $Dim1[1].ToString()
        $Dim1[0] = "[" + $Dim1[0] + "]"
        $Dim1[1] = "[" + $Dim1[1] + "]"
        $DimFixed += $Dim1[0] + "." + $Dim1[1]
      }

      foreach ($MeasureShort in $Measures) {
        $Measure1 = $MeasureShort.Split(".")
        $MeasureSimple += $Measure1[1].ToString()
        $Measure1[0] = "[" + $Measure1[0] + "]"
        $Measure1[1] = "[" + $Measure1[1] + "]"
        $MeasureFixed += $Measure1[0] + "." + $Measure1[1]
      }

      $Dims = $DimFixed
      $Measures = $MeasureFixed




      if ($Weekdays -ne $null) {
        $DaysofWeekList = GetDaysofWeek
      }
      else {
        $Weekdays = $null
      }







      $Filters = FilterCreation


      ##Dimension and Measure Arrays##
      $DimensionsArray = $Dims 
      $MeasurementsArray = $Measures 


      ##Create Results Table##
      $DataResults = New-Object system.Data.DataTable "DataResults"
      foreach ($DimensionVar in $DimSimple) {
        $Column = New-Object system.Data.DataColumn $DimensionVar, ([string])
        $DataResults.columns.Add($Column)
      }

      foreach ($MeasureVar in $MeasureSimple) {
        $Column = New-Object system.Data.DataColumn $MeasureVar, ([string])
        $DataResults.columns.Add($Column)
      }

      $FilterRowArray = @()
      $DimensionRowArray = @()
      $MeasureRowArray = @()
      $AllArray = $DimSimple + $MeasureSimple


      ##Build Query Structure##

      #Start/End Query
      $StartQuery = "{"
      $EndQuery = "}"

      #Filter Sections
      $StartFilters = @'
"Filters":[
'@

      #Dimension Sections
      $StartDimensions = @'
"Dimensions":[
'@

      #Measure Sections
      $StartMeasures = @'
"Measurements":[
'@


      ###############Loop Arrays of Each Type

      foreach ($Filter in $Filters) {
        $FLN = $Filter.FilterName
        $FCN = $Filter.FilterCaption
        $FVE = $Filter.FilterValue
        $FOP = $Filter.FilterOperand
        $UNGP = $Filter.FilterUnionGroup
        $FLNSplit = $FLN.Split(".")
        $FLNName = "[" + $FLNSplit[0] + "].[" + $FLNSplit[1] + "]" 
        $FilterRowArray += @"
{"DataModelName":"$FLNName","Caption":"$FCN","Value":"$FVE","Operand":$FOP,"UnionGroup":"$UNGP"},
"@
      }
      $DimCount = $DimensionsArray.Count - 1
      foreach ($DimensionLoop in $DimensionsArray) {

        $DimensionRowArray += @"
{"DataModelName":"$DimensionLoop"},
"@

      }
      $MeaCount = $MeasurementsArray.Count - 1
      foreach ($MeasureLoop in $MeasurementsArray) {

        $MeasureRowArray += @"
{"DataModelName":"$MeasureLoop"},
"@

      }
      ########Build Dynamic Query
      if ($LargeQuery) {

        $Query = @"
  {
   
  $StartFilters
  $FilterRowArray
   
  ]
  ,
  $StartDimensions
  $DimensionRowArray
  ]
  ,
  $StartMeasures
  $MeasureRowArray
  ]
  ,
  LimitResultRowsCount:200000
  }
"@

      }
      else {
  
        $Query = @"
  {
   
  $StartFilters
  $FilterRowArray
   
  ]
  ,
  $StartDimensions
  $DimensionRowArray
  ]
  ,
  $StartMeasures
  $MeasureRowArray
  ],
  LimitResultRowsCount:200000
  }
"@

      }


      #Check to see if ShowQuery is true. Used to show JSON query for debugging queries.
      if ($ShowQuery -eq $true) {
        Write-Host "JSON Query:"
        Write-Host $Query
      }

      CheckToken
      $verb = "POST"
      $content = $Query
      $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
      $IRM = Invoke-RestMethod -Uri ('{0}RunQuery' -f $DataServiceBaseUrl) -WebSession $WebSession -Method Post -Body $Query -ContentType 'application/json' -UserAgent "CQDPowerShell V2.0" -Headers $headers


      $IRM2 = ConvertTo-Json -InputObject $IRM
      $JsonGarb = ConvertFrom-Json -InputObject $IRM2

      $QueryExecutionTime = $JsonGarb.ExecutionTime
      $ErrorType = $JsonGarb.ErrorType
      $ResultList = $JsonGarb.DataResult

      if ($ErrorType -ne 0) {
        Write-Host "Error Querying CQD with Error " $ErrorType
        if ($ErrorType -eq 6) { Write-Host "Invalid Query. Check the query and try again." }
        if ($ErrorType -eq 5) { Write-Host "Query scope too large. Reduce Dimensions, Measures and Timespan" }
        if ($ErrorType -eq 3) { Write-Host "Cube currently unavailable. Try again later." }
      }



      foreach ($ResultItem in $ResultList) {
        if (!$ResultItem) {
          #if(1 -eq 2)
          Write-Host "Warning: Result is Null:" $ResultItem

        }
        else {
          $ItemCount = $ResultItem.Count
          $FieldCount = $DimensionsArray.Count + $MeasurementsArray.Count
          #Create a row
          $Resultrow = $DataResults.NewRow()


          $i = 0

          do {

            $Resultrow.($AllArray[$i]) = $ResultItem.Item($i)
            $i++
          }
          while ($i -lt $AllArray.Count)

          $DataResults.Rows.Add($Resultrow)

        }

      }

      if ($OutPutType -eq "CSV") {
        if ($OverWriteOutput -eq $true) {
          $DataResults | Export-Csv -Path $OutPutFilePath -notypeinformation 
        }
        else {
          $DataResults | Export-Csv -Path $OutPutFilePath -notypeinformation -Append
        }
      }
      elseif ($OutPutType -eq "DataTable") {
        return $DataResults
      }

      Write-Host "Execution Complete. Query took " $QueryExecutionTime
    }
    catch [System.Net.WebException] {
      "Unable to complete query. Please reduce query scope or try again later."
    }
    catch [System.Management.Automation.ParameterBindingException] { "Error Binding" }

    catch { "Error: $Error" }

  }

}

Export-ModuleMember -Function Get-CQDData




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
AllStreams.Date

AllStreams.Duration 5 seconds or less
AllStreams.Duration 60 seconds or more
AllStreams.Duration (Minutes)
AllStreams.Duration (Seconds)



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


Measures.Avg Video Packet Loss Rate
Measures.Avg Packet Loss Rate
Measures.Avg Packet Loss Rate Max

Measures.Avg Jitter
Measures.Avg Jitter Max



Measures.Avg Round Trip
Measures.Avg Round Trip Max
Measures.Avg Packet Utilization
Measures.Avg Network Jitter
Measures.Avg Network Jitter Max
Measures.Avg Network Jitter Min
Measures.Avg Jitter Buffer Size
Measures.Avg Jitter Buffer Size Max
Measures.Avg Jitter Buffer Size Min
Measures.Avg Relative OneWay
Measures.Avg Relative OneWay Max
Measures.Avg Relative OneWay Gap Occurrences
Measures.Avg Relative OneWay Gap Density
Measures.Avg Relative OneWay Gap Duration

Measures.Avg Call Duration
Measures.Total Audio Stream Duration (Minutes)

"
$ListOfMeasures = $ListOfMeasuresRaw.Split([Environment]::NewLine, [StringSplitOptions]::RemoveEmptyEntries)




function Get-CQDConferenceReport {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$ConferenceID = $null
  )

  $CustomFilter = @()
  $F1 = New-Object pscustomobject
  $F1 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.Conference Id"
  $F1 | Add-Member -Type NoteProperty -Name FValue -Value $ConferenceID
  $F1 | Add-Member -Type NoteProperty -Name Op -Value 0
  $CustomFilter += $F1


  $reportfilename = "CQD_Report_Conference_" + $ConferenceID + "_RUNDATE_" + (Get-Date -Format 'MM_dd_yyyy__HH_mm_ss') + ".csv"
  $cqdDataInfo = Get-CQDData -Dimensions $ListOfDimensions -Measures $ListOfMeasures -ShowQuery $True -CustomFilter $CustomFilter -OutputType datatable 
  $cqdDataInfo | Out-GridView
  Write-Output "Writing report to the file " $reportfilename ""
  $cqdDataInfo | Export-Csv -Path $reportfilename -NoTypeInformation

}
Export-ModuleMember -Function Get-CQDConferenceReport


function Get-CQDUserReport {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true, Position = 1)]
    [string]$UPN = $null,
    [Parameter(Mandatory = $false, Position = 1)]
    [int]$days = 28
  )

  $FUnionGroup = "user"
  $CustomFilter = @()

  $F1 = New-Object pscustomobject
  $F1 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.First UPN"
  $F1 | Add-Member -Type NoteProperty -Name FValue -Value $UPN
  $F1 | Add-Member -Type NoteProperty -Name Op -Value 0
  $F1 | Add-Member -Type NoteProperty -Name FUnionGroup -Value $FUnionGroup
  $CustomFilter += $F1


  $F2 = New-Object pscustomobject
  $F2 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.Second UPN"
  $F2 | Add-Member -Type NoteProperty -Name FValue -Value $UPN
  $F2 | Add-Member -Type NoteProperty -Name Op -Value 0
  $F2 | Add-Member -Type NoteProperty -Name FUnionGroup -Value $FUnionGroup
  $CustomFilter += $F2


  $Offsetdays = 0
  $StartDate = (Get-Date).AddDays(-$Offsetdays - $days)
  $EndDate = (Get-Date).AddDays(-$Offsetdays)
  $StartDateString = Get-Date $StartDate -Format 'MM/dd/yyyy'
  $EndDateString = Get-Date $EndDate -Format 'MM/dd/yyyy'


  $reportfilename = "CQD_Report_User_" + $UPN + "_" + "EndDate_" + (Get-Date $EndDate -Format 'MM_dd_yyyy') + "_StartDate_" + (Get-Date $StartDate -Format 'MM_dd_yyyy') + "_RUNDATE_" + (Get-Date -Format 'MM_dd_yyyy__HH_mm_ss') + ".csv"
  $cqdDataInfo = Get-CQDData -StartDate $StartDateString -EndDate $EndDateString -Dimensions $ListOfDimensions -Measures $ListOfMeasures -ShowQuery $True -CustomFilter $CustomFilter -OutputType datatable 
  $cqdDataInfo | Out-GridView
  $cqdDataInfo | Export-Csv -Path $reportfilename -NoTypeInformation

}
Export-ModuleMember -Function Get-CQDUserReport


function Get-CQDSubnetsReport {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [array]$Subnets,
    [Parameter(Mandatory = $false)]
    [int]$days = 28
  )
  

  $FUnionGroup = "subnets"
  $CustomFilter = @()
  # Adding filters
  for ($i = 0; $i -le ($Subnets.length - 1); $i += 1) {
    $Subnets[$i]
    $F1 = New-Object pscustomobject
    $F1 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.First Subnet"
    $F1 | Add-Member -Type NoteProperty -Name FValue -Value $Subnets[$i]
    $F1 | Add-Member -Type NoteProperty -Name Op -Value 0
    $F1 | Add-Member -Type NoteProperty -Name FUnionGroup -Value $FUnionGroup
    $CustomFilter += $F1
    $F2 = New-Object pscustomobject
    $F2 | Add-Member -Type NoteProperty -Name FName -Value "AllStreams.Second Subnet"
    $F2 | Add-Member -Type NoteProperty -Name FValue -Value $Subnets[$i]
    $F2 | Add-Member -Type NoteProperty -Name Op -Value 0
    $F2 | Add-Member -Type NoteProperty -Name FUnionGroup -Value $FUnionGroup
    $CustomFilter += $F2
  }
  
  $Offsetdays = 0
  $StartDate = (Get-Date).AddDays(-$Offsetdays - $days)
  $EndDate = (Get-Date).AddDays(-$Offsetdays)
  $StartDateString = Get-Date $StartDate -Format 'MM/dd/yyyy'
  $EndDateString = Get-Date $EndDate -Format 'MM/dd/yyyy'

  $reportfilename = "CQD_Report_Subnets" + "_" + "EndDate_" + (Get-Date $EndDate -Format 'MM_dd_yyyy') + "_StartDate_" + (Get-Date $StartDate -Format 'MM_dd_yyyy') + "_RUNDATE_" + (Get-Date -Format 'MM_dd_yyyy__HH_mm_ss') + ".csv"
  $cqdDataInfo = Get-CQDData -StartDate $StartDateString -EndDate $EndDateString -Dimensions $ListOfDimensions -Measures $ListOfMeasures -ShowQuery $True -CustomFilter $CustomFilter -OutputType datatable 
  $cqdDataInfo | Out-GridView
  $cqdDataInfo | Export-Csv -Path $reportfilename -NoTypeInformation
}
Export-ModuleMember -Function Get-CQDSubnetsReport