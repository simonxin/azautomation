#
#usage : GetImageState -registry $registry -image_name $image_name -tag $tag -tagdigest $tagdigest
#usage : ./trackingonimageversion.ps1 -workspacename "somsdemoworkshop" -resourcegroupname "omsdemo" -subscriptionId "0f2daa80-6b16-44ee-8016-4ad888e059ac"
# optional: Use a search base filter which is lile resource group name or cluster name

param (
[Parameter(Mandatory=$false)][string]$cloud="mooncake",
[Parameter(Mandatory=$false)][string]$logType="containerimagestate",
[Parameter(Mandatory=$true)][string]$workspacename,
[Parameter(Mandatory=$true)][string]$resourcegroupname,
[Parameter(Mandatory=$false)][string]$subscriptionId="",
[Parameter(Mandatory=$false)][string]$searchbase=""
)


Import-Module Az.Accounts

function Invoke-LogAnalyticsQuery {
    param(
        [string]
        [Parameter(Mandatory=$true)]
        $WorkspaceName,
    
        [guid]
        [Parameter(Mandatory=$true)]
        $SubscriptionId,
    
        [string]
        [Parameter(Mandatory=$true)]
        $ResourceGroup,
    
        [string]
        $Query,
    
        [string]
        [Parameter(Mandatory=$true)]    
        [ValidateSet("query", "metadata","sharedKeys","workspace")]
        $querytype,
    
        [string]
        [Parameter(Mandatory=$false)] 
        $Timespan='P1D',
    
        [switch]
        $IncludeTabularView,
    
        [switch]
        $IncludeStatistics,
    
        [switch]
        $IncludeRender,
    
        [int]
        $ServerTimeout,
    
        [string]
        [ValidateSet("", "int", "aimon","mooncake")]
        $Environment = "",

        [string]$queryapiVersion="2020-03-01-preview",

        [string]$metadataapiVersion = "2017-10-01"
    
        )


    
        $ErrorActionPreference = "stop"
    
        $accessToken = GetAADAccessToken
    
        $armhost = GetArmHost $environment
    
        if ($null -eq $ServerTimeout) {
            $ServerTimeout = 300
        }
    
        try {
            
            if ($querytype -eq "query") {
                $queryParams = @("api-version=$queryapiversion")
                $queryParamString = [string]::Join("&", $queryParams)        
                $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParamString $querytype
                # map to mooncake logA rest API endpoint
                $accessToken = (Get-AzAccessToken -ResourceUrl "https://api.loganalytics.azure.cn/").token
                $body = @{
                    "query" = $query;
                    "timespan" = $Timespan
                } | ConvertTo-Json
                
                $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
            
                $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Body $body -ContentType "application/json" -Headers $headers -Method Post -ErrorAction:Ignore
                
            } elseif ($querytype -eq "metadata") {
                $queryParams=@("api-version=$metadataapiVersion")
                $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParams $querytype
                $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
                $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers $headers -Method Post -ErrorAction:Ignore
                    
            } elseif ($querytype -eq "sharedKeys") {
        
                $queryParams=@("api-version=$queryapiVersion")
                $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParams $querytype
                $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
                $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers $headers -Method Post -ErrorAction:Ignore
            } elseif ($querytype -eq "workspace") {
                $queryParams=@("api-version=2020-08-01")
                $uri = BuildUri $armHost $subscriptionId $resourceGroup $workspaceName $queryParams $querytype
                $headers = GetHeaders $accessToken -IncludeStatistics:$IncludeStatistics -IncludeRender:$IncludeRender -ServerTimeout $ServerTimeout
                $response = Invoke-WebRequest -UseBasicParsing -Uri $uri -Headers $headers -Method Get -ErrorAction:Ignore
             }
    
            if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
                $statusCode = $response.StatusCode
                $reasonPhrase = $response.StatusDescription
                $message = $response.Content
                throw "Failed to execute query.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
            } 
        
        
            $data = $response.Content | ConvertFrom-Json
        
    
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name Response -Value $response
        
            # In this case, we only need the response member set and we can bail out
            if ($response.StatusCode -eq 204) {
                $result
                return
            }
            $objectView = CreateObjectView  $data -querytype $querytype
    
            $result | Add-Member -MemberType NoteProperty -Name Results -Value $objectView
        
            if ($IncludeTabularView) {
                $result | Add-Member -MemberType NoteProperty -Name Tables -Value $data.tables
            }
        
            if ($IncludeStatistics) {
                $result | Add-Member -MemberType NoteProperty -Name Statistics -Value $data.statistics
            }
        
            if ($IncludeRender) {
                $result | Add-Member -MemberType NoteProperty -Name Render -Value $data.render
            }        
    
        }
        catch {
            # return null if invoke query is failed
            $result = ""
        }
       
        $result
    }

function GetArmHost {
        param(
            [string]
            $environment
            )
        
            switch ($environment) {
                "" {
                    $armHost = "management.azure.com"
                }
                "mooncake" {
                    $armHost = "management.chinacloudapi.cn"
                }
                "int" {
                    $armHost = "api-dogfood.resources.windows-int.net"
                }
            }
        
            $armHost
        }
    
    
function CreateObjectView {
    param(
        $data,
        [string]
        [ValidateSet("query", "metadata","sharedKeys","workspace")]
        $querytype    
        )
    
        if($querytype -eq "query") {
        # Find the number of entries we'll need in this array
            $count = 0
            foreach ($table in $data.Tables) {
                $count += $table.Rows.Count
            }
    
            $objectView = New-Object object[] $count
            $i = 0;
            foreach ($table in $data.Tables) {
                foreach ($row in $table.Rows) {
                # Create a dictionary of properties
                $properties = @{}
                for ($columnNum=0; $columnNum -lt $table.Columns.Count; $columnNum++) {
                    $properties[$table.Columns[$columnNum].name] = $row[$columnNum]
                }
                # Then create a PSObject from it. This seems to be *much* faster than using Add-Member
                $objectView[$i] = (New-Object PSObject -Property $properties)
                $null = $i++
                }
            }
    
           
        } elseif ($querytype -eq "metadata") {
            # for metadaa, return the table name and column names only
            $count = $data.Tables.count
            $objectView = New-Object object[] $count
            $i = 0;
            foreach ($table in $data.tables) {
                $properties = @{
                    datatype = $table.name
                    columns = $table.columns
                }
                $objectView[$i] = (New-Object PSObject -Property $properties)
                $null = $i++
            }
        } else {
    
            $objectView = $data
        }
    
        $objectView
    }

function BuildUri {
        param(
            [string]
            $armHost,
            
            [string]
            $subscriptionId,
        
            [string]
            $resourceGroup,
        
            [string]
            $workspaceName,
        
            [string]
            $queryParamString,
        
            [string]
            [ValidateSet("query", "metadata","sharedKeys","workspace")]
            $querytype
            )
        
            if ($querytype -eq 'query') { 
            
              "https://api.loganalytics.azure.cn/v1/workspaces/$workspaceName/query"
        
            } elseif ($querytype -eq 'metadata') {
            "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
                "microsoft.operationalinsights/workspaces/$workspaceName/metadata?$queryParamString"
        
            } elseif ($querytype -eq 'sharedKeys') {
                "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
                "microsoft.operationalinsights/workspaces/$workspaceName/sharedKeys?$queryParamString"
        
            } elseif($querytype -eq 'workspace') {
                "https://$armHost/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/" + `
                "microsoft.operationalinsights/workspaces/$workspaceName"+"?"+$queryParamString
            }
        }
    
    
   
function GetHeaders {
        param(
            [string]
            $AccessToken,
        
            [switch]
            $IncludeStatistics,
        
            [string]
            $headerapp='LogAnalyticsQuery.ps1',
    
            [string]
            $IncludeRender,
        
            [int]
            $ServerTimeout
            )
        
            $preferString = "response-v1=true"
        
            if ($IncludeStatistics) {
                $preferString += ",include-statistics=true"
            }
        
            if ($IncludeRender) {
                $preferString += ",include-render=true"
            }
        
            if ($ServerTimeout -ne $null) {
                $preferString += ",wait=$ServerTimeout"
            }
        
            if ($null -eq $headerapp) {
                $headerapp = 'LogAnalyticsQuery.ps1'
            }
        
            $headers = @{
                "Authorization" = "Bearer $accessToken";
                "prefer" = $preferString;
                "x-ms-app" = $headerapp;
                "x-ms-client-request-id" = [Guid]::NewGuid().ToString();
            }
        
            $headers
        }


Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
        {
            $xHeaders = "x-ms-date:" + $date
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        
            $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
            $keyBytes = [Convert]::FromBase64String($sharedKey)
        
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.Key = $keyBytes
            $calculatedHash = $sha256.ComputeHash($bytesToHash)
            $encodedHash = [Convert]::ToBase64String($calculatedHash)
            $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
            return $authorization
        }
        
        
        # Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
        {
            $method = "POST"
            $contentType = "application/json"
            $resource = "/api/logs"
            $rfc1123date = [DateTime]::UtcNow.ToString("r")
            $TimeStampField = "" # use default TimeGenerated as time stamp
            $contentLength = $body.Length
            $signature = Build-Signature `
                -customerId $customerId `
                -sharedKey $sharedKey `
                -date $rfc1123date `
                -contentLength $contentLength `
                -method $method `
                -contentType $contentType `
                -resource $resource
            $uri = "https://" + $customerId + ".ods.opinsights.azure.cn" + $resource + "?api-version=2016-04-01"
        
            $headers = @{
                "Authorization" = $signature;
                "Log-Type" = $logType;
                "x-ms-date" = $rfc1123date;
                "time-generated-field" = $TimeStampField;
            }
        
            $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
            return $response.StatusCode
        
        }
        
    

function GetAADAccessToken {
    $azureCmdlet = get-command -Name Get-AzureRMContext -ErrorAction SilentlyContinue
    if ($azureCmdlet -eq $null)
    {
        $null = Import-Module Az.Accounts -ErrorAction Stop;
    }
    $AzureContext = & "Get-AzContext" -ErrorAction Stop;
    $authenticationFactory = New-Object -TypeName Microsoft.Azure.Commands.Common.Authentication.Factories.AuthenticationFactory
    if ((Get-Variable -Name PSEdition -ErrorAction Ignore) -and ('Core' -eq $PSEdition)) {
        [Action[string]]$stringAction = {param($s)}
        $serviceCredentials = $authenticationFactory.GetServiceClientCredentials($AzureContext, $stringAction)
    } else {
        $serviceCredentials = $authenticationFactory.GetServiceClientCredentials($AzureContext)
    }

    # We can't get a token directly from the service credentials. Instead, we need to make a dummy message which we will ask
    # the serviceCredentials to add an auth token to, then we can take the token from this message.
    $message = New-Object System.Net.Http.HttpRequestMessage -ArgumentList @([System.Net.Http.HttpMethod]::Get, "http://foobar/")
    $cancellationToken = New-Object System.Threading.CancellationToken
    $null = $serviceCredentials.ProcessHttpRequestAsync($message, $cancellationToken).GetAwaiter().GetResult()
    $accessToken = $message.Headers.GetValues("Authorization").Split(" ")[1] # This comes out in the form "Bearer <token>"
    $accessToken
}

function GetRegistryToken {
    param(
        [string][Parameter(Mandatory=$true)] $IMAGE_NAME,
        [string][Parameter(Mandatory=$true)] $REGISTRY
        )

    if ($REGISTRY -match '.azurecr.') {
        $REGISTRYBASE = "azurecr"
    } elseif (($REGISTRY -match 'docker.') -or ($REGISTRY -match 'dockerhub.')) {
        $REGISTRYBASE = "docker.io"
 #   } elseif ($REGISTRY -match 'gcr.io') {
 #       $REGISTRYBASE = "gcr.io"
    } else {
        $REGISTRYBASE = $REGISTRY
    }

    switch ($REGISTRYBASE) {
        # update for public docker registry and azure ACR (Azure China Cloud)

        "docker.io" {
            $REGISTRY_AUTH="https://auth.docker.io"
            $REGISTRY_SERVICE="registry.docker.io"

            if ($IMAGE_name -match "/") {
                $IMAGE=$IMAGE_name
            } else {
                $IMAGE="library/$IMAGE_name"
            }

            $URL="$REGISTRY_AUTH/token?service=$REGISTRY_SERVICE&scope=repository:$IMAGE`:pull"

            $response = invoke-webrequest -uri $URL  -UseBasicParsing
        }
        "ghcr.io" {
            $REGISTRY_AUTH="https://ghcr.io"
            $REGISTRY_SERVICE="ghcr.io"
            $URL="$REGISTRY_AUTH/token?scope=repository:$IMAGE_NAME`:pull"
            $response = invoke-webrequest -uri $URL  -UseBasicParsing
        }
        "gcr.io" {
            $REGISTRY_AUTH="https://$REGISTRY/v2"
            $REGISTRY_SERVICE=$REGISTRY
            $URL="$REGISTRY_AUTH/token?scope=repository:$IMAGE_name`:pull"
            $response = invoke-webrequest -uri $URL  -UseBasicParsing
        }
        "azurecr" {
            $REGISTRY_AUTH="https://$registry/oauth2/exchange"
            
            # used acr refresh token from an AAD token: https://github.com/Azure/acr/blob/main/docs/AAD-OAuth.md
        
            $aadaccesstoken = GetAADAccessToken

            $tenant = $(Get-AzContext).Tenant
   
            $Headers = @{
                "Content-Type" = "application/x-www-form-urlencoded"
            }

            $body = "grant_type=access_token&service=$registry&tenant=$($tenant.id)$&access_token=$aadaccesstoken"

            $response = invoke-webrequest  -UseBasicParsing -uri $REGISTRY_AUTH -Body $body -Headers  $Headers -Method Post -ErrorAction:Ignore
            $acrrefreshtoken = $response.Content | ConvertFrom-Json 

            $ACRtoken_auth = "https://$registry/oauth2/token"
            $acrtoken_body = "grant_type=refresh_token&service=$registry&scope=repository:$IMAGE_NAME`:pull&refresh_token=$($acrrefreshtoken.refresh_token)" 

            $response = invoke-webrequest -UseBasicParsing -uri $ACRtoken_auth -Body $acrtoken_body -Headers  $Headers -Method Post -ErrorAction:Ignore

        }
        default {
            return $NULL               
        }

               
    }

   
    if ($NULL -ne $response -and $response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
        $statusCode = $response.StatusCode
        $reasonPhrase = $response.StatusDescription
        $message = $response.Content
        $accesstoken  = $NULL
        throw "Failed to get access token for $registry.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
        return $NULL
    } else {
        $accesstoken = $response.Content | ConvertFrom-Json
        $tokenproperty = $accesstoken | get-member -type NoteProperty | where {$_.name -match "token"} | select -first 1
        if ($tokenproperty) {
            $token = $accesstoken.$($tokenproperty.name)
        } else {
            $token = $NULL
        }
        return $token
   
    }
    

}


function GetNextImagetags {
    param(
        [string][Parameter(Mandatory=$true)] $IMAGE_NAME,
        [string][Parameter(Mandatory=$true)] $REGISTRY,
        [string][Parameter(Mandatory=$true)] $tag,
        [string][Parameter(Mandatory=$false)] $accesstoken,
        [int][Parameter(Mandatory=$false)] $returncount=100
        )

        if ($REGISTRY -match '.azurecr.') {
            $REGISTRYBASE = "azurecr"
        } elseif (($REGISTRY -match 'docker.') -or ($REGISTRY -match 'dockerhub.')) {
            $REGISTRYBASE = "docker.io"
 #       } elseif ($REGISTRY -match 'gcr.io') {
 #           $REGISTRYBASE = "gcr.io"
        } else {
            $REGISTRYBASE = $REGISTRY
        }
    
    
        switch ($REGISTRYBASE) {
            # update for public docker registry and azure ACR (Azure China Cloud)
    
            "docker.io" {
                $REGISTRY_URL="https://index.docker.io/v2"
                if ($IMAGE_name -match "/") {
                    $IMAGE=$IMAGE_name
                } else {
                    $IMAGE="library/$IMAGE_name"
                }
                $URL="$REGISTRY_URL/$IMAGE/tags/list?n=$returncount&last=$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
            }
            "ghcr.io" {
                $REGISTRY_URL="https://ghcr.io/v2"
                $URL="$REGISTRY_URL/$IMAGE_NAME/tags/list?n=$returncount&last=$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
            }
            "gcr.io" {
                $REGISTRY_URL="https://$REGISTRY/v2"
                $URL="$REGISTRY_URL/$IMAGE_name/tags/list?n=$returncount&last=$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
            }
            "azurecr" {
                $REGISTRY_URL="https://$REGISTRY/v2"
                $URL="$REGISTRY_URL/$IMAGE_NAME/tags/list?n=$returncount&last=$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
    
              }
            default {
                $REGISTRY_URL="https://$REGISTRY/v2"
                $URL="$REGISTRY_URL/$IMAGE_NAME/tags/list?n=$returncount&last=$tag"
                if ($accesstoken) {
                    $headers = @{
                        "Authorization" = "Bearer $accesstoken"
                    }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
                } else {
                    $response = invoke-webrequest -UseBasicParsing -uri $URL
                } 
                       
            }
    
                   
        }


        if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
            $statusCode = $response.StatusCode
            $reasonPhrase = $response.StatusDescription
            $message = $response.Content
            $imagetags  = $NULL
            throw "Failed to next image tags. `nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
        } else {
            $imagetags = $response.Content | ConvertFrom-Json 
        }

        return $imagetags

    }

    
function GetImageManifests {
    param(
        [string][Parameter(Mandatory=$true)] $IMAGE_NAME,
        [string][Parameter(Mandatory=$true)] $REGISTRY,
        [string][Parameter(Mandatory=$true)] $tag,
        [string][Parameter(Mandatory=$false)] $accesstoken
        )

        if ($REGISTRY -match '.azurecr.') {
            $REGISTRYBASE = "azurecr"
        } elseif (($REGISTRY -match 'docker.') -or ($REGISTRY -match 'dockerhub.')) {
            $REGISTRYBASE = "docker.io"
 #       } elseif ($REGISTRY -match 'gcr.io') {
 #           $REGISTRYBASE = "gcr.io"
        } else {
            $REGISTRYBASE = $REGISTRY
        }
        
        switch ($REGISTRYBASE) {
            # update for public docker registry and azure ACR (Azure China Cloud)
    
            "docker.io" {
                $REGISTRY_URL="https://index.docker.io/v2"
                # docker.io image will be formated as library/image name or repository/image name
                if ($IMAGE_name -match "/") {
                    $IMAGE=$IMAGE_name
                } else {
                    $IMAGE="library/$IMAGE_name"
                }

                $URL="$REGISTRY_URL/$IMAGE/manifests/$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken";
                    "Accept" = "application/vnd.docker.container.image.v1+json"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
            }
            "ghcr.io" {
                $REGISTRY_URL="https://ghcr.io/v2"
                $URL="$REGISTRY_URL/$IMAGE_NAME/manifests/$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken";
                    "Accept" = "application/vnd.docker.container.image.v1+json"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
            }
            "gcr.io" {
                $REGISTRY_URL="https://$REGISTRY/v2"
                $URL="$REGISTRY_URL/$IMAGE_name/manifests/$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken";
                    "Accept" = "application/vnd.docker.container.image.v1+json"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
            }
            "azurecr" {
                $REGISTRY_URL="https://$REGISTRY/v2"
                $URL="$REGISTRY_URL/$IMAGE_NAME/manifests/$tag"
                $headers = @{
                    "Authorization" = "Bearer $accesstoken";
                    "Accept" = "application/vnd.docker.container.image.v1+json"
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
    
              }
            default {
                # try to load data directly
                $REGISTRY_URL="https://$REGISTRY/v2"
                $URL="$REGISTRY_URL/$IMAGE_NAME/manifests/$tag"
                if ($accesstoken) {
                    $headers = @{
                        "Authorization" = "Bearer $accesstoken";
                        "Accept" = "application/vnd.docker.container.image.v1+json"
                    }
                } else {
                    $headers = @{
                        "Accept" = "application/vnd.docker.container.image.v1+json"
                    }
                }
                $response = invoke-webrequest -UseBasicParsing -uri $URL -Headers $headers
                   
            }
    
                   
        }


        if ($response.StatusCode -ne 200 -and $response.StatusCode -ne 204) {
            $statusCode = $response.StatusCode
            $reasonPhrase = $response.StatusDescription
            $message = $response.Content
            $image  = $NULL
            throw "Failed to get image manifests.`nStatus Code: $statusCode`nReason: $reasonPhrase`nMessage: $message"
        } else {
            $imagedetails = [System.Text.Encoding]::UTF8.GetString($response.Content) | convertfrom-json
        }

        return $imagedetails

    }


function GetValidVerion {
    param(
    [string][Parameter(Mandatory=$true)] $versionstring
    )
    
    $versionheader = $versionstring.split("-_")[0].tostring()

    if ($versionheader -notmatch "^v|V|[0-9]") {
        $versionval = $NULL
    } else {
        $versionheader = $versionheader.TrimStart("vV")

        if($versionheader.split('.').Count -eq 1){
            $versionheader="$versionheader.0"
        }

        try{
            $versionval = [version]$versionheader
        } catch {
            $versionval = $NULL
        }
    }
    return $versionval
}


function GetImageState {
    param(
        [string][Parameter(Mandatory=$true)] $IMAGE_NAME,
        [string][Parameter(Mandatory=$true)] $REGISTRY,
        [string][Parameter(Mandatory=$true)] $tag,
        [string][Parameter(Mandatory=$false)] $tagdigest
        )


    write-host "get registry access token with scop: $REGISTRY/$IMAGE_NAME`:$tag"
    $accesstoken = GetRegistryToken -REGISTRY $REGISTRY -IMAGE_NAME $IMAGE_NAME
    # if a valid token returned, try to pulling next image tags
        # for internal azure k8s proxy, ignore the access token 
        # https://github.com/Azure/container-service-for-azure-china/blob/master/aks/README.md

    if ($null -ne $accesstoken -or $registry -match "azk8s." -or $registry -match "mcr.") {

        $imagedetails = GetImageManifests -IMAGE_NAME $IMAGE_NAME -REGISTRY $REGISTRY -tag $tag -accesstoken $accesstoken

        # $imagetags | format-list *
        # $imagedetails | format-list *
    
        if ($imagedetails) {
            if ($imagedetails.history.v1Compatibility) {
            $lastcreatedtime = $($imagedetails.history.v1Compatibility | convertfrom-json | sort -Property created -Descending | select -First 1).created
            $currenttime = [DateTime]::UtcNow.ToString("")
            $ageddays = $(NEW-TIMESPAN -Start $lastcreatedtime -End $currenttime).Days
            } else {
                $ageddays = $NULL
            }

            # try to get the next tags from current image tag
            $imagetags = GetNextImagetags -IMAGE_NAME $IMAGE_NAME -REGISTRY $REGISTRY -tag $tag -accesstoken $accesstoken

            if ( $($imagetags.tags | measure-object).count -eq 0) {
                # if no nexted tags, mark the current image is the lastest image tag
                $islatesttag = "true"
                $taggaps = 0
                $latesttag = $tag
            } else {
               

                # try to evaluate if the last tag returned as usually 
                if ($tag -notin $imagetags.tags) {
                    $islatesttag = "false"
                    # try sort tags if the tags are formatted as xx.xxx or vxx.xx 
                    # if it is not, set last tag as NULL
                    $latesttag = ""
                    $taggaps =  0
                    
                    $rawversions=@()
                    $rawversions += $($imagetags.tags |  Where {$_ -match "^v|V|[0-9]"}) | select -unique  

                    if ($rawversions.count -gt 0) {

           
                        # sort by tag version
                        $availableversions=@{}
                        # $availableversions = $rawversions -replace "[^\d.]" | sort-object [version]$_ -Descending
                        
                        foreach ($rawversion in  $rawversions) {

                            $version = GetValidVerion($rawversion)
                            if ($version) {
                                if (!$availableversions[$version]) {
                                        $availableversions[$version] = $rawversion
                                    } else {
                                    if ($availableversions[$version] -match $rawversion) {
                                            $availableversions[$version] = $rawversion
                                    }
                                }
                            }
                            
                        }

                        
                        $vkeys = $availableversions.keys | sort-object -Descending
                        if($vkeys) {
                            $latesttag = $availableversions[$vkeys[0]]
                            $taggaps =  $vkeys.count
                        } 

                    } 
                
                } else {
                    # return last tag but contains the current one. 
                    $latesttag = ""
                    $taggaps =  0
                    $islatesttag = "unknown"
                   
                    $rawversions=@()
                    $rawversions += $($imagetags.tags |  Where {$_ -match "^[v|V][0-9]"}) | select -unique  
                    
                    $currenttagkey =  GetValidVerion($tag)
                      
                    if ($rawversions.count -gt 0 -and $NULL -ne $currenttagkey) {

           
                        # sort by tag version
                        $availableversions=@{}
                        # $availableversions = $rawversions -replace "[^\d.]" | sort-object [version]$_ -Descending
                        
                        foreach ($rawversion in  $rawversions) {

                            $version = GetValidVerion($rawversion)
                            if ($version) {
                                if (!$availableversions[$version]) {
                                        $availableversions[$version] = $rawversion
                                    } else {
                                    if ($availableversions[$version] -match $rawversion) {
                                            $availableversions[$version] = $rawversion
                                    }
                                }
                            }
                            
                        }

                        
                        $vkeys = $availableversions.keys | sort-object -Descending
                        if($vkeys) {
                            if ($vkeys[0] -eq $currenttagkey) {
                                $latesttag = $tag
                                $taggaps =  0
                                $islatesttag = "true"
                            } else {
                                for($i=0;$i -lt $vcount;$i++) {
                                    if($vkeys[$i] -eq $currenttagkey) {
                                        break
                                    }
                                }
                                $latesttag = $availableversions[$vkeys[0]]
                                $taggaps =  $i
                                $islatesttag = "false"
                            }
                        
                        } 


                    } else {
                        # cannot match with exact version tags
                        $latesttag = ""
                        $taggaps =  0
                        $islatesttag = "false"
                    }

                }
     
            }
            $imagestate = [PSCustomObject]@{
                registry = $REGISTRY
                image = $IMAGE_NAME
                tag = $tag
                tagdigest = $tagdigest
                ageddays = $ageddays
                islatesttag = $islatesttag
                latesttag = $latesttag
                taggaps = $taggaps
            }

            $imagestate 

        If ($ageddays -lt 0) {$ageddays = 0}
        } else {
            write-host "cannot find the matched images: $REGISTRY/$IMAGE_NAME`:$tag. Please check if the image path is correct"
        }
        
    } else {

        write-host "cannot grant access token for: $REGISTRY/$IMAGE_NAME`:$tag. Please check if you have permisison to access the target registry"

    }

}


# login with automtion credential


$connectionName = "AzureRunAsConnection"
try
{
    # Get the connection "AzureRunAsConnection "
    $servicePrincipalConnection=Get-AutomationConnection -Name $connectionName

    "Logging in to Azure..."
    Connect-AzAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint `
        -EnvironmentName AzureChinaCloud
 }
catch {
    if (!$servicePrincipalConnection)
    {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    } else{
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}

if ($subscriptionId -eq "") {
    $subscriptionId = $servicePrincipalConnection.SubscriptionId
}
set-azcontext $subscriptionId

$workspace = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "workspace").response | ConvertFrom-Json
$sharedkeys = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspacename -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -querytype "sharedkeys").response | ConvertFrom-Json

# build query statement to list image version with searchbase
$query = @'
let timerange = 1d;
ContainerInventory
| where TimeGenerated > ago(timerange)
| where _ResourceId contains "
'@
$query=$query+$searchbase+@'
"
| summarize arg_max(TimeGenerated, ContainerState, Repository, Image, ImageTag) by ImageID, _ResourceId
| extend clustername = tostring(split(_ResourceId,'/')[-1])
| extend repository = iif(Repository<>'',Repository,'docker.io')
| project TimeGenerated, clustername, repository, Image, ImageTag, ContainerState, ImageID
'@

$currentimages  = (Invoke-LogAnalyticsQuery -Environment $cloud -WorkspaceName $workspace.properties.customerId -SubscriptionId $subscriptionId -ResourceGroup $resourcegroupname -Query $query -querytype "query").Results 
$imagestates = @()
foreach($currentimage in $currentimages) {


    $registry = $currentimage.repository 

    # map to external, only when not using azure internal IP 
    #if ($currentimage.repository  -match "mcr.azk8s.cn") { 
    #    $registry = "mcr.microsoft.com"
    #} elseif ($currentimage.repository  -match "azk8s.cn") {
    #    $registry = $currentimage.repository.repalce('azk8s.cn','io')
    #} else {
    #    $registry = $currentimage.repository
    #    }

    $imagestate = GetImageState -REGISTRY $registry -IMAGE_NAME $currentimage.Image -tag  $currentimage.ImageTag -tagdigest  $currentimage.ImageID
    if ($imagestate) {
        # link to the aks cluster name
        $imagestate | Add-Member -NotePropertyName ClusterName -NotePropertyValue $currentimage.clustername
        $imagestates+=$imagestate 
    }
}
# $imagestates
if ($imagestates.count -ge 1) {

    $jsonTable = ConvertTo-Json -InputObject $imagestates
    # upload the result
    Post-LogAnalyticsData -customerId $workspace.properties.customerId -sharedKey $sharedkeys.primarySharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($jsonTable)) -logType $logType
}

