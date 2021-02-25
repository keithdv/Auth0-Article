# OAuth2 Token Exchange for the Enterprise API Gateway
# Keith Voels
# Rocket Mortgage

# Creates all components in Auth0
# to execute Authorization Code Flow
# and Client Credential Flow with Token Exchange
# showing how the user's context and permissions
# can be securly given to the API thru and API Gateway

#Prerequisits
#
# Auth0 Account
#     Free Account Works!!
#     Enter the Auth0 Domain, Management ClientId and Secret below
#     https://auth0.com/docs/tokens/management-api-access-tokens
#     Note: Other vendors support Token Exchange but functionality varies
# 
# When the browser window pops up users are
# admin@tokenexchange.com or user@tokenexchange.com
# password is "Password1234" ($userPw variable below)
#

$ErrorActionPreference = "Stop";

##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Replace the values below with those from your Auth0 Account
$auth0Domain = "tokenexchange2.us.auth0.com";
# Auth0 "Auth0 Management API" ClientID and Client Secret
$auth0ManagementClientId = "K33Ifj100stOr7ygno8tgMFfC9fr0Jjg";
$auth0ManagementClientSecret = "HxWGC577skGkj2TCKe8mui2Z6TXODNSKgJqcQ-NccXhurFQwt7ZIaAWuie_c-v_r";
##!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

$userPw = "Password1234";

$readScope = @{ 
    value="gateway:read"
    description="Token Exchange API Gateway Read Permissions" 
}

$writeScope = @{ 
    value="gateway:write"
    description="Token Exchange API Gateway Write Permissions" 
}

Set-Location $PSScriptRoot

. $PSScriptRoot\Decode-JwtToken.ps1
. $PSScriptRoot\AuthorizationCodeFlow.ps1


#-------------------------------------------------------------------------------------------------------------------------------------
# Get Management token to auth to the Auth0 Management API V2

if($null -eq $managementAccessToken){

    Write-Verbose "Getting new Auth0 Management Api Access Token";

    $managementAccessToken = $null, $managementAccessTokenResponse = $null; $body = $null;

    $body = @{
        grant_type='client_credentials'
        audience="https://$auth0Domain/api/v2/"
        client_id= $auth0ManagementClientId
        client_secret= $auth0ManagementClientSecret
    }

    $contentType = 'application/x-www-form-urlencoded' 
    $managementAccessTokenResponse =  Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/oauth/token" -body $body -ContentType $contentType

    if(($null -eq $managementAccessTokenResponse) -or
        ($null -eq $managementAccessTokenResponse.access_token)){
        Write-Error 'Unable to retrieve Auth0 management access token';
        return 1;
    }

    $managementAccessToken = $managementAccessTokenResponse.access_token;

}


#-------------------------------------------------------------------------------------------------------------------------------------
# Create User and Admin Roles

function CreateRole([string] $name, [string] $description) {

    
    $roles = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/roles" -Headers @{ Authorization = "Bearer $managementAccessToken" }
    
    $role = $null;
    
    foreach($r in $roles){
        if($r.name -eq $name){
            $role = $r;
            break;
        }
    
    }
    
    if($null -eq $role){
    
        $body = 
        @{
          name=$name
          description=$description
        }
        
        
        $role = Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/roles" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'
    
    }

    return $role;

}

if($null -eq $adminRole){
    $adminRole = CreateRole -name "TokenExchangeAdmin" -description "Token Exchange Elevated Permissions";
}

if($null -eq $userRole){
    $userRole = CreateRole -name "TokenExchangeUser" -description "Token Exchange Default permissions";
}

#-------------------------------------------------------------------------------------------------------------------------------------
# Create Users: admin and user

function CreateUser([string] $givenname, [string] $familyname) {

    
    $users = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/users" -Headers @{ Authorization = "Bearer $managementAccessToken" }
    
    $user = $null;
    
    foreach($u in $users){
        if($u.given_name -eq $givenname){
            $user = $u;
            break;
        }
    
    }
    
    if($null -eq $user){
    
        $body = 
        @{
          email="$givenname@tokenexchange.com"
          given_name = $givenname
          name = "$givenname $familyname"
          family_name = $familyname
          connection = "Username-Password-Authentication"
          verify_email = $false
          password = $userPw
        }
        
        
        $user = Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/users" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'
    
    }

    return $user;

}

if($null -eq $adminUser){
    $adminUser = CreateUser -givenname "admin" -familyname "TokenExchange"
}

if($null -eq $user){
    $user = CreateUser -givenname "User" -familyname "TokenExchange"
}

#-------------------------------------------------------------------------------------------------------------------------------------
# Assign Users to Roles

function AssignUserRole([PSCustomObject] $user, [PSCustomObject] $role) {

    $userRoles = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/users/$($user.user_id)/roles" -Headers @{ Authorization = "Bearer $managementAccessToken" }
    
    $userRole = $null;
    
    foreach($r in $userRoles){
        if($r.id -eq $role.id){
            $userRole = $r;
            break;
        }
    }

    if($null -eq $userRole){
    
        $body = 
        @{
          roles=@($role.id)
        }
        
        $userRole = Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/users/$($user.user_id)/roles" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'
    
    }

    return $userRole;

}

if($null -eq $adminUserAdminRole){
    $adminUserAdminRole = AssignUserRole -user $adminUser -role $adminRole
}
if($null -eq $adminUserUserRole){
    $adminUserUserRole = AssignUserRole -user $adminUser -role $userRole
}
if($null -eq $userUserRole){
    $userUserRole = AssignUserRole -user $user -role $userRole
}

#-------------------------------------------------------------------------------------------------------------------------------------
# Create Auth0 Application "Token Exchange Application" - Web Application
#   and "Token Exchange API Gateway Client"
# Applications request access tokens

function CreateApplication([string] $name, [string] $description, [string] $appType) {

    
    $clients = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/clients" -Headers @{ Authorization = "Bearer $managementAccessToken" }
    
    $client = $null;
    
    foreach($c in $clients){
        if($c.name -eq $name){
            $client = $c;
            break;
        }
    
    }
    
    if($null -eq $client){
    
        $body = 
        @{
          name=$name
          description=$description
          callbacks=@("http://localhost","https://www.google.com")
          allowed_logout_urls=@("https://www.google.com")
          app_type=$appType
          is_first_party=$true
        }

        $client = Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/clients" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'
    
    }

    return $client;

}

if($null -eq $application) {
    $application = CreateApplication -name "Token Exchange Application" -description "Token Exchange Article - Application - This is the client application (SPA, Website, etc)." -appType "regular_web" -scopes $scopes;
}

if($null -eq $apiGatewayApplication) {
    # Auth0 splits the role of Application and API. If the component is both protected (accepts/validates tokens) and makes calls (request tokens) it has both an Application and API configured in Auth0.
    $apiGatewayApplication = CreateApplication -name "Token Exchange API Gateway Application" -description "Token Exchange Article - API Gateway Application to request access token to APIs" -appType "non_interactive";
}

#-------------------------------------------------------------------------------------------------------------------------------------
# Create Auth0 APIs "Token Exchange API Gateway" and "Token Exchange API"
# APIs accept and validate tokens and their audience

function CreateResourceServer([string] $name, [string] $identifier, [PSCustomObject[]] $scopes){

    $resources = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/resource-servers" -Headers @{ Authorization = "Bearer $managementAccessToken" }

    $server = $null;

    foreach($r in $resources){
        if($r.name -eq $name){
            $server = $r;
        }
    }

    if($null -eq $server){
        $body =
        @{
          name = $name
          identifier = "http://$($identifier)"
          skip_consent_for_verifiable_first_party_clients = $true
          scopes = $scopes
          enforce_policies = $true
          token_dialect = "access_token_authz"
        }

        $server = Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/resource-servers" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'
    }

    Write-Verbose "CreateResourceServer Results: $($server)";

    return $server;
}

if($null -eq $apiGateway) {

    $scopes = @();

    $scopes += $readScope;
    $scopes += $writeScope;

    $apiGateway = CreateResourceServer -name "Token Exchange API Gateway" -identifier "TokenExchangeAPIGateway" -scopes $scopes;
}

if($null -eq $api){
    $scopes = @();
    $api = CreateResourceServer -name "Token Exchange API" -identifier "TokenExchangeAPI" -scopes $scopes
}

#-------------------------------------------------------------------------------------------------------------------------------------
# Grant the "Token Exchange API Gateway Application" machine-to-machine access to the "Token Exchange API"
# This allows the API Gateway to request an access token using client credential flow to the "Token Exchange API"

function CreateClientGrant([PSCustomObject] $client, [PSCustomObject] $api){

    $resources = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/client-grants" -Headers @{ Authorization = "Bearer $managementAccessToken" }

    $server = $null;

    foreach($r in $resources){
        if(($r.client_id -eq $client.client_id) -and ($r.audience -eq $api.identifier)){
            $server = $r;
        }
    }

    if($null -eq $server){
        $body =
        @{
          client_id = $client.client_id
          audience = $api.identifier
          scope = @()
        }

        $server = Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/client-grants" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'

    }
    

    return $server;
}

if($null -eq $gatewayAPIGrant) {
    $gatewayAPIGrant = CreateClientGrant -client $apiGatewayApplication -api $api
}


#-------------------------------------------------------------------------------------------------------------------------------------
# Associate the scopes (aka permissions) defined for "Token Exchange API Gateway API" to the Roles
# The Roles are assigned to the users linking the users to the scopes (permissions) they are approved for

function AssociateRolePermission($role, $permission, $resourceServer){

    $permissions = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/roles/$($role.id)/permissions" -Headers @{ Authorization = "Bearer $managementAccessToken" }

    foreach($p in $permissions){
        if($p.permission_name -eq $permission.Values){
            RETURN $p;
        }
    }

    $permission =
    @{
        resource_server_identifier = $resourceServer.identifier
        permission_name = $permission.Value;
    }

    $body = 
    @{
        permissions = @($permission)
    }


    RETURN Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/roles/$($role.id)/permissions" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'

}

if($null -eq $adminRoleReadScope){
    $adminRoleReadScope = AssociateRolePermission -role $adminRole -permission $readScope -resourceServer $apiGateway
}

if($null -eq $adminRoleWriteScope){
    $adminRoleWriteScope = AssociateRolePermission -role $adminRole -permission $writeScope -resourceServer $apiGateway
}

if($null -eq $userRoleReadScope){
    $userRoleReadScope = AssociateRolePermission -role $userRole -permission $readScope -resourceServer $apiGateway
}

#-------------------------------------------------------------------------------------------------------------------------------------
# Create Client Credential Exchange Hook


function CreateHook([string] $name, [string] $fileName, [PSCustomObject] $dependencies){

    $hooks = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/hooks" -Headers @{ Authorization = "Bearer $managementAccessToken" }

    foreach($h in $hooks){
        if($h.name -eq $name){
            RETURN $h;
        }
    }

    $script = [System.IO.File]::ReadAllText("$PSScriptRoot\$fileName")

    $script = $script -replace "%%auth0domain%%", $auth0Domain

    $body = [PSCustomObject] @{
        name=$name
        triggerId = "credentials-exchange"
        enabled = $true
        dependencies = $dependencies
        script = $script
    }

    RETURN Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/api/v2/hooks" -Headers @{ Authorization = "Bearer $managementAccessToken" } -body $(ConvertTo-Json $body) -ContentType 'application/json'


}

$dependencies = [PSCustomObject]@{
    jsonwebtoken="8.5.1"
    "jwks-rsa"="1.10.1"
}

if($null -eq $hook){
    $hook = CreateHook -name token-exchange -fileName .\TokenExchangeAuth0Hook.js -dependencies $dependencies
}

#-------------------------------------------------------------------------------------------------------------------------------------
# At this point all of the Auth0 components have been created
# This is the OAuth2 token flow in Diagram A


function GetAuthCode([string] $aud,[PSCustomObject] $client) 
{

    $clientreq =  @{ redirect_uris = @("https://www.google.com/") };

    # client registration response json, download from sso
    $clientres =  @{ client_id = $client.client_id
                     client_secret = $client.client_secret
                     audience = $aud
    }
        
    #Write-Verbose $(ConvertTo-Json $clientreq);
    #Write-Verbose $(ConvertTo-Json $clientres);
   
    $code = AuthorizationCodeFlow -Domain $auth0Domain -clientreq $clientreq -clientres $clientres
    
    return $code;

}

function GetAuthCodeAccessToken([string] $code, [string] $aud,[PSCustomObject] $client) 
{

    $body = @{
        grant_type='authorization_code'
        audience=$aud
        code=$code
        client_id= $client.client_id
        client_secret= $client.client_secret
        redirect_uri= "https://www.google.com/"
    }
    
    $contentType = 'application/x-www-form-urlencoded' 
    $accessTokenResponse =  Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/oauth/token" -body $body -ContentType $contentType

    return $accessTokenResponse[0]; #Not sure why it is an array

}

#if(-not $tokenA){
    $code = GetAuthCode -aud $apiGateway.identifier -client $application;
    $tokenA = GetAuthCodeAccessToken -code $code -aud $apiGateway.identifier -client $application;
#}

$decoded = Decode-JWT -rawToken $tokenA[0].access_token

Write-Output "Access Token A"
Write-Output $decoded.claims

# Set-Clipboard -Value $tokenA.access_token

function GetAccessTokenDoTokenExchange([string] $aud, [string] $accessToken, [PSCustomObject] $client) 
{

    $body = @{
        grant_type='client_credentials'
        audience=$aud
        client_id= $client.client_id
        client_secret= $client.client_secret
        #SubjectToken is what the Auth0 Hook recognizes as the token to exchange
        subject_token_type='urn:ietf:params:oauth:token-type:jwt'
        subject_token=$accessToken
    }
    
    Write-Verbose $(ConvertTo-Json $body)

    $contentType = 'application/x-www-form-urlencoded' 
    $accessTokenResponse =  Invoke-RestMethod -Method Post -Uri "https://$auth0Domain/oauth/token" -body $body -ContentType $contentType

    return $accessTokenResponse[0]; #Honestly, not sure why it is an array

}

$ApiAccessTokenWUser = GetAccessTokenDoTokenExchange -aud $api.identifier -accessToken $tokenA.access_token -client $apiGatewayApplication

$decoded = Decode-JWT -rawToken $ApiAccessTokenWUser.access_token

Write-Output "Access Token B"
Write-Output $decoded.claims

# Set-Clipboard -Value $ApiAccessTokenWUser.access_token

function CleanUp(){

    # Remove Everything from Auth0
    

    if($null -ne $application){
        #Logout the user
        #Use to switch between user and admin
        $clientreq =  @{ redirect_uris = @("https://www.google.com/") };

        # client registration response json, download from sso
        $clientres =  @{ client_id = $application.client_id }
    
        LogoutUser -Domain $auth0Domain -clientreq $clientreq -clientres $clientres
    }

    if($gatewayAPIGrant -ne $null){
        Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/client-grants/$($gatewayAPIGrant.id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        $gatewayAPIGrant = $null;
    }

    if($apiGatewayApplication -ne $null){
        Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/clients/$($apiGatewayApplication.client_id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        $apiGatewayApplication = $null;
    }

    if($application -ne $null){
        Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/clients/$($application.client_id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        $application = $null;
    }

    if($apiGateway -ne $null){
        Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/resource-servers/$($apiGateway.id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        $apiGateway = $null;
    }

    if($api -ne $null){
        Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/resource-servers/$($api.id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        $api = $null;
    }

    $users = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/users" -Headers @{ Authorization = "Bearer $managementAccessToken" }
 
    foreach($u in $users){
        if($u.email.EndsWith("tokenexchange.com")){
            Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/users/$($u.user_id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        }
    }

    $adminUser = $null;
    $user = $null;
   

    $roles = Invoke-RestMethod -Method Get -Uri "https://$auth0Domain/api/v2/roles" -Headers @{ Authorization = "Bearer $managementAccessToken" }
 
    foreach($r in $roles){
        if($r.name.StartsWith("TokenExchange")){
            Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/roles/$($r.id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        }
    }

    if($null -ne $hook){
        Invoke-RestMethod -Method Delete -Uri "https://$auth0Domain/api/v2/hooks/$($hook.id)" -Headers @{ Authorization = "Bearer $managementAccessToken" }
        $hook = $null;
    }

    $adminRole = $null;
    $userRole = $null;
    $rolesAssignRan = $false;

    $adminUserAdminRole = $null;
    $adminUserUserRole = $null;
    $userUserRole = $null;

    $adminRoleReadScope = $null;
    $adminRoleWriteScope = $null;
    $userRoleReadScope = $null;
    $tokenA = $null;
    $ApiAccessTokenWUser = $null;

}
