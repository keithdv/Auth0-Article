
# From https://github.com/globalsign/OAuth-2.0-client-examples/blob/master/PowerShell/Powershell-example.ps1
# Thank you for a great example!!

# configuration

# enable verbose output
$VerbosePreference = "Continue"


function AuthorizationCodeFlow([string] $domain, [PSCustomObject] $clientreq,[PSCustomObject] $clientres)
{

    # authorization server metadata
    $metadata = Invoke-RestMethod -Uri $("https://" + $domain.Trim() + "/.well-known/openid-configuration")
    Write-Verbose "metadata.json: $($metadata)"

    # windows forms dependencies
    Add-Type -AssemblyName System.Windows.Forms 
    Add-Type -AssemblyName System.Web

    # create window for embedded browser
    $form = New-Object Windows.Forms.Form
    $form.Width = 640
    $form.Height = 480
    $web = New-Object Windows.Forms.WebBrowser
    $web.Size = $form.ClientSize
    $web.Anchor = "Left,Top,Right,Bottom"
    $form.Controls.Add($web)
    # global for collecting authorization code response
    $Global:redirect_uri = $null;
    $Global:clientreq = $clientreq;

    # add handler for the embedded browser's Navigating event
    $web.add_Navigating({
        Write-Verbose "Navigating $($_.Url)"
        # detect when browser is about to fetch redirect_uri
        $uri = [uri] $Global:clientreq.redirect_uris[0];
        if($_.Url.Authority -eq $uri.Authority) {
            # collect authorization response in a global
            $Global:redirect_uri = $_.Url
            # cancel event and close browser window
            $form.DialogResult = "OK"
            $form.Close()
            $_.Cancel = $true
        }
    })

    $scope = ""

    $web.Navigate("$($metadata.authorization_endpoint)?scope=$($scope)&response_type=code&redirect_uri=$($clientreq.redirect_uris[0])&client_id=$($clientres.client_id)&audience=$($clientres.audience)")
    # show browser window, waits for window to close
    if($form.ShowDialog() -ne "OK") {
        Write-Verbose "WebBrowser: Canceled"
        return
    }
    if(-not $Global:redirect_uri) {
        Write-Verbose "WebBrowser: redirect_uri is null"
        return
    }

    # decode query string of authorization code response
    $response = [Web.HttpUtility]::ParseQueryString($Global:redirect_uri.Query)
    if(-not $response.Get("code")) {
        Write-Verbose "WebBrowser: authorization code is null"
        return
    }

    return $response.Get("code");

}


function LogoutUser([string] $domain, [PSCustomObject] $clientreq,[PSCustomObject] $clientres)
{

    # windows forms dependencies
    Add-Type -AssemblyName System.Windows.Forms 
    Add-Type -AssemblyName System.Web

    # create window for embedded browser
    $form = New-Object Windows.Forms.Form
    $form.Width = 640
    $form.Height = 480
    $web = New-Object Windows.Forms.WebBrowser
    $web.Size = $form.ClientSize
    $web.Anchor = "Left,Top,Right,Bottom"
    $form.Controls.Add($web)
    # global for collecting authorization code response
    $Global:redirect_uri = $null;
    $Global:clientreq = $clientreq;

    # add handler for the embedded browser's Navigating event
    $web.add_Navigating({
        Write-Verbose "Navigating $($_.Url)"
        # detect when browser is about to fetch redirect_uri
        $uri = [uri] $Global:clientreq.redirect_uris[0];
        if($_.Url.Authority -eq $uri.Authority) {
            # collect authorization response in a global
            $Global:redirect_uri = $_.Url
            # cancel event and close browser window
            $form.DialogResult = "OK"
            $form.Close()
            $_.Cancel = $true
        }
    })

    $web.Navigate("$($domain)/v2/logout?returnTo=$($clientreq.redirect_uris[0])&client_id=$($clientres.client_id)")
    # show browser window, waits for window to close
    if($form.ShowDialog() -ne "OK") {
        Write-Verbose "WebBrowser: Canceled"
        return
    }
    if(-not $Global:redirect_uri) {
        Write-Verbose "WebBrowser: redirect_uri is null"
        return
    }


}
