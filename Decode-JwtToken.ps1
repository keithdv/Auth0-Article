function Convert-FromBase64StringWithNoPadding([string]$data)
{
    $data = $data.Replace('-', '+').Replace('_', '/')
    switch ($data.Length % 4)
    {
        0 { break }
        2 { $data += '==' }
        3 { $data += '=' }
        default { throw New-Object ArgumentException('data') }
    }
    return [System.Convert]::FromBase64String($data)
}

function Decode-JWT([string]$rawToken)
{
    $parts = $rawToken.Split('.');
    $headers = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[0]))
    $claims = [System.Text.Encoding]::UTF8.GetString((Convert-FromBase64StringWithNoPadding $parts[1]))
    $signature = (Convert-FromBase64StringWithNoPadding $parts[2])

    $customObject = [PSCustomObject]@{
        headers = ($headers | ConvertFrom-Json)
        claims = ($claims | ConvertFrom-Json)
        signature = $signature
    }

    Write-Verbose -Message ("JWT`r`n.headers: {0}`r`n.claims: {1}`r`n.signature: {2}`r`n" -f $headers,$claims,[System.BitConverter]::ToString($signature))
    return $customObject
}

function Get-JwtTokenData
{
    [CmdletBinding()]  
    Param
    (
        # Param1 help description
        [Parameter(Mandatory=$true)]
        [string] $Token,
        [switch] $Recurse
    )
    
    if ($Recurse)
    {
        $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Token))
        Write-Host("Token") -ForegroundColor Green
        Write-Host($decoded)
        $DecodedJwt = Decode-JWT -rawToken $decoded
    }
    else
    {
        $DecodedJwt = Decode-JWT -rawToken $Token
    }
    Write-Host("Token Values") -ForegroundColor Green
    Write-Host ($DecodedJwt | Select headers,claims | ConvertTo-Json)
    return $DecodedJwt
}

