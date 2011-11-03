param($installPath, $toolsPath, $package, $project)

Import-Module (Join-Path $toolsPath forms.psm1)

	if ([system.reflection.assembly]::loadwithpartialname("Microsoft.IdentityModel") -eq $null)
	{
		$nl= [System.Environment]::NewLine
		$message = "You need to install Windows Identity Foundation Runtime." + $nl
		$message = $message + "Click yes if you want to navigate to the download page." + $nl + $nl
		$message = $message + "Make sure to add 'Microsoft.IdentityModel' reference to the project after you install it."
		$caption = "Dependency Not Found"

		$result = Show-MessageBox $caption $message

		if ($result -eq [Windows.Forms.DialogResult]::Yes)
		{
			start http://support.microsoft.com/kb/974405
		}
	}
	else 
	{
		$project.Object.References.Add("Microsoft.IdentityModel")
	}

	$removeAddedKey = 0
	$removeAddedTrustedIssuer = 0
	$removeAddedAudience = 0
	$removeAddedConfigSection = 0
	
	# Set the issuer registry
	$web = $project.ProjectItems | Where-Object { $_.Name -eq "Web.config" };
	if ($web -ne $null)
	{
		[xml]$xml = Get-Content $web.FileNames(1)

		# Check for previous keys
		foreach ($key in $xml.configuration.appSettings.add)
		{
			if (($key.key -eq "SwtSigningKey") -and ($key.value -ne "[your 256-bit symmetric key configured in the STS/ACS]"))
			{
				$removeAddedKey = 1
			}
		}
		
		# Check for previous issuernameregistries
		foreach ($key in $xml.SelectNodes("configuration/microsoft.identityModel/service/issuerNameRegistry"))
		{
			foreach ($trustedIssuers in $key.trustedIssuers.add)
			{
				if ($trustedIssuers.name -ne "https://[youracsnamespace].accesscontrol.windows.net/")
				{
					$removeAddedTrustedIssuer = 1
				}
			}
		}
		
		# Check for previous issuernameregistries
		foreach ($key in $xml.SelectNodes("configuration/microsoft.identityModel/service/audienceUris/add"))
		{
			if ($key.value -ne "[yourrealm]")
			{
				$removeAddedAudience = 1
			}
		}
		
		# Check for previous configsections
		foreach ($key in $xml.SelectNodes("configuration/configSections/section"))
		{
			if ($key.name -eq "microsoft.identityModel")
			{
				$removeAddedConfigSection++
			}
		}
		
		$registry = $xml.SelectSingleNode("configuration/microsoft.identityModel/service/issuerNameRegistry")
		$registry.type = "Microsoft.IdentityModel.Swt.SwtIssuerNameRegistry, Wif.Swt"

		if($removeAddedKey)
		{
			foreach ($key in $xml.configuration.appSettings.add)
			{
				if (($key.key -eq "SwtSigningKey") -and ($key.value -eq "[your 256-bit symmetric key configured in the STS/ACS]"))
				{
					$xml.SelectSingleNode("configuration/appSettings").RemoveChild($key)
				}
			}
		}
		
		if ($removeAddedTrustedIssuer)
		{
			foreach ($key in $xml.SelectNodes("configuration/microsoft.identityModel/service/issuerNameRegistry"))
			{
				foreach ($trustedIssuers in $key.trustedIssuers.add)
				{
					if ($trustedIssuers.name -eq "https://[youracsnamespace].accesscontrol.windows.net/")
					{
						$xml.SelectSingleNode("configuration/microsoft.identityModel/service").RemoveChild($key)
						break
					}
				}
			}
		}

		if ($removeAddedAudience)
		{
			# Check for previous issuernameregistries
			foreach ($key in $xml.SelectNodes("configuration/microsoft.identityModel/service/audienceUris/add"))
			{
				if ($key.value -eq "[yourrealm]")
				{
					$xml.SelectSingleNode("configuration/microsoft.identityModel/service/audienceUris").RemoveChild($key)
				}
			}
			
			$xml.save($web.FileNames(1))
		}
		
		if ($removeAddedConfigSection -ge 1)
		{
			$configSection = $xml.SelectSingleNode("configuration/configSections/section")
			$xml.SelectSingleNode("configuration/configSections").RemoveChild($configSection)
		}
	}
	
