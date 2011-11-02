param($installPath, $toolsPath, $package, $project)

	if ([system.reflection.assembly]::loadwithpartialname("Microsoft.IdentityModel") -eq $null)
	{
		write-warning Windows Identity Foundation is not installed. Opening browser to install from: http://support.microsoft.com/?kbid=974405
		start http://support.microsoft.com/?kbid=974405
		uninstall-package Wif.Swt
		return
	}

	# Set the issuer registry
	$web = $project.ProjectItems | Where-Object { $_.Name -eq "Web.config" };

	if ($web -ne $null)
	{
		$xml = new-object System.Xml.XmlDocument
		$xml.Load($web.FileNames(1))
		$registry = $xml.SelectSingleNode("configuration/microsoft.identityModel/service/issuerNameRegistry")

		if ($registry -eq $null)
		{
			write-warning "Please add an STS reference to your project before installing SWT support. Reinstall again after doing so."
			uninstall-package Wif.Swt
			return
		}

		$registry.type = "Microsoft.IdentityModel.Swt.SwtIssuerNameRegistry, Wif.Swt"

		$xml.Save($web.FileNames(1))
	}
	else
	{
		return
	}