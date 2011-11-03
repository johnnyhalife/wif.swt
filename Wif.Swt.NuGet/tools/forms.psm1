function Show-MessageBox ($title, $msg) {     
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null 
    [Windows.Forms.MessageBox]::Show($msg, $title, [Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning, [System.Windows.Forms.MessageBoxDefaultButton]::Button1, [System.Windows.Forms.MessageBoxOptions]::DefaultDesktopOnly)
}

Export-ModuleMember Show-MessageBox
