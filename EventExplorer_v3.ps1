
#Requires -Version 5.1
<#
.SYNOPSIS
    Windows Event Explorer - PowerShell GUI
.DESCRIPTION
    3-panel dark-theme GUI for collecting and analyzing Windows Event Logs
    from local and remote hosts with privileged credentials.
.NOTES
    Requires: PowerShell 5.1+, Windows OS
    Run as Administrator for Security log and remote access.
    ASCII-only source - no Unicode symbols.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ==============================================================================
#  GLOBAL STATE
# ==============================================================================
$global:Hosts      = @{}
$global:CurrentLog = @{}
$global:Events     = @()
$global:MaxEvents  = 500
$global:FilterCfg  = @{
    Levels    = @(1, 2, 3, 4, 5)
    StartTime = $null
    EndTime   = $null
    EventIDs  = @()
    Source    = ""
}

# ==============================================================================
#  COLOR PALETTE
# ==============================================================================
$CLR = @{
    Bg       = [Drawing.Color]::FromArgb(20,  20,  28)
    Panel    = [Drawing.Color]::FromArgb(30,  30,  42)
    Strip    = [Drawing.Color]::FromArgb(26,  26,  36)
    Border   = [Drawing.Color]::FromArgb(55,  55,  75)
    Accent   = [Drawing.Color]::FromArgb(0,   120, 215)
    Text     = [Drawing.Color]::FromArgb(218, 218, 222)
    SubText  = [Drawing.Color]::FromArgb(130, 130, 155)
    Grid     = [Drawing.Color]::FromArgb(36,  36,  48)
    GridAlt  = [Drawing.Color]::FromArgb(31,  31,  43)
    GridHdr  = [Drawing.Color]::FromArgb(40,  40,  55)
    RowSel   = [Drawing.Color]::FromArgb(0,   88,  168)
    Critical = [Drawing.Color]::FromArgb(210, 45,  45)
    Err      = [Drawing.Color]::FromArgb(225, 75,  55)
    Warning  = [Drawing.Color]::FromArgb(215, 158, 0)
    Info     = [Drawing.Color]::FromArgb(0,   175, 115)
    Verbose  = [Drawing.Color]::FromArgb(100, 145, 205)
    Success  = [Drawing.Color]::FromArgb(40,  195, 105)
}

# ==============================================================================
#  FONTS
# ==============================================================================
$Fonts = @{
    UI     = New-Object Drawing.Font("Segoe UI", 9)
    UIBold = New-Object Drawing.Font("Segoe UI", 9,  [Drawing.FontStyle]::Bold)
    Small  = New-Object Drawing.Font("Segoe UI", 8)
    Mono   = New-Object Drawing.Font("Consolas", 9.5)
}

# ==============================================================================
#  HELPERS
# ==============================================================================
function Get-LevelInfo {
    param([int]$Level)
    switch ($Level) {
        1       { return @{ Name="Critical";    Symbol="[CRIT]"; Color=$CLR.Critical } }
        2       { return @{ Name="Error";       Symbol="[ERR] "; Color=$CLR.Err      } }
        3       { return @{ Name="Warning";     Symbol="[WARN]"; Color=$CLR.Warning  } }
        4       { return @{ Name="Information"; Symbol="[INFO]"; Color=$CLR.Info     } }
        5       { return @{ Name="Verbose";     Symbol="[VERB]"; Color=$CLR.Verbose  } }
        0       { return @{ Name="LogAlways";   Symbol="[LOG] "; Color=$CLR.SubText  } }
        default { return @{ Name="Unknown";     Symbol="[?]  ";  Color=$CLR.SubText  } }
    }
}

function Format-Xml {
    param([string]$Xml)
    try {
        $doc = [xml]$Xml
        $sw  = New-Object System.IO.StringWriter
        $xws = New-Object System.Xml.XmlWriterSettings
        $xws.Indent = $true; $xws.IndentChars = "  "
        $xw = [System.Xml.XmlWriter]::Create($sw, $xws)
        $doc.Save($xw); $xw.Close()
        return $sw.ToString()
    } catch { return $Xml }
}

function Get-EventRawText {
    param($Event)
    if (-not $Event) { return "" }
    $lvl = Get-LevelInfo $Event.Level
    $sb  = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine("=" * 72)
    [void]$sb.AppendLine("  WINDOWS EVENT LOG - ENTRY DETAIL")
    [void]$sb.AppendLine("=" * 72)
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("  Log Name    : $($Event.LogName)")
    [void]$sb.AppendLine("  Source      : $($Event.ProviderName)")
    [void]$sb.AppendLine("  Date / Time : $($Event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff zzz'))")
    [void]$sb.AppendLine("  Event ID    : $($Event.Id)")
    [void]$sb.AppendLine("  Level       : $($lvl.Name) [$($Event.Level)]")
    [void]$sb.AppendLine("  Task Cat.   : $($Event.TaskDisplayName)")
    [void]$sb.AppendLine("  Opcode      : $($Event.OpcodeDisplayName)")
    [void]$sb.AppendLine("  Keywords    : $($Event.KeywordsDisplayNames -join ', ')")
    [void]$sb.AppendLine("  User        : $(if ($Event.UserId) { $Event.UserId.Value } else { 'N/A' })")
    [void]$sb.AppendLine("  Computer    : $($Event.MachineName)")
    [void]$sb.AppendLine("  Process ID  : $($Event.ProcessId)")
    [void]$sb.AppendLine("  Thread ID   : $($Event.ThreadId)")
    [void]$sb.AppendLine("  Activity ID : $($Event.ActivityId)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("-" * 72)
    [void]$sb.AppendLine("  MESSAGE")
    [void]$sb.AppendLine("-" * 72)
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine($Event.Message)
    [void]$sb.AppendLine("")
    if ($Event.Properties.Count -gt 0) {
        [void]$sb.AppendLine("-" * 72)
        [void]$sb.AppendLine("  PROPERTIES  ($($Event.Properties.Count) items)")
        [void]$sb.AppendLine("-" * 72)
        for ($i = 0; $i -lt $Event.Properties.Count; $i++) {
            [void]$sb.AppendLine("  [$i]  $($Event.Properties[$i].Value)")
        }
        [void]$sb.AppendLine("")
    }
    return $sb.ToString()
}

function ConvertTo-EventJson {
    param($Event)
    if (-not $Event) { return "{}" }
    try {
        $obj = [ordered]@{
            EventId           = $Event.Id
            Level             = (Get-LevelInfo $Event.Level).Name
            LevelCode         = $Event.Level
            TimeCreated       = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss.fff zzz")
            TimeCreatedUtc    = $Event.TimeCreated.ToUniversalTime().ToString("o")
            ProviderName      = $Event.ProviderName
            LogName           = $Event.LogName
            MachineName       = $Event.MachineName
            UserId            = if ($Event.UserId)     { $Event.UserId.Value }         else { $null }
            ProcessId         = $Event.ProcessId
            ThreadId          = $Event.ThreadId
            ActivityId        = if ($Event.ActivityId) { $Event.ActivityId.ToString() } else { $null }
            TaskDisplayName   = $Event.TaskDisplayName
            OpcodeDisplayName = $Event.OpcodeDisplayName
            Keywords          = $Event.KeywordsDisplayNames -join ", "
            Message           = $Event.Message
            Properties        = ($Event.Properties | ForEach-Object { $_.Value })
        }
        return $obj | ConvertTo-Json -Depth 5
    } catch {
        return "{`"error`": `"$($_.Exception.Message)`"}"
    }
}

# ==============================================================================
#  CORE: LOAD EVENTS
# ==============================================================================
function Load-Events {
    param(
        [string]$ComputerName = $env:COMPUTERNAME,
        [string]$LogName      = "System",
        [System.Management.Automation.PSCredential]$Credential = $null
    )
    $statusLabel.Text = "[...] Loading $ComputerName -> $LogName ..."
    $form.Refresh()

    try {
        # Plain hashtable required by Get-WinEvent -FilterHashtable
        $filter = @{ LogName = $LogName }
        if ($global:FilterCfg.StartTime) {
            $filter.StartTime = $global:FilterCfg.StartTime
        }
        if ($global:FilterCfg.EndTime) {
            $filter.EndTime = $global:FilterCfg.EndTime
        }
        if ($global:FilterCfg.EventIDs -and $global:FilterCfg.EventIDs.Count -gt 0) {
            $filter.Id = $global:FilterCfg.EventIDs
        }
        if ($global:FilterCfg.Levels -and
            $global:FilterCfg.Levels.Count -gt 0 -and
            $global:FilterCfg.Levels.Count -lt 5) {
            $filter.Level = $global:FilterCfg.Levels
        }

        $safeMax = if ($global:MaxEvents -ge 1) { $global:MaxEvents } else { 500 }

        $params = @{
            FilterHashtable = $filter
            MaxEvents       = $safeMax
            ErrorAction     = 'Stop'
        }
        $isLocal = ($ComputerName -eq $env:COMPUTERNAME -or
                    $ComputerName -eq "localhost"        -or
                    $ComputerName -eq ".")
        if (-not $isLocal) { $params.ComputerName = $ComputerName }
        if ($Credential)   { $params.Credential   = $Credential   }

        $loaded = Get-WinEvent @params
        $global:Events     = @($loaded)
        $global:CurrentLog = @{ ComputerName=$ComputerName; LogName=$LogName; Credential=$Credential }
        Update-EventGrid -Events $global:Events
        $statusLabel.Text   = "[OK] Loaded $($global:Events.Count) events -- $ComputerName / $LogName"
        $evtCountLabel.Text = "Events: $($global:Events.Count)"

    } catch [System.Exception] {
        $msg = $_.Exception.Message
        if ($msg -match "No events were found") {
            $global:Events      = @()
            Update-EventGrid -Events @()
            $statusLabel.Text   = "No events matched the filter criteria."
            $evtCountLabel.Text = "Events: 0"
        } else {
            $global:Events = @()
            Update-EventGrid -Events @()
            $statusLabel.Text = "[ERR] $msg"
            [Windows.Forms.MessageBox]::Show(
                "Failed to load events from '$ComputerName / $LogName':`n`n$msg",
                "Load Error", "OK", "Error")
        }
    }
}

function Update-EventGrid {
    param($Events)
    $dgv.SuspendLayout()
    $dgv.Rows.Clear()
    foreach ($evt in $Events) {
        $lvl = Get-LevelInfo $evt.Level
        $idx = $dgv.Rows.Add(
            "$($lvl.Symbol)  $($lvl.Name)",
            $evt.TimeCreated.ToString("yyyy-MM-dd  HH:mm:ss"),
            $evt.ProviderName,
            $evt.Id,
            $evt.TaskDisplayName,
            $evt.MachineName
        )
        $row = $dgv.Rows[$idx]
        $row.Tag = $evt
        $row.DefaultCellStyle.ForeColor = $lvl.Color
    }
    $dgv.ResumeLayout()
}

function Show-EventDetail {
    param($Event)
    $rawBox.Text  = Get-EventRawText    -Event $Event
    $jsonBox.Text = ConvertTo-EventJson -Event $Event
    try   { $xmlBox.Text = Format-Xml -Xml $Event.ToXml() }
    catch { $xmlBox.Text = $Event.ToXml() }
}

# ==============================================================================
#  DIALOG: ADD REMOTE HOST
#  NOTE: All Add_Click / Add_CheckedChanged handlers use .GetNewClosure()
#        so local variables remain valid after the function returns.
# ==============================================================================
function Show-AddHostDialog {
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text            = "Connect to Remote Host"
    $dlg.Size            = New-Object Drawing.Size(460, 340)
    $dlg.StartPosition   = "CenterParent"
    $dlg.FormBorderStyle = "FixedDialog"
    $dlg.MaximizeBox     = $false; $dlg.MinimizeBox = $false
    $dlg.BackColor       = $CLR.Panel
    $dlg.ForeColor       = $CLR.Text
    $dlg.Font            = $Fonts.UI

    function MkLbl($t,$x,$y) {
        $l = New-Object Windows.Forms.Label
        $l.Text = $t; $l.Location = New-Object Drawing.Point($x,$y)
        $l.AutoSize = $true; $l.ForeColor = $CLR.SubText
        return $l
    }
    function MkTxt($x,$y,$w) {
        $tb = New-Object Windows.Forms.TextBox
        $tb.Location = New-Object Drawing.Point($x,$y)
        $tb.Size     = New-Object Drawing.Size($w, 24)
        $tb.BackColor    = $CLR.Bg
        $tb.ForeColor    = $CLR.Text
        $tb.BorderStyle  = "FixedSingle"
        return $tb
    }

    $lbComp  = MkLbl "Computer Name / IP Address:"             16  18
    $tbComp  = MkTxt 16 40 410
    $lbUser  = MkLbl "Username  (DOMAIN\user  or  .\localuser):" 16 82
    $tbUser  = MkTxt 16 104 410
    $lbPass  = MkLbl "Password:"                                16 144
    $tbPass  = MkTxt 16 166 410
    $tbPass.UseSystemPasswordChar = $true

    $chkCurr = New-Object Windows.Forms.CheckBox
    $chkCurr.Text      = "Use current session credentials (skip explicit login)"
    $chkCurr.Location  = New-Object Drawing.Point(16, 206)
    $chkCurr.AutoSize  = $true
    $chkCurr.ForeColor = $CLR.SubText

    $btnConnect = New-Object Windows.Forms.Button
    $btnConnect.Text     = "Connect"
    $btnConnect.Size     = New-Object Drawing.Size(110, 30)
    $btnConnect.Location = New-Object Drawing.Point(228, 266)
    $btnConnect.FlatStyle = "Flat"
    $btnConnect.BackColor = $CLR.Accent
    $btnConnect.ForeColor = [Drawing.Color]::White
    $btnConnect.FlatAppearance.BorderSize = 0

    $btnCancel = New-Object Windows.Forms.Button
    $btnCancel.Text     = "Cancel"
    $btnCancel.Size     = New-Object Drawing.Size(90, 30)
    $btnCancel.Location = New-Object Drawing.Point(348, 266)
    $btnCancel.FlatStyle = "Flat"
    $btnCancel.BackColor = $CLR.Strip
    $btnCancel.ForeColor = $CLR.Text
    $btnCancel.FlatAppearance.BorderColor = $CLR.Border
    $btnCancel.DialogResult = [Windows.Forms.DialogResult]::Cancel

    # .GetNewClosure() captures $tbUser/$tbPass so they are valid after function returns
    $chkCurr.Add_CheckedChanged({
        $tbUser.Enabled = -not $chkCurr.Checked
        $tbPass.Enabled = -not $chkCurr.Checked
    }.GetNewClosure())

    $btnConnect.Add_Click({
        $compVal = $tbComp.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($compVal)) {
            [Windows.Forms.MessageBox]::Show(
                "Please enter a computer name or IP address.",
                "Validation", "OK", "Warning")
            return
        }
        $dlg.Tag = @{
            ComputerName          = $compVal
            UseCurrentCredentials = $chkCurr.Checked
            Username              = $tbUser.Text.Trim()
            Password              = $tbPass.Text
        }
        $dlg.DialogResult = [Windows.Forms.DialogResult]::OK
        $dlg.Close()
    }.GetNewClosure())

    $dlg.Controls.AddRange(@($lbComp,$tbComp,$lbUser,$tbUser,$lbPass,$tbPass,
                               $chkCurr,$btnConnect,$btnCancel))
    $dlg.AcceptButton = $btnConnect
    $dlg.CancelButton = $btnCancel
    return $dlg
}

# ==============================================================================
#  DIALOG: FILTER EVENTS
#  NOTE: All scriptblock handlers use .GetNewClosure()
# ==============================================================================
function Show-FilterDialog {
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text            = "Filter Events"
    $dlg.Size            = New-Object Drawing.Size(480, 440)
    $dlg.StartPosition   = "CenterParent"
    $dlg.FormBorderStyle = "FixedDialog"
    $dlg.MaximizeBox     = $false; $dlg.MinimizeBox = $false
    $dlg.BackColor       = $CLR.Panel
    $dlg.ForeColor       = $CLR.Text
    $dlg.Font            = $Fonts.UI

    # --- Level checkboxes ---
    $gbLvl = New-Object Windows.Forms.GroupBox
    $gbLvl.Text = "Event Levels"
    $gbLvl.Location = New-Object Drawing.Point(12, 10)
    $gbLvl.Size     = New-Object Drawing.Size(448, 75)
    $gbLvl.ForeColor = $CLR.SubText

    function MkChk($t, $x, $y, $fg, $lvlNum) {
        $ck = New-Object Windows.Forms.CheckBox
        $ck.Text     = $t
        $ck.Location = New-Object Drawing.Point($x, $y)
        $ck.AutoSize = $true
        $ck.ForeColor = $fg
        $ck.Checked  = $global:FilterCfg.Levels -contains $lvlNum
        return $ck
    }
    $chkCrit = MkChk "Critical (1)"    8   26 $CLR.Critical 1
    $chkErr  = MkChk "Error (2)"       108 26 $CLR.Err      2
    $chkWarn = MkChk "Warning (3)"     196 26 $CLR.Warning  3
    $chkInfo = MkChk "Information (4)" 292 26 $CLR.Info     4
    $chkVerb = MkChk "Verbose (5)"     8   50 $CLR.Verbose  5
    $gbLvl.Controls.AddRange(@($chkCrit,$chkErr,$chkWarn,$chkInfo,$chkVerb))

    # --- Date range ---
    $gbDate = New-Object Windows.Forms.GroupBox
    $gbDate.Text = "Date / Time Range"
    $gbDate.Location = New-Object Drawing.Point(12, 94)
    $gbDate.Size     = New-Object Drawing.Size(448, 96)
    $gbDate.ForeColor = $CLR.SubText

    $lblFrom = New-Object Windows.Forms.Label
    $lblFrom.Text = "From:"; $lblFrom.Location = New-Object Drawing.Point(8,30)
    $lblFrom.AutoSize = $true; $lblFrom.ForeColor = $CLR.SubText

    $dtFrom = New-Object Windows.Forms.DateTimePicker
    $dtFrom.Location = New-Object Drawing.Point(58, 27)
    $dtFrom.Size     = New-Object Drawing.Size(190, 24)
    $dtFrom.Format   = "Custom"; $dtFrom.CustomFormat = "yyyy-MM-dd  HH:mm:ss"
    $dtFrom.ShowCheckBox = $true; $dtFrom.Checked = $false

    $lblTo = New-Object Windows.Forms.Label
    $lblTo.Text = "To:"; $lblTo.Location = New-Object Drawing.Point(8, 62)
    $lblTo.AutoSize = $true; $lblTo.ForeColor = $CLR.SubText

    $dtTo = New-Object Windows.Forms.DateTimePicker
    $dtTo.Location = New-Object Drawing.Point(58, 59)
    $dtTo.Size     = New-Object Drawing.Size(190, 24)
    $dtTo.Format   = "Custom"; $dtTo.CustomFormat = "yyyy-MM-dd  HH:mm:ss"
    $dtTo.ShowCheckBox = $true; $dtTo.Checked = $false

    if ($global:FilterCfg.StartTime) { $dtFrom.Value = $global:FilterCfg.StartTime; $dtFrom.Checked = $true }
    if ($global:FilterCfg.EndTime)   { $dtTo.Value   = $global:FilterCfg.EndTime;   $dtTo.Checked   = $true }
    $gbDate.Controls.AddRange(@($lblFrom,$dtFrom,$lblTo,$dtTo))

    # --- Event IDs ---
    $gbIds = New-Object Windows.Forms.GroupBox
    $gbIds.Text = "Event IDs  (comma-separated, e.g.  4624, 4625, 7045)"
    $gbIds.Location = New-Object Drawing.Point(12, 200)
    $gbIds.Size     = New-Object Drawing.Size(448, 55)
    $gbIds.ForeColor = $CLR.SubText

    $tbIds = New-Object Windows.Forms.TextBox
    $tbIds.Location    = New-Object Drawing.Point(8, 22)
    $tbIds.Size        = New-Object Drawing.Size(424, 24)
    $tbIds.BackColor   = $CLR.Bg
    $tbIds.ForeColor   = $CLR.Text
    $tbIds.BorderStyle = "FixedSingle"
    if ($global:FilterCfg.EventIDs.Count -gt 0) {
        $tbIds.Text = $global:FilterCfg.EventIDs -join ", "
    }
    $gbIds.Controls.Add($tbIds)

    # --- Source ---
    $gbSrc = New-Object Windows.Forms.GroupBox
    $gbSrc.Text = "Source / Provider"
    $gbSrc.Location = New-Object Drawing.Point(12, 264)
    $gbSrc.Size     = New-Object Drawing.Size(222, 55)
    $gbSrc.ForeColor = $CLR.SubText

    $tbSrc = New-Object Windows.Forms.TextBox
    $tbSrc.Location    = New-Object Drawing.Point(8, 22)
    $tbSrc.Size        = New-Object Drawing.Size(198, 24)
    $tbSrc.BackColor   = $CLR.Bg
    $tbSrc.ForeColor   = $CLR.Text
    $tbSrc.BorderStyle = "FixedSingle"
    $tbSrc.Text        = $global:FilterCfg.Source
    $gbSrc.Controls.Add($tbSrc)

    # --- Max events ---
    $gbMax = New-Object Windows.Forms.GroupBox
    $gbMax.Text = "Max Events"
    $gbMax.Location = New-Object Drawing.Point(242, 264)
    $gbMax.Size     = New-Object Drawing.Size(218, 55)
    $gbMax.ForeColor = $CLR.SubText

    $nudMax = New-Object Windows.Forms.NumericUpDown
    $nudMax.Location = New-Object Drawing.Point(8, 22)
    $nudMax.Size     = New-Object Drawing.Size(194, 24)
    $nudMax.Minimum  = 10; $nudMax.Maximum = 50000
    $nudMax.Value    = if ($global:MaxEvents -ge 10) { $global:MaxEvents } else { 500 }
    $nudMax.BackColor = $CLR.Bg; $nudMax.ForeColor = $CLR.Text
    $gbMax.Controls.Add($nudMax)

    # --- Buttons ---
    $btnApply = New-Object Windows.Forms.Button
    $btnApply.Text     = "Apply Filter"
    $btnApply.Size     = New-Object Drawing.Size(120, 30)
    $btnApply.Location = New-Object Drawing.Point(200, 372)
    $btnApply.FlatStyle = "Flat"
    $btnApply.BackColor = $CLR.Accent
    $btnApply.ForeColor = [Drawing.Color]::White
    $btnApply.FlatAppearance.BorderSize = 0

    $btnReset = New-Object Windows.Forms.Button
    $btnReset.Text     = "Reset"
    $btnReset.Size     = New-Object Drawing.Size(90, 30)
    $btnReset.Location = New-Object Drawing.Point(330, 372)
    $btnReset.FlatStyle = "Flat"
    $btnReset.BackColor = $CLR.Strip
    $btnReset.ForeColor = $CLR.Text
    $btnReset.FlatAppearance.BorderColor = $CLR.Border

    $btnCancel2 = New-Object Windows.Forms.Button
    $btnCancel2.Text     = "Cancel"
    $btnCancel2.Size     = New-Object Drawing.Size(90, 30)
    $btnCancel2.Location = New-Object Drawing.Point(12, 372)
    $btnCancel2.FlatStyle = "Flat"
    $btnCancel2.BackColor = $CLR.Strip
    $btnCancel2.ForeColor = $CLR.Text
    $btnCancel2.FlatAppearance.BorderColor = $CLR.Border
    $btnCancel2.DialogResult = [Windows.Forms.DialogResult]::Cancel

    # .GetNewClosure() on BOTH handlers so local vars survive function return
    $btnReset.Add_Click({
        foreach ($chk in @($chkCrit,$chkErr,$chkWarn,$chkInfo,$chkVerb)) { $chk.Checked = $true }
        $dtFrom.Checked = $false; $dtTo.Checked = $false
        $tbIds.Text = ""; $tbSrc.Text = ""; $nudMax.Value = 500
    }.GetNewClosure())

    $btnApply.Add_Click({
        $lvls = @()
        if ($chkCrit.Checked) { $lvls += 1 }
        if ($chkErr.Checked)  { $lvls += 2 }
        if ($chkWarn.Checked) { $lvls += 3 }
        if ($chkInfo.Checked) { $lvls += 4 }
        if ($chkVerb.Checked) { $lvls += 5 }
        $global:FilterCfg.Levels    = $lvls
        $global:FilterCfg.StartTime = if ($dtFrom.Checked) { $dtFrom.Value } else { $null }
        $global:FilterCfg.EndTime   = if ($dtTo.Checked)   { $dtTo.Value   } else { $null }
        $global:FilterCfg.Source    = $tbSrc.Text.Trim()
        $v = [int]$nudMax.Value
        $global:MaxEvents = if ($v -ge 10) { $v } else { 500 }
        $global:FilterCfg.EventIDs  = if ($tbIds.Text.Trim()) {
            $tbIds.Text.Split(',') | ForEach-Object {
                $x = $_.Trim()
                if ($x -match '^\d+$') { [int]$x }
            }
        } else { @() }
        $dlg.DialogResult = [Windows.Forms.DialogResult]::OK
        $dlg.Close()
    }.GetNewClosure())

    $dlg.Controls.AddRange(@($gbLvl,$gbDate,$gbIds,$gbSrc,$gbMax,
                               $btnApply,$btnReset,$btnCancel2))
    $dlg.AcceptButton = $btnApply
    $dlg.CancelButton = $btnCancel2
    return $dlg
}

# ==============================================================================
#  MAIN FORM
# ==============================================================================
$form = New-Object Windows.Forms.Form
$form.Text          = "Windows Event Explorer"
$form.Size          = New-Object Drawing.Size(1440, 940)
$form.MinimumSize   = New-Object Drawing.Size(1050, 680)
$form.StartPosition = "CenterScreen"
$form.BackColor     = $CLR.Bg
$form.ForeColor     = $CLR.Text
$form.Font          = $Fonts.UI
$form.KeyPreview    = $true
try { $form.Icon = [Drawing.SystemIcons]::Shield } catch {}

# --- Menu ---
$menuStrip           = New-Object Windows.Forms.MenuStrip
$menuStrip.BackColor = $CLR.Strip
$menuStrip.ForeColor = $CLR.Text

$mnuFile      = New-Object Windows.Forms.ToolStripMenuItem("File")
$mnuAction    = New-Object Windows.Forms.ToolStripMenuItem("Action")
$mnuView      = New-Object Windows.Forms.ToolStripMenuItem("View")
$mnuHelp      = New-Object Windows.Forms.ToolStripMenuItem("Help")
$mnuExpCsv    = New-Object Windows.Forms.ToolStripMenuItem("Export to CSV...")
$mnuExpJson   = New-Object Windows.Forms.ToolStripMenuItem("Export to JSON...")
$mnuExpXml    = New-Object Windows.Forms.ToolStripMenuItem("Export Selected Event XML...")
$mnuExit      = New-Object Windows.Forms.ToolStripMenuItem("Exit")
$mnuRefresh   = New-Object Windows.Forms.ToolStripMenuItem("Refresh  [F5]")
$mnuAddHost   = New-Object Windows.Forms.ToolStripMenuItem("Add Remote Host...")
$mnuRemHost   = New-Object Windows.Forms.ToolStripMenuItem("Remove Selected Host")
$mnuFilter    = New-Object Windows.Forms.ToolStripMenuItem("Filter Events...")
$mnuClrFilter = New-Object Windows.Forms.ToolStripMenuItem("Clear Filter")
$mnuClrView   = New-Object Windows.Forms.ToolStripMenuItem("Clear View")
$mnuWrap      = New-Object Windows.Forms.ToolStripMenuItem("Toggle Word Wrap")
$mnuAbout     = New-Object Windows.Forms.ToolStripMenuItem("About")

$mnuFile.DropDownItems.AddRange(@(
    $mnuExpCsv, $mnuExpJson, $mnuExpXml,
    (New-Object Windows.Forms.ToolStripSeparator), $mnuExit))
$mnuAction.DropDownItems.AddRange(@(
    $mnuRefresh, $mnuAddHost, $mnuRemHost,
    (New-Object Windows.Forms.ToolStripSeparator),
    $mnuFilter, $mnuClrFilter, $mnuClrView))
$mnuView.DropDownItems.Add($mnuWrap)
$mnuHelp.DropDownItems.Add($mnuAbout)
$menuStrip.Items.AddRange(@($mnuFile,$mnuAction,$mnuView,$mnuHelp))

# --- ToolStrip ---
$toolStrip              = New-Object Windows.Forms.ToolStrip
$toolStrip.BackColor    = $CLR.Strip
$toolStrip.ForeColor    = $CLR.Text
$toolStrip.GripStyle    = [Windows.Forms.ToolStripGripStyle]::Hidden
$toolStrip.Padding      = New-Object Windows.Forms.Padding(6, 2, 6, 2)

function New-TsBtn($Text, $Tip) {
    $b = New-Object Windows.Forms.ToolStripButton
    $b.Text = $Text; $b.ToolTipText = $Tip
    $b.DisplayStyle = [Windows.Forms.ToolStripItemDisplayStyle]::Text
    $b.ForeColor = $CLR.Text
    $b.Padding   = New-Object Windows.Forms.Padding(8, 0, 8, 0)
    $b.AutoSize  = $true
    return $b
}
function New-TsSep { return New-Object Windows.Forms.ToolStripSeparator }

$tsBtnRefresh = New-TsBtn "Refresh [F5]"   "Reload current log"
$tsBtnAddHost = New-TsBtn "+ Add Host"     "Connect to remote host"
$tsBtnRemHost = New-TsBtn "X Remove Host"  "Remove selected remote host"
$tsBtnFilter  = New-TsBtn "Filter..."      "Open filter dialog"
$tsBtnClrFlt  = New-TsBtn "Clear Filter"   "Clear all filters"
$tsBtnExpCsv  = New-TsBtn "Export CSV"     "Export events to CSV"
$tsBtnExpJson = New-TsBtn "Export JSON"    "Export events to JSON"

$tsLblSearch = New-Object Windows.Forms.ToolStripLabel
$tsLblSearch.Text = "   Search:"; $tsLblSearch.ForeColor = $CLR.SubText

$tsTbSearch = New-Object Windows.Forms.ToolStripTextBox
$tsTbSearch.Size = New-Object Drawing.Size(200, 24)
$tsTbSearch.BackColor = $CLR.Bg; $tsTbSearch.ForeColor = $CLR.Text
$tsTbSearch.ToolTipText = "Enter=apply  Esc=clear"

$tsLblMax = New-Object Windows.Forms.ToolStripLabel
$tsLblMax.Text = "   Max:"; $tsLblMax.ForeColor = $CLR.SubText

$tsCboMax = New-Object Windows.Forms.ToolStripComboBox
@("100","250","500","1000","2500","5000") | ForEach-Object { [void]$tsCboMax.Items.Add($_) }
$tsCboMax.SelectedItem = "500"
$tsCboMax.BackColor = $CLR.Bg; $tsCboMax.ForeColor = $CLR.Text

$toolStrip.Items.AddRange(@(
    $tsBtnRefresh,(New-TsSep),$tsBtnAddHost,$tsBtnRemHost,(New-TsSep),
    $tsBtnFilter,$tsBtnClrFlt,(New-TsSep),
    $tsBtnExpCsv,$tsBtnExpJson,(New-TsSep),
    $tsLblSearch,$tsTbSearch,$tsLblMax,$tsCboMax))

# --- Main splitter: left tree | right panels ---
$splitMain = New-Object Windows.Forms.SplitContainer
$splitMain.Dock             = [Windows.Forms.DockStyle]::Fill
$splitMain.Orientation      = [Windows.Forms.Orientation]::Vertical
$splitMain.SplitterDistance = 288   # overridden in Add_Shown to 20%
$splitMain.SplitterWidth    = 5
$splitMain.BackColor        = $CLR.Border
$splitMain.Panel1.BackColor = $CLR.Panel
$splitMain.Panel2.BackColor = $CLR.Bg

# --- Left: TreeView ---
$treeHeader           = New-Object Windows.Forms.Panel
$treeHeader.Dock      = [Windows.Forms.DockStyle]::Top
$treeHeader.Height    = 32
$treeHeader.BackColor = $CLR.Strip

$lblTree           = New-Object Windows.Forms.Label
$lblTree.Text      = "  EVENT SOURCES"
$lblTree.Dock      = [Windows.Forms.DockStyle]::Fill
$lblTree.Font      = $Fonts.Small
$lblTree.ForeColor = $CLR.SubText
$lblTree.TextAlign = [Drawing.ContentAlignment]::MiddleLeft
$treeHeader.Controls.Add($lblTree)

$treeView               = New-Object Windows.Forms.TreeView
$treeView.Dock          = [Windows.Forms.DockStyle]::Fill
$treeView.BackColor     = $CLR.Panel
$treeView.ForeColor     = $CLR.Text
$treeView.Font          = $Fonts.UI
$treeView.BorderStyle   = [Windows.Forms.BorderStyle]::None
$treeView.HideSelection = $false
$treeView.ShowLines     = $true
$treeView.ShowPlusMinus = $true
$treeView.FullRowSelect = $true
$treeView.DrawMode      = [Windows.Forms.TreeViewDrawMode]::OwnerDrawText

$treeView.Add_DrawNode({
    param($s,$e)
    $nd = $e.Node
    $bg = if ($nd.IsSelected) { $CLR.RowSel } else { $CLR.Panel }
    $fg = if ($nd.IsSelected) { [Drawing.Color]::White } `
          elseif ($nd.Tag -eq "category") { $CLR.SubText } `
          else { $CLR.Text }
    $e.Graphics.FillRectangle((New-Object Drawing.SolidBrush($bg)), $e.Bounds)
    $r = $e.Bounds; $r.X += 2
    [Windows.Forms.TextRenderer]::DrawText($e.Graphics, $nd.Text, $treeView.Font, $r, $fg,
        [Windows.Forms.TextFormatFlags]::Left -bor
        [Windows.Forms.TextFormatFlags]::VerticalCenter)
})

function Add-HostLogNodes {
    param($HostNode, $ComputerName, $Credential)
    $HostNode.Nodes.Clear()

    $winNode = $HostNode.Nodes.Add("  Windows Logs")
    $winNode.Tag = "category"
    foreach ($log in @("Application","Security","System","Setup","Forwarded Events")) {
        $n = $winNode.Nodes.Add("    $log")
        $n.Tag = [PSCustomObject]@{ ComputerName=$ComputerName; LogName=$log; Credential=$Credential }
    }
    $winNode.Expand()

    $svcNode = $HostNode.Nodes.Add("  Applications and Services Logs")
    $svcNode.Tag = "category"
    $svcLogs = @(
        @{ D="PowerShell/Operational";           L="Microsoft-Windows-PowerShell/Operational"                           }
        @{ D="TaskScheduler/Operational";        L="Microsoft-Windows-TaskScheduler/Operational"                        }
        @{ D="WinRM/Operational";                L="Microsoft-Windows-WinRM/Operational"                                }
        @{ D="Defender/Operational";             L="Microsoft-Windows-Windows Defender/Operational"                     }
        @{ D="Sysmon/Operational";               L="Microsoft-Windows-Sysmon/Operational"                              }
        @{ D="RDP-CoreTS/Operational";           L="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational"      }
        @{ D="TerminalServices-LocalSessionMgr"; L="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" }
        @{ D="AppLocker/EXE and DLL";            L="Microsoft-Windows-AppLocker/EXE and DLL"                           }
    )
    foreach ($sl in $svcLogs) {
        $n = $svcNode.Nodes.Add("    $($sl.D)")
        $n.Tag = [PSCustomObject]@{ ComputerName=$ComputerName; LogName=$sl.L; Credential=$Credential }
    }
}

$localNode = $treeView.Nodes.Add("  $($env:COMPUTERNAME)  [Local]")
$localNode.Tag = "host"
Add-HostLogNodes -HostNode $localNode -ComputerName $env:COMPUTERNAME -Credential $null
$localNode.Expand()

$remoteRoot = $treeView.Nodes.Add("  Remote Computers")
$remoteRoot.Tag = "remote_root"

$splitMain.Panel1.Controls.Add($treeView)
$splitMain.Panel1.Controls.Add($treeHeader)

# --- Right splitter: top grid | bottom detail ---
$splitRight = New-Object Windows.Forms.SplitContainer
$splitRight.Dock             = [Windows.Forms.DockStyle]::Fill
$splitRight.Orientation      = [Windows.Forms.Orientation]::Horizontal
$splitRight.SplitterDistance = 430
$splitRight.SplitterWidth    = 5
$splitRight.BackColor        = $CLR.Border
$splitRight.Panel1.BackColor = $CLR.Bg
$splitRight.Panel2.BackColor = $CLR.Panel

# --- Grid header ---
$gridHeader           = New-Object Windows.Forms.Panel
$gridHeader.Dock      = [Windows.Forms.DockStyle]::Top
$gridHeader.Height    = 28
$gridHeader.BackColor = $CLR.Strip

$lblGrid           = New-Object Windows.Forms.Label
$lblGrid.Text      = "  EVENT LOG ENTRIES"
$lblGrid.Dock      = [Windows.Forms.DockStyle]::Fill
$lblGrid.Font      = $Fonts.Small
$lblGrid.ForeColor = $CLR.SubText
$lblGrid.TextAlign = [Drawing.ContentAlignment]::MiddleLeft
$gridHeader.Controls.Add($lblGrid)

# --- DataGridView ---
$dgv = New-Object Windows.Forms.DataGridView
$dgv.Dock          = [Windows.Forms.DockStyle]::Fill
$dgv.BackgroundColor = $CLR.Grid
$dgv.GridColor     = $CLR.Border
$dgv.DefaultCellStyle.BackColor          = $CLR.Grid
$dgv.DefaultCellStyle.ForeColor          = $CLR.Text
$dgv.DefaultCellStyle.Font               = $Fonts.UI
$dgv.DefaultCellStyle.SelectionBackColor = $CLR.RowSel
$dgv.DefaultCellStyle.SelectionForeColor = [Drawing.Color]::White
$dgv.AlternatingRowsDefaultCellStyle.BackColor        = $CLR.GridAlt
$dgv.ColumnHeadersDefaultCellStyle.BackColor          = $CLR.GridHdr
$dgv.ColumnHeadersDefaultCellStyle.ForeColor          = $CLR.Text
$dgv.ColumnHeadersDefaultCellStyle.Font               = $Fonts.UIBold
$dgv.ColumnHeadersDefaultCellStyle.SelectionBackColor = $CLR.GridHdr
$dgv.ColumnHeadersBorderStyle     = [Windows.Forms.DataGridViewHeaderBorderStyle]::Single
$dgv.ColumnHeadersHeight          = 32
$dgv.ColumnHeadersHeightSizeMode  = [Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
$dgv.RowHeadersVisible            = $false
$dgv.SelectionMode                = [Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$dgv.MultiSelect                  = $false
$dgv.ReadOnly                     = $true
$dgv.AllowUserToAddRows           = $false
$dgv.AllowUserToDeleteRows        = $false
$dgv.AllowUserToResizeRows        = $false
$dgv.BorderStyle                  = [Windows.Forms.BorderStyle]::None
$dgv.CellBorderStyle              = [Windows.Forms.DataGridViewCellBorderStyle]::SingleHorizontal
$dgv.EnableHeadersVisualStyles    = $false
$dgv.ScrollBars                   = [Windows.Forms.ScrollBars]::Both
$dgv.RowTemplate.Height           = 25

foreach ($cd in @(
    @{ N="ColLevel";    H="Level";         W=130; F=$false }
    @{ N="ColDateTime"; H="Date / Time";   W=178; F=$false }
    @{ N="ColSource";   H="Source";        W=50;  F=$true  }
    @{ N="ColEventID";  H="Event ID";      W=82;  F=$false }
    @{ N="ColTask";     H="Task Category"; W=160; F=$false }
    @{ N="ColComputer"; H="Computer";      W=145; F=$false }
)) {
    $col = New-Object Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $cd.N; $col.HeaderText = $cd.H; $col.Width = $cd.W
    $col.SortMode = [Windows.Forms.DataGridViewColumnSortMode]::Automatic
    if ($cd.F) { $col.AutoSizeMode = [Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill }
    [void]$dgv.Columns.Add($col)
}

$splitRight.Panel1.Controls.Add($dgv)
$splitRight.Panel1.Controls.Add($gridHeader)

# --- Content tabs ---
$contentHeader           = New-Object Windows.Forms.Panel
$contentHeader.Dock      = [Windows.Forms.DockStyle]::Top
$contentHeader.Height    = 28
$contentHeader.BackColor = $CLR.Strip

$lblContent           = New-Object Windows.Forms.Label
$lblContent.Text      = "  EVENT DETAILS"
$lblContent.Dock      = [Windows.Forms.DockStyle]::Fill
$lblContent.Font      = $Fonts.Small
$lblContent.ForeColor = $CLR.SubText
$lblContent.TextAlign = [Drawing.ContentAlignment]::MiddleLeft
$contentHeader.Controls.Add($lblContent)

$tabContent          = New-Object Windows.Forms.TabControl
$tabContent.Dock     = [Windows.Forms.DockStyle]::Fill
$tabContent.Font     = $Fonts.UI
$tabContent.Padding  = New-Object Drawing.Point(14, 5)
$tabContent.DrawMode = [Windows.Forms.TabDrawMode]::OwnerDrawFixed
$tabContent.ItemSize = New-Object Drawing.Size(110, 26)

$tabContent.Add_DrawItem({
    param($s,$e)
    $pg = $tabContent.TabPages[$e.Index]
    $bg = if ($e.Index -eq $tabContent.SelectedIndex) { $CLR.Bg } else { $CLR.Strip }
    $fg = if ($e.Index -eq $tabContent.SelectedIndex) { $CLR.Text } else { $CLR.SubText }
    $e.Graphics.FillRectangle((New-Object Drawing.SolidBrush($bg)), $e.Bounds)
    [Windows.Forms.TextRenderer]::DrawText($e.Graphics, $pg.Text, $Fonts.UI, $e.Bounds, $fg,
        [Windows.Forms.TextFormatFlags]::HorizontalCenter -bor
        [Windows.Forms.TextFormatFlags]::VerticalCenter)
})

function New-ContentBox {
    $tb = New-Object Windows.Forms.RichTextBox
    $tb.Dock        = [Windows.Forms.DockStyle]::Fill
    $tb.BackColor   = $CLR.Bg
    $tb.ForeColor   = $CLR.Text
    $tb.Font        = $Fonts.Mono
    $tb.ReadOnly    = $true
    $tb.BorderStyle = [Windows.Forms.BorderStyle]::None
    $tb.ScrollBars  = [Windows.Forms.RichTextBoxScrollBars]::Both
    $tb.WordWrap    = $false
    return $tb
}

$tabGeneral = New-Object Windows.Forms.TabPage; $tabGeneral.Text = "  General"; $tabGeneral.BackColor = $CLR.Bg; $tabGeneral.Padding = New-Object Windows.Forms.Padding(0)
$tabJson    = New-Object Windows.Forms.TabPage; $tabJson.Text    = "  JSON";    $tabJson.BackColor    = $CLR.Bg; $tabJson.Padding    = New-Object Windows.Forms.Padding(0)
$tabXml     = New-Object Windows.Forms.TabPage; $tabXml.Text     = "  XML";     $tabXml.BackColor     = $CLR.Bg; $tabXml.Padding     = New-Object Windows.Forms.Padding(0)

$rawBox  = New-ContentBox
$jsonBox = New-ContentBox
$xmlBox  = New-ContentBox

$tabGeneral.Controls.Add($rawBox)
$tabJson.Controls.Add($jsonBox)
$tabXml.Controls.Add($xmlBox)
$tabContent.TabPages.AddRange(@($tabGeneral,$tabJson,$tabXml))

$splitRight.Panel2.Controls.Add($tabContent)
$splitRight.Panel2.Controls.Add($contentHeader)
$splitMain.Panel2.Controls.Add($splitRight)

# --- Status bar ---
$statusStrip           = New-Object Windows.Forms.StatusStrip
$statusStrip.BackColor = $CLR.Strip
$statusStrip.ForeColor = $CLR.Text
$statusStrip.SizingGrip = $true

$statusLabel = New-Object Windows.Forms.ToolStripStatusLabel
$statusLabel.Text      = "Ready -- Select a log from the left panel to load events."
$statusLabel.Spring    = $true
$statusLabel.TextAlign = [Drawing.ContentAlignment]::MiddleLeft
$statusLabel.ForeColor = $CLR.SubText

$evtCountLabel = New-Object Windows.Forms.ToolStripStatusLabel
$evtCountLabel.Text        = "Events: 0"
$evtCountLabel.ForeColor   = $CLR.Info
$evtCountLabel.BorderSides = [Windows.Forms.ToolStripStatusLabelBorderSides]::Left
$evtCountLabel.Padding     = New-Object Windows.Forms.Padding(10, 0, 10, 0)

$filterLabel = New-Object Windows.Forms.ToolStripStatusLabel
$filterLabel.Text        = "No Filter"
$filterLabel.ForeColor   = $CLR.SubText
$filterLabel.BorderSides = [Windows.Forms.ToolStripStatusLabelBorderSides]::Left
$filterLabel.Padding     = New-Object Windows.Forms.Padding(10, 0, 10, 0)

$hostLabel = New-Object Windows.Forms.ToolStripStatusLabel
$hostLabel.Text        = "Local"
$hostLabel.ForeColor   = $CLR.Success
$hostLabel.BorderSides = [Windows.Forms.ToolStripStatusLabelBorderSides]::Left
$hostLabel.Padding     = New-Object Windows.Forms.Padding(10, 0, 10, 0)

$statusStrip.Items.AddRange(@($statusLabel,$evtCountLabel,$filterLabel,$hostLabel))

# --- Assemble form ---
$form.Controls.Add($splitMain)
$form.Controls.Add($toolStrip)
$form.Controls.Add($menuStrip)
$form.Controls.Add($statusStrip)
$form.MainMenuStrip = $menuStrip

# --- Context menu ---
$ctxGrid = New-Object Windows.Forms.ContextMenuStrip
$ctxGrid.BackColor = $CLR.Panel; $ctxGrid.ForeColor = $CLR.Text; $ctxGrid.Font = $Fonts.UI

function New-CtxItem($Text) {
    $i = New-Object Windows.Forms.ToolStripMenuItem($Text)
    $i.BackColor = $CLR.Panel; $i.ForeColor = $CLR.Text; return $i
}
$ctxCopyRaw  = New-CtxItem "Copy General / Raw Text"
$ctxCopyJson = New-CtxItem "Copy JSON"
$ctxCopyXml  = New-CtxItem "Copy XML"
$ctxCopyId   = New-CtxItem "Copy Event ID"
$ctxFltById  = New-CtxItem "Filter by this Event ID"
$ctxFltBySrc = New-CtxItem "Filter by this Source"
$ctxOpenXml  = New-CtxItem "View Full XML in Notepad"

$ctxGrid.Items.AddRange(@(
    $ctxCopyRaw, $ctxCopyJson, $ctxCopyXml, $ctxCopyId,
    (New-Object Windows.Forms.ToolStripSeparator),
    $ctxFltById, $ctxFltBySrc,
    (New-Object Windows.Forms.ToolStripSeparator),
    $ctxOpenXml))
$dgv.ContextMenuStrip = $ctxGrid

# ==============================================================================
#  EVENT HANDLERS
# ==============================================================================

# 20% splitter on first show and every resize
function Set-SplitterTo20 {
    $newDist = [int]($form.ClientSize.Width * 0.20)
    $minOk   = $newDist -ge $splitMain.Panel1MinSize
    $maxOk   = $newDist -le ($splitMain.Width - $splitMain.Panel2MinSize - $splitMain.SplitterWidth)
    if ($minOk -and $maxOk) { $splitMain.SplitterDistance = $newDist }
}
$form.Add_Shown({  Set-SplitterTo20 })
$form.Add_Resize({ Set-SplitterTo20 })

# TreeView click
$treeView.Add_NodeMouseClick({
    param($s,$e)
    $nd = $e.Node
    if ($nd.Tag -and $nd.Tag -is [PSCustomObject] -and
        $nd.Tag.PSObject.Properties.Name -contains 'LogName') {
        $ctx = $nd.Tag
        $hostLabel.Text = if ($ctx.ComputerName -eq $env:COMPUTERNAME) { "Local" } else { $ctx.ComputerName }
        Load-Events -ComputerName $ctx.ComputerName -LogName $ctx.LogName -Credential $ctx.Credential
    }
})

# Grid selection
$dgv.Add_SelectionChanged({
    if ($dgv.SelectedRows.Count -gt 0) {
        $evt = $dgv.SelectedRows[0].Tag
        if ($evt) { Show-EventDetail -Event $evt }
    }
})

# Grid double-click -> copy raw
$dgv.Add_CellDoubleClick({
    param($s,$e)
    if ($e.RowIndex -ge 0 -and $dgv.Rows[$e.RowIndex].Tag -and $rawBox.Text) {
        [Windows.Forms.Clipboard]::SetText($rawBox.Text)
        $statusLabel.Text = "Event detail copied to clipboard."
    }
})

# Search
$tsTbSearch.Add_KeyUp({
    param($s,$e)
    if ($e.KeyCode -eq [Windows.Forms.Keys]::Return) {
        $q = $tsTbSearch.Text.Trim().ToLower()
        if ($q -eq "") {
            foreach ($row in $dgv.Rows) { $row.Visible = $true }
            $statusLabel.Text = "Search cleared."; return
        }
        $shown = 0
        foreach ($row in $dgv.Rows) {
            $hit = $false
            foreach ($cell in $row.Cells) {
                if ($cell.Value -and $cell.Value.ToString().ToLower().Contains($q)) {
                    $hit = $true; break
                }
            }
            $row.Visible = $hit
            if ($hit) { $shown++ }
        }
        $statusLabel.Text = "Search '$q': $shown rows visible."
    }
    if ($e.KeyCode -eq [Windows.Forms.Keys]::Escape) {
        $tsTbSearch.Text = ""
        foreach ($row in $dgv.Rows) { $row.Visible = $true }
        $statusLabel.Text = "Search cleared."
    }
})

# Max events combo (null-guarded)
$tsCboMax.Add_SelectedIndexChanged({
    $val = "$($tsCboMax.SelectedItem)"
    if ($val -match '^\d+$') {
        $v = [int]$val
        if ($v -ge 1) { $global:MaxEvents = $v }
    }
})

# Refresh
$tsBtnRefresh.Add_Click({
    if ($global:CurrentLog.Count -gt 0 -and $global:CurrentLog.LogName) {
        Load-Events -ComputerName $global:CurrentLog.ComputerName `
                    -LogName      $global:CurrentLog.LogName `
                    -Credential   $global:CurrentLog.Credential
    } else { $statusLabel.Text = "Select a log first." }
})

# Add remote host
$tsBtnAddHost.Add_Click({
    $dlg = Show-AddHostDialog
    if ($dlg.ShowDialog($form) -ne [Windows.Forms.DialogResult]::OK) { return }
    $cfg  = $dlg.Tag
    $cred = $null
    if (-not $cfg.UseCurrentCredentials -and -not [string]::IsNullOrWhiteSpace($cfg.Username)) {
        try {
            $secPwd = ConvertTo-SecureString $cfg.Password -AsPlainText -Force
            $cred   = New-Object System.Management.Automation.PSCredential($cfg.Username, $secPwd)
        } catch {
            [Windows.Forms.MessageBox]::Show("Credential error: $_","Error","OK","Error"); return
        }
    }
    $statusLabel.Text = "[...] Testing connection to $($cfg.ComputerName)..."
    $form.Refresh()
    try {
        $p = @{ LogName="System"; MaxEvents=1; ErrorAction="Stop"; ComputerName=$cfg.ComputerName }
        if ($cred) { $p.Credential = $cred }
        Get-WinEvent @p | Out-Null
        $global:Hosts[$cfg.ComputerName] = @{ Credential=$cred; Connected=$true }
        $hn = $remoteRoot.Nodes.Add("  $($cfg.ComputerName)  [Remote]")
        $hn.Tag = "host"
        Add-HostLogNodes -HostNode $hn -ComputerName $cfg.ComputerName -Credential $cred
        $remoteRoot.Expand(); $hn.Expand()
        $treeView.SelectedNode = $hn
        $statusLabel.Text = "[OK] Connected to $($cfg.ComputerName)"
    } catch {
        $statusLabel.Text = "[ERR] Cannot connect to $($cfg.ComputerName)"
        [Windows.Forms.MessageBox]::Show(
            "Cannot connect to '$($cfg.ComputerName)':`n`n$($_.Exception.Message)",
            "Connection Failed","OK","Error")
    }
})

# Remove host
$tsBtnRemHost.Add_Click({
    $sel = $treeView.SelectedNode
    if (-not $sel) { $statusLabel.Text = "Select a remote host node."; return }
    $target = $sel
    while ($target.Parent -and $target.Parent -ne $remoteRoot) { $target = $target.Parent }
    if ($target.Parent -and $target.Parent -eq $remoteRoot) {
        $ans = [Windows.Forms.MessageBox]::Show(
            "Remove '$($target.Text.Trim())'?","Confirm","YesNo","Question")
        if ($ans -eq "Yes") {
            $key = $target.Text.Trim() -replace '\s*\[Remote\]\s*',''
            $global:Hosts.Remove($key)
            $remoteRoot.Nodes.Remove($target)
            $statusLabel.Text = "Host removed."
            $dgv.Rows.Clear(); $rawBox.Clear(); $jsonBox.Clear(); $xmlBox.Clear()
        }
    } else { $statusLabel.Text = "Select a remote host node to remove." }
})

# Filter
$tsBtnFilter.Add_Click({
    $dlg = Show-FilterDialog
    if ($dlg.ShowDialog($form) -eq [Windows.Forms.DialogResult]::OK) {
        $parts    = @()
        $lvlNames = @{1="Crit";2="Err";3="Warn";4="Info";5="Verb"}
        if ($global:FilterCfg.Levels.Count -lt 5) {
            $parts += "Levels:" + (($global:FilterCfg.Levels | ForEach-Object { $lvlNames[$_] }) -join ",")
        }
        if ($global:FilterCfg.EventIDs.Count -gt 0) { $parts += "IDs:"  + ($global:FilterCfg.EventIDs -join ",") }
        if ($global:FilterCfg.StartTime) { $parts += "From:" + $global:FilterCfg.StartTime.ToString("MM/dd HH:mm") }
        if ($global:FilterCfg.EndTime)   { $parts += "To:"   + $global:FilterCfg.EndTime.ToString("MM/dd HH:mm")   }
        $filterLabel.Text      = if ($parts.Count -gt 0) { "Filter: " + ($parts -join "  ") } else { "Filter Active" }
        $filterLabel.ForeColor = $CLR.Warning
        if ($global:CurrentLog.Count -gt 0 -and $global:CurrentLog.LogName) {
            Load-Events -ComputerName $global:CurrentLog.ComputerName `
                        -LogName      $global:CurrentLog.LogName `
                        -Credential   $global:CurrentLog.Credential
        }
    }
})

# Clear filter
$tsBtnClrFlt.Add_Click({
    $global:FilterCfg = @{ Levels=@(1,2,3,4,5); StartTime=$null; EndTime=$null; EventIDs=@(); Source="" }
    $filterLabel.Text = "No Filter"; $filterLabel.ForeColor = $CLR.SubText
    if ($global:CurrentLog.Count -gt 0 -and $global:CurrentLog.LogName) {
        Load-Events -ComputerName $global:CurrentLog.ComputerName `
                    -LogName      $global:CurrentLog.LogName `
                    -Credential   $global:CurrentLog.Credential
    }
})

# Export CSV
$tsBtnExpCsv.Add_Click({
    if ($global:Events.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show("No events loaded.","Info","OK","Information"); return
    }
    $sfd = New-Object Windows.Forms.SaveFileDialog
    $sfd.Filter   = "CSV Files (*.csv)|*.csv"
    $sfd.FileName = "Events_$($global:CurrentLog.LogName -replace '[\/\\]','_')_$(Get-Date -f 'yyyyMMdd_HHmmss').csv"
    if ($sfd.ShowDialog() -eq "OK") {
        $global:Events | Select-Object Id, Level, TimeCreated, ProviderName, LogName, MachineName,
            @{N="TaskCategory";E={$_.TaskDisplayName}},
            @{N="Message";     E={($_.Message -replace "`r`n"," ") -replace "`n"," "}} |
            Export-Csv $sfd.FileName -NoTypeInformation -Encoding UTF8
        $statusLabel.Text = "[OK] Exported $($global:Events.Count) events -> $($sfd.FileName)"
    }
})

# Export JSON
$tsBtnExpJson.Add_Click({
    if ($global:Events.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show("No events loaded.","Info","OK","Information"); return
    }
    $sfd = New-Object Windows.Forms.SaveFileDialog
    $sfd.Filter   = "JSON Files (*.json)|*.json"
    $sfd.FileName = "Events_$($global:CurrentLog.LogName -replace '[\/\\]','_')_$(Get-Date -f 'yyyyMMdd_HHmmss').json"
    if ($sfd.ShowDialog() -eq "OK") {
        $export = $global:Events | ForEach-Object {
            [ordered]@{
                EventId      = $_.Id
                Level        = (Get-LevelInfo $_.Level).Name
                LevelCode    = $_.Level
                TimeCreated  = $_.TimeCreated.ToString("o")
                Source       = $_.ProviderName
                LogName      = $_.LogName
                Computer     = $_.MachineName
                TaskCategory = $_.TaskDisplayName
                Message      = $_.Message
                Properties   = ($_.Properties | ForEach-Object { $_.Value })
            }
        }
        $export | ConvertTo-Json -Depth 5 | Out-File $sfd.FileName -Encoding UTF8
        $statusLabel.Text = "[OK] Exported $($global:Events.Count) events -> $($sfd.FileName)"
    }
})

# Context menu handlers
$ctxCopyRaw.Add_Click({
    if ($rawBox.Text)  { [Windows.Forms.Clipboard]::SetText($rawBox.Text);  $statusLabel.Text = "Copied raw text." }
})
$ctxCopyJson.Add_Click({
    if ($jsonBox.Text) { [Windows.Forms.Clipboard]::SetText($jsonBox.Text); $statusLabel.Text = "Copied JSON." }
})
$ctxCopyXml.Add_Click({
    if ($xmlBox.Text)  { [Windows.Forms.Clipboard]::SetText($xmlBox.Text);  $statusLabel.Text = "Copied XML." }
})
$ctxCopyId.Add_Click({
    if ($dgv.SelectedRows.Count -gt 0 -and $dgv.SelectedRows[0].Tag) {
        [Windows.Forms.Clipboard]::SetText($dgv.SelectedRows[0].Tag.Id.ToString())
        $statusLabel.Text = "Copied Event ID."
    }
})
$ctxFltById.Add_Click({
    if ($dgv.SelectedRows.Count -gt 0 -and $dgv.SelectedRows[0].Tag) {
        $id = $dgv.SelectedRows[0].Tag.Id
        $global:FilterCfg.EventIDs = @($id)
        $filterLabel.Text = "Filter: ID=$id"; $filterLabel.ForeColor = $CLR.Warning
        if ($global:CurrentLog.LogName) {
            Load-Events -ComputerName $global:CurrentLog.ComputerName `
                        -LogName      $global:CurrentLog.LogName `
                        -Credential   $global:CurrentLog.Credential
        }
    }
})
$ctxFltBySrc.Add_Click({
    if ($dgv.SelectedRows.Count -gt 0 -and $dgv.SelectedRows[0].Tag) {
        $src = $dgv.SelectedRows[0].Tag.ProviderName
        foreach ($row in $dgv.Rows) { $row.Visible = ($row.Cells["ColSource"].Value -eq $src) }
        $filterLabel.Text = "In-grid: Source=$src"; $filterLabel.ForeColor = $CLR.Warning
        $statusLabel.Text = "Filtered grid: Source = $src"
    }
})
$ctxOpenXml.Add_Click({
    if ($xmlBox.Text) {
        $tmp = [System.IO.Path]::GetTempFileName() + ".xml"
        $xmlBox.Text | Out-File $tmp -Encoding UTF8
        Start-Process notepad.exe $tmp
    }
})

# Menu wiring
$mnuRefresh.Add_Click({   $tsBtnRefresh.PerformClick() })
$mnuAddHost.Add_Click({   $tsBtnAddHost.PerformClick() })
$mnuRemHost.Add_Click({   $tsBtnRemHost.PerformClick() })
$mnuFilter.Add_Click({    $tsBtnFilter.PerformClick()  })
$mnuClrFilter.Add_Click({ $tsBtnClrFlt.PerformClick()  })
$mnuExpCsv.Add_Click({    $tsBtnExpCsv.PerformClick()  })
$mnuExpJson.Add_Click({   $tsBtnExpJson.PerformClick() })
$mnuExpXml.Add_Click({
    if ($dgv.SelectedRows.Count -gt 0 -and $dgv.SelectedRows[0].Tag) { $ctxOpenXml.PerformClick() }
})
$mnuClrView.Add_Click({
    $dgv.Rows.Clear(); $rawBox.Clear(); $jsonBox.Clear(); $xmlBox.Clear()
    $global:Events = @(); $evtCountLabel.Text = "Events: 0"
    $statusLabel.Text = "View cleared."
})
$mnuWrap.Add_Click({
    $rawBox.WordWrap  = -not $rawBox.WordWrap
    $jsonBox.WordWrap = $rawBox.WordWrap
    $xmlBox.WordWrap  = $rawBox.WordWrap
    $mnuWrap.Checked  = $rawBox.WordWrap
    $statusLabel.Text = "Word wrap: $($rawBox.WordWrap)"
})
$mnuExit.Add_Click({ $form.Close() })
$mnuAbout.Add_Click({
    [Windows.Forms.MessageBox]::Show(
        "Windows Event Explorer  v1.2`n" +
        "PowerShell WinForms GUI`n`n" +
        "Features:`n" +
        "  - Local and remote event log collection`n" +
        "  - PSCredential support for remote hosts`n" +
        "  - Multi-log tree (Windows + App/Services logs)`n" +
        "  - Level / Date / EventID / Source filter`n" +
        "  - General / JSON / XML detail views`n" +
        "  - Grid search, context menu, CSV/JSON export`n`n" +
        "Requires: PowerShell 5.1+`n" +
        "Run as Administrator for Security log access.",
        "About -- Windows Event Explorer",
        [Windows.Forms.MessageBoxButtons]::OK,
        [Windows.Forms.MessageBoxIcon]::Information)
})

# Keyboard shortcuts
$form.Add_KeyDown({
    param($s,$e)
    if ($e.KeyCode -eq [Windows.Forms.Keys]::F5)                                      { $tsBtnRefresh.PerformClick() }
    if ($e.Control -and $e.KeyCode -eq [Windows.Forms.Keys]::F)                       { $tsTbSearch.Focus() }
    if ($e.Control -and $e.KeyCode -eq [Windows.Forms.Keys]::E)                       { $tsBtnExpCsv.PerformClick() }
    if ($e.Control -and $e.Shift -and $e.KeyCode -eq [Windows.Forms.Keys]::E)         { $tsBtnExpJson.PerformClick() }
})

# ==============================================================================
#  LAUNCH
# ==============================================================================
[Windows.Forms.Application]::Run($form)
