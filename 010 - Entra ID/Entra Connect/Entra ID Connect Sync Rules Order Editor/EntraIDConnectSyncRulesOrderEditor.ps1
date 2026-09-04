#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$BackupRoot
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms

$modulePath = Join-Path $PSScriptRoot 'EntraIDConnectSyncRulesOrder.Engine.psm1'
Import-Module $modulePath -Force
if ([string]::IsNullOrWhiteSpace($BackupRoot)) {
    $BackupRoot = Join-Path $PSScriptRoot 'Backups'
}

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Entra ID Connect Sync Rules Order Editor - Live"
        Width="1460" Height="850" MinWidth="1100" MinHeight="650"
        WindowStartupLocation="CenterScreen" UseLayoutRounding="True" SnapsToDevicePixels="True"
        FontFamily="Segoe UI" FontSize="13">
    <Window.Background>
        <LinearGradientBrush StartPoint="0,0" EndPoint="0,1">
            <GradientStop Color="#F8FAFB" Offset="0" />
            <GradientStop Color="#EAF0F3" Offset="1" />
        </LinearGradientBrush>
    </Window.Background>
    <Window.Resources>
        <SolidColorBrush x:Key="Ink" Color="#18222D" />
        <SolidColorBrush x:Key="Muted" Color="#5F6B76" />
        <SolidColorBrush x:Key="Accent" Color="#237F8F" />
        <SolidColorBrush x:Key="ControlBorder" Color="#B9C5CC" />
        <Style TargetType="Button">
            <Setter Property="Background" Value="White" />
            <Setter Property="Foreground" Value="{StaticResource Ink}" />
            <Setter Property="BorderBrush" Value="{StaticResource ControlBorder}" />
            <Setter Property="BorderThickness" Value="1" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="Padding" Value="12,7" />
            <Setter Property="Margin" Value="0,0,8,0" />
            <Setter Property="MinHeight" Value="34" />
            <Setter Property="Cursor" Value="Hand" />
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="ButtonChrome" Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="4" Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"
                                              RecognizesAccessKey="True" />
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="ButtonChrome" Property="Opacity" Value="0.86" />
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="ButtonChrome" Property="Opacity" Value="0.70" />
                            </Trigger>
                            <Trigger Property="IsKeyboardFocused" Value="True">
                                <Setter TargetName="ButtonChrome" Property="BorderBrush" Value="#237F8F" />
                                <Setter TargetName="ButtonChrome" Property="BorderThickness" Value="2" />
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#8B959C" />
                                <Setter Property="Cursor" Value="Arrow" />
                                <Setter TargetName="ButtonChrome" Property="Background" Value="#EDF1F3" />
                                <Setter TargetName="ButtonChrome" Property="BorderBrush" Value="#D5DDE1" />
                                <Setter TargetName="ButtonChrome" Property="Opacity" Value="0.72" />
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="White" />
            <Setter Property="Foreground" Value="{StaticResource Ink}" />
            <Setter Property="BorderBrush" Value="{StaticResource ControlBorder}" />
            <Setter Property="BorderThickness" Value="1" />
            <Setter Property="Padding" Value="7,5" />
            <Setter Property="MinHeight" Value="32" />
            <Setter Property="VerticalContentAlignment" Value="Center" />
            <Style.Triggers>
                <Trigger Property="IsKeyboardFocusWithin" Value="True">
                    <Setter Property="BorderBrush" Value="{StaticResource Accent}" />
                    <Setter Property="BorderThickness" Value="2" />
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#E5ECEF" />
            <Setter Property="Foreground" Value="{StaticResource Ink}" />
            <Setter Property="FontWeight" Value="SemiBold" />
            <Setter Property="Padding" Value="7,0" />
            <Setter Property="Height" Value="36" />
            <Setter Property="BorderBrush" Value="#C7D1D6" />
            <Setter Property="BorderThickness" Value="0,0,1,1" />
        </Style>
        <Style TargetType="DataGridCell">
            <Setter Property="Padding" Value="6,0" />
            <Setter Property="BorderThickness" Value="0" />
            <Setter Property="VerticalContentAlignment" Value="Center" />
        </Style>
        <Style TargetType="ToolTip">
            <Setter Property="Background" Value="#122A38" />
            <Setter Property="Foreground" Value="White" />
            <Setter Property="BorderThickness" Value="0" />
            <Setter Property="Padding" Value="9,6" />
        </Style>
    </Window.Resources>

    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="Auto" />
            <RowDefinition Height="*" />
            <RowDefinition Height="Auto" />
        </Grid.RowDefinitions>

        <Grid Grid.Row="0" Margin="0,0,0,12">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="Auto" />
                <ColumnDefinition Width="Auto" />
                <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="*" />
                </Grid.ColumnDefinitions>
                <Image x:Name="AppIcon" Width="58" Height="58" Margin="0,0,13,0"
                       Stretch="Uniform" RenderOptions.BitmapScalingMode="HighQuality" />
                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <TextBlock Text="Entra ID Connect sync rules order" FontFamily="Bahnschrift SemiBold" FontSize="27"
                               Foreground="{StaticResource Ink}" />
                    <TextBlock Text="Rules are loaded from the local ADSync engine. Grid moves remain a plan until Apply."
                               Foreground="{StaticResource Muted}" Margin="0,3,0,0" />
                    <TextBlock Text="Scope: restores rule order only. Entra Connect configuration backup and recovery are outside this tool."
                               Foreground="#A15C00" FontWeight="SemiBold" TextWrapping="Wrap" Margin="0,3,12,0" />
                </StackPanel>
            </Grid>
            <Button x:Name="BackupButton" Grid.Column="1" Content="Safety snapshot" MinWidth="115"
                    ToolTip="Creates evidence for this tool. This is not an Entra Connect recovery backup."
                    VerticalAlignment="Center" />
            <Button x:Name="RestoreOrderButton" Grid.Column="2" Content="Restore rule order..." MinWidth="135"
                    ToolTip="Loads only the saved relative order as a plan. Rule definitions and states are not restored."
                    VerticalAlignment="Center" />
            <Button x:Name="RefreshButton" Grid.Column="3" Content="Reload live" MinWidth="105"
                    Margin="0" VerticalAlignment="Center" />
        </Grid>

        <Border Grid.Row="1" Background="#122A38" CornerRadius="4" Padding="11" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="*" />
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="ServerText" Grid.Column="0" Foreground="White" FontWeight="SemiBold" Margin="0,0,24,0" />
                <TextBlock x:Name="ModeText" Grid.Column="1" Foreground="White" Margin="0,0,24,0" />
                <TextBlock x:Name="SchedulerText" Grid.Column="2" Foreground="White" Margin="0,0,24,0" />
                <TextBlock x:Name="BackupText" Grid.Column="3" Foreground="#C8D1D8" TextTrimming="CharacterEllipsis" />
            </Grid>
        </Border>

        <Border Grid.Row="2" Background="White" BorderBrush="#D5DADE" BorderThickness="1"
                CornerRadius="5" Padding="10" Margin="0,0,0,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="340" />
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="Auto" />
                </Grid.ColumnDefinitions>
                <TextBlock Grid.Column="0" Text="Find" VerticalAlignment="Center" Margin="0,0,8,0" />
                <TextBox x:Name="SearchBox" Grid.Column="1" ToolTip="Name, connector or identifier" />
                <Button x:Name="FindNextButton" Grid.Column="2" Content="Find next" Margin="8,0,0,0" />
                <TextBlock x:Name="PlanText" Grid.Column="3" Foreground="{StaticResource Muted}"
                           VerticalAlignment="Center" Margin="18,0" />
                <Button x:Name="ResetButton" Grid.Column="4" Content="Discard plan" Margin="0" />
            </Grid>
        </Border>

        <Grid Grid.Row="3">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="*" />
                <ColumnDefinition Width="Auto" />
            </Grid.ColumnDefinitions>

            <DataGrid x:Name="RuleGrid" Grid.Column="0" AutoGenerateColumns="False"
                      CanUserAddRows="False" CanUserDeleteRows="False" CanUserSortColumns="False"
                      IsReadOnly="True" SelectionMode="Single" SelectionUnit="FullRow"
                      GridLinesVisibility="Horizontal" AlternatingRowBackground="#F8FAFB"
                      Background="White" BorderBrush="#B9C5CC" BorderThickness="1" RowHeight="31"
                      EnableRowVirtualization="True" VirtualizingPanel.IsVirtualizing="True"
                      VirtualizingPanel.VirtualizationMode="Recycling">
                <DataGrid.RowStyle>
                    <Style TargetType="DataGridRow">
                        <Style.Triggers>
                            <DataTrigger Binding="{Binding DisabledLabel}" Value="Disabled">
                                <Setter Property="Foreground" Value="#7A858F" />
                                <Setter Property="Background" Value="#EEF1F3" />
                            </DataTrigger>
                            <DataTrigger Binding="{Binding WillMove}" Value="True">
                                <Setter Property="Background" Value="#FFF2C7" />
                            </DataTrigger>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter Property="Background" Value="#CDEBE5" />
                                <Setter Property="Foreground" Value="#101820" />
                            </Trigger>
                        </Style.Triggers>
                    </Style>
                </DataGrid.RowStyle>
                <DataGrid.Columns>
                    <DataGridTextColumn Header="Loaded order" Binding="{Binding OriginalDisplayOrder}" Width="86" />
                    <DataGridTextColumn Header="Planned order" Binding="{Binding DisplayOrder}" Width="92" />
                    <DataGridTextColumn Header="Position change" Binding="{Binding PositionChange}" Width="105" />
                    <DataGridCheckBoxColumn Header="Operation" Binding="{Binding WillMove}" Width="72" />
                    <DataGridTextColumn Header="Live prec." Binding="{Binding OldPrecedence}" Width="78" />
                    <DataGridTextColumn Header="Connector" Binding="{Binding Connector}" Width="190" />
                    <DataGridTextColumn Header="Rule name" Binding="{Binding Name}" Width="470" />
                    <DataGridTextColumn Header="State" Binding="{Binding DisabledLabel}" Width="80" />
                    <DataGridTextColumn Header="Type" Binding="{Binding RuleType}" Width="82" />
                    <DataGridTextColumn Header="Direction" Binding="{Binding Direction}" Width="86" />
                    <DataGridTextColumn Header="Link" Binding="{Binding LinkType}" Width="82" />
                    <DataGridTextColumn Header="Source" Binding="{Binding SourceObjectType}" Width="82" />
                    <DataGridTextColumn Header="Target" Binding="{Binding TargetObjectType}" Width="82" />
                    <DataGridTextColumn Header="Identifier" Binding="{Binding Identifier}" Width="260" />
                </DataGrid.Columns>
            </DataGrid>

            <StackPanel Grid.Column="1" Margin="12,0,0,0" Width="150">
                <TextBlock Text="Move selected" FontFamily="Bahnschrift SemiBold" Foreground="{StaticResource Ink}"
                           Margin="0,0,0,8" />
                <Button x:Name="MoveTopButton" Content="Move to top" Margin="0,0,0,7" />
                <Button x:Name="MoveUp10Button" Content="Move up 10" Margin="0,0,0,7" />
                <Button x:Name="MoveUpButton" Content="Move up" Margin="0,0,0,7" />
                <Button x:Name="MoveDownButton" Content="Move down" Margin="0,0,0,7" />
                <Button x:Name="MoveDown10Button" Content="Move down 10" Margin="0,0,0,7" />
                <Button x:Name="MoveBottomButton" Content="Move to bottom" Margin="0,0,0,7" />
                <TextBlock Text="Exact planned position" FontWeight="SemiBold" Foreground="{StaticResource Ink}"
                           Margin="0,8,0,5" />
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*" />
                        <ColumnDefinition Width="Auto" />
                    </Grid.ColumnDefinitions>
                    <TextBox x:Name="TargetPositionBox" ToolTip="Enter a position between 1 and the number of live rules" />
                    <Button x:Name="MoveToPositionButton" Grid.Column="1" Content="Move" MinWidth="55"
                            Margin="6,0,0,0" ToolTip="Move the selected rule to this planned position" />
                </Grid>
                <TextBlock Text="Ctrl+Up/Down: 1&#x0a;Ctrl+PgUp/PgDn: 10&#x0a;Ctrl+Home/End: first/last"
                           Foreground="{StaticResource Muted}" TextWrapping="Wrap" FontSize="11" Margin="0,9,0,0" />
            </StackPanel>
        </Grid>

        <Border Grid.Row="4" Background="#122A38" CornerRadius="4" Padding="10" Margin="0,12,0,0">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*" />
                    <ColumnDefinition Width="Auto" />
                    <ColumnDefinition Width="Auto" />
                </Grid.ColumnDefinitions>
                <TextBlock x:Name="StatusText" Foreground="White" VerticalAlignment="Center"
                           Text="Connecting to the local ADSync engine..." />
                <Button x:Name="ExportPlanButton" Grid.Column="1" Content="Export plan..." />
                <Button x:Name="ApplyButton" Grid.Column="2" Content="Apply live..."
                    Background="#B3261E" Foreground="White" BorderBrush="#B3261E" Margin="0" />
            </Grid>
        </Border>
    </Grid>
</Window>
'@

$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [Windows.Markup.XamlReader]::Load($reader)
$controlNames = @(
    'AppIcon', 'BackupButton', 'RestoreOrderButton', 'RefreshButton', 'ServerText', 'ModeText', 'SchedulerText', 'BackupText',
    'SearchBox', 'FindNextButton', 'PlanText', 'ResetButton', 'RuleGrid', 'MoveTopButton',
    'MoveUp10Button', 'MoveUpButton', 'MoveDownButton', 'MoveDown10Button', 'MoveBottomButton',
    'TargetPositionBox', 'MoveToPositionButton', 'StatusText', 'ExportPlanButton', 'ApplyButton'
)
foreach ($controlName in $controlNames) {
    Set-Variable -Name $controlName -Value $window.FindName($controlName)
}

$iconPath = Join-Path $PSScriptRoot 'assets\EntraIDConnectSyncRulesOrderEditor.png'
if (Test-Path -LiteralPath $iconPath -PathType Leaf) {
    $iconImage = [System.Windows.Media.Imaging.BitmapImage]::new()
    $iconImage.BeginInit()
    $iconImage.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
    $iconImage.UriSource = [System.Uri]::new($iconPath, [System.UriKind]::Absolute)
    $iconImage.EndInit()
    $iconImage.Freeze()
    $window.Icon = $iconImage
    $AppIcon.Source = $iconImage
}

$script:RuleItems = [System.Collections.ObjectModel.ObservableCollection[object]]::new()
$script:OriginalRules = @()
$script:LiveFingerprint = $null
$script:InitialBackup = $null
$script:LastSearchIndex = -1
$script:Initialized = $false
$script:SyncCycleInProgress = $true
$RuleGrid.ItemsSource = $script:RuleItems

function Set-EditorEnabled {
    param([bool]$Enabled)
    foreach ($control in @(
            $BackupButton, $RestoreOrderButton, $RefreshButton, $ResetButton, $MoveTopButton, $MoveUpButton,
            $MoveUp10Button, $MoveDownButton, $MoveDown10Button, $MoveBottomButton,
            $TargetPositionBox, $MoveToPositionButton, $ExportPlanButton, $ApplyButton
        )) {
        $control.IsEnabled = $Enabled
    }
}

function Set-EditorStatus {
    param([string]$Message, [ValidateSet('Normal', 'Warning', 'Error')][string]$Level = 'Normal')
    $StatusText.Text = $Message
    $StatusText.Foreground = switch ($Level) {
        'Warning' { '#FFD166' }
        'Error' { '#FF9C9C' }
        default { 'White' }
    }
}

function Get-DesiredRules {
    return @($script:RuleItems)
}

function Get-MicrosoftCloneOperations {
    param([object[]]$Moves)
    if ($Moves.Count -eq 0) {
        return @()
    }
    $standardIdentifiers = @($script:OriginalRules | Where-Object { [bool]$_.IsStandardRule } |
            ForEach-Object { [string]$_.Identifier })
    return @($Moves | Where-Object { [string]$_.Identifier -in $standardIdentifiers })
}

function Get-MicrosoftCloneCount {
    param([object[]]$Moves)
    return @(Get-MicrosoftCloneOperations -Moves $Moves).Count
}

function Update-PlanPreview {
    if ($script:OriginalRules.Count -eq 0) {
        return
    }
    $moves = @(Get-ADSyncRuleOrderMovePlan -OriginalRules $script:OriginalRules -DesiredRules (Get-DesiredRules))
    $movedIdentifiers = @($moves | ForEach-Object Identifier)
    for ($index = 0; $index -lt $script:RuleItems.Count; $index++) {
        $rule = $script:RuleItems[$index]
        $rule.DisplayOrder = $index + 1
        $rule.WillMove = $rule.Identifier -in $movedIdentifiers
        $positionDelta = $rule.DisplayOrder - $rule.OriginalDisplayOrder
        $rule.PositionChange = if ($positionDelta -lt 0) {
            "Up $([Math]::Abs($positionDelta))"
        }
        elseif ($positionDelta -gt 0) {
            "Down $positionDelta"
        }
        else {
            '-'
        }
    }
    $RuleGrid.Items.Refresh()
    $microsoftCloneCount = Get-MicrosoftCloneCount -Moves $moves
    if ($script:SyncCycleInProgress) {
        $PlanText.Text = "$($script:RuleItems.Count) live rules | APPLY LOCKED: cycle in progress | Microsoft clones: $microsoftCloneCount"
        $PlanText.Foreground = '#C62828'
        $PlanText.FontWeight = 'Bold'
    }
    elseif ($moves.Count -gt 0) {
        $cloneValidation = if ($microsoftCloneCount -gt 0) {
            "WARNING: $microsoftCloneCount Microsoft clone(s)"
        }
        else {
            'Microsoft clones: 0'
        }
        $PlanText.Text = "$($script:RuleItems.Count) live rules | PLAN NOT APPLIED: $($moves.Count) relative move(s) | $cloneValidation"
        $PlanText.Foreground = if ($microsoftCloneCount -gt 0) { '#C62828' } else { '#A15C00' }
        $PlanText.FontWeight = 'Bold'
    }
    else {
        $PlanText.Text = "$($script:RuleItems.Count) live rules | No pending plan"
        $PlanText.Foreground = '#5F6B76'
        $PlanText.FontWeight = 'Normal'
    }
    $ApplyButton.Content = if ($moves.Count -gt 0) { "Apply $($moves.Count) move(s) live..." } else { 'Apply live...' }
    $ApplyButton.IsEnabled = $moves.Count -gt 0 -and -not $script:SyncCycleInProgress
    $ExportPlanButton.IsEnabled = $moves.Count -gt 0
    $ResetButton.IsEnabled = $moves.Count -gt 0
}

function Set-RuleCollection {
    param([object[]]$Rules)
    $script:RuleItems.Clear()
    $TargetPositionBox.Clear()
    foreach ($rule in $Rules) {
        $rule | Add-Member -MemberType NoteProperty -Name DisplayOrder -Value 0 -Force
        $rule | Add-Member -MemberType NoteProperty -Name OriginalDisplayOrder -Value ($rule.OriginalOrder + 1) -Force
        $rule | Add-Member -MemberType NoteProperty -Name PositionChange -Value '-' -Force
        $rule | Add-Member -MemberType NoteProperty -Name WillMove -Value $false -Force
        $disabledLabel = if ([bool]$rule.Disabled) { 'Disabled' } else { 'Active' }
        $rule | Add-Member -MemberType NoteProperty -Name DisabledLabel -Value $disabledLabel -Force
        $script:RuleItems.Add($rule)
    }
    Update-PlanPreview
}

function Update-ServerState {
    $scheduler = Get-ADSyncScheduler
    $schedulerCheckTime = Get-Date -Format 'HH:mm:ss'
    $ServerText.Text = "Server: $($env:COMPUTERNAME)"
    $ModeText.Text = if ($scheduler.StagingModeEnabled) { 'Mode: STAGING' } else { 'Mode: ACTIVE - LIVE EXPORTS ENABLED' }
    $ModeText.Foreground = if ($scheduler.StagingModeEnabled) { '#7FE1C8' } else { '#FFB3AE' }
    $ModeText.FontWeight = 'Bold'
    $ModeText.ToolTip = if ($scheduler.StagingModeEnabled) {
        'The server is in staging mode and cannot export changes to Entra ID or Active Directory.'
    }
    else {
        'This server is active. Applied rule changes can affect subsequent synchronization and export cycles.'
    }
    $script:SyncCycleInProgress = [bool]$scheduler.SyncCycleInProgress
    if ($script:SyncCycleInProgress) {
        $SchedulerText.Text = "Scheduler [$schedulerCheckTime]: CYCLE IN PROGRESS - DO NOT APPLY CHANGES"
        $SchedulerText.Foreground = '#FF6B6B'
        $SchedulerText.FontWeight = 'Bold'
        $SchedulerText.ToolTip = 'Wait for the current cycle to finish, then select Reload live before applying changes.'
    }
    elseif ($scheduler.SyncCycleEnabled) {
        $SchedulerText.Text = "Scheduler [$schedulerCheckTime]: IDLE (enabled) - no cycle may run during Apply"
        $SchedulerText.Foreground = '#7FE1C8'
        $SchedulerText.FontWeight = 'SemiBold'
        $SchedulerText.ToolTip = 'The engine is idle. Apply will pause the scheduler and restore it afterward.'
    }
    else {
        $SchedulerText.Text = "Scheduler [$schedulerCheckTime]: IDLE (disabled) - ready for Apply"
        $SchedulerText.Foreground = '#7FE1C8'
        $SchedulerText.FontWeight = 'SemiBold'
        $SchedulerText.ToolTip = 'The engine is idle and the scheduler is disabled.'
    }
}

function Update-LiveRules {
    param([switch]$CreateBackup, [string]$BackupLabel = 'InitialLoad')
    Set-EditorEnabled -Enabled $false
    Set-EditorStatus 'Loading rules from the local ADSync engine...'
    try {
        Assert-ADSyncRuleOrderAvailable
        Update-ServerState
        if ($CreateBackup) {
            Set-EditorStatus 'Creating a safety snapshot for audit and rollback evidence...'
            $script:InitialBackup = New-ADSyncRuleOrderBackup `
                -BackupRoot $BackupRoot `
                -Label $BackupLabel
            $BackupText.Text = "Snapshot: $($script:InitialBackup.Path)"
            $BackupText.ToolTip = $script:InitialBackup.Path
        }
        $rules = @(Get-ADSyncRuleOrderSnapshot)
        $script:OriginalRules = @($rules)
        $script:LiveFingerprint = Get-ADSyncRuleOrderFingerprint
        $script:LastSearchIndex = -1
        Set-RuleCollection -Rules $rules
        Set-EditorStatus "Live load complete: $($rules.Count) rules. Grid changes are not applied yet."
        Set-EditorEnabled -Enabled $true
        Update-PlanPreview
    }
    catch {
        Set-EditorStatus $_.Exception.Message -Level Error
        [System.Windows.MessageBox]::Show(
            $window, $_.Exception.Message, 'Unable to load ADSync rules',
            [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error
        ) | Out-Null
    }
}

function Move-RuleItemToIndex {
    param([Parameter(Mandatory)]$Rule, [Parameter(Mandatory)][int]$NewIndex)
    $oldIndex = $script:RuleItems.IndexOf($Rule)
    if ($oldIndex -lt 0 -or $NewIndex -lt 0 -or $NewIndex -ge $script:RuleItems.Count) {
        throw 'The requested planned position is outside the rule list.'
    }
    if ($oldIndex -eq $NewIndex) {
        return
    }
    $script:RuleItems.Move($oldIndex, $NewIndex)
    Update-PlanPreview
    $RuleGrid.SelectedItem = $Rule
    $RuleGrid.ScrollIntoView($Rule)
    $TargetPositionBox.Text = [string]($NewIndex + 1)
    Set-EditorStatus "PLAN ONLY: '$($Rule.Name)' moved from position $($oldIndex + 1) to $($NewIndex + 1)." -Level Warning
}

function Move-SelectedRule {
    param([ValidateSet('Top', 'Up10', 'Up', 'Down', 'Down10', 'Bottom')][string]$Direction)
    $selectedRule = $RuleGrid.SelectedItem
    if ($null -eq $selectedRule) {
        Set-EditorStatus 'Select a rule before moving it.' -Level Warning
        return
    }
    $oldIndex = $script:RuleItems.IndexOf($selectedRule)
    $newIndex = switch ($Direction) {
        'Top' { 0 }
        'Up10' { [Math]::Max(0, $oldIndex - 10) }
        'Up' { [Math]::Max(0, $oldIndex - 1) }
        'Down' { [Math]::Min($script:RuleItems.Count - 1, $oldIndex + 1) }
        'Down10' { [Math]::Min($script:RuleItems.Count - 1, $oldIndex + 10) }
        'Bottom' { $script:RuleItems.Count - 1 }
    }
    Move-RuleItemToIndex -Rule $selectedRule -NewIndex $newIndex
}

function Move-SelectedRuleToPosition {
    $selectedRule = $RuleGrid.SelectedItem
    if ($null -eq $selectedRule) {
        Set-EditorStatus 'Select a rule before entering its planned position.' -Level Warning
        return
    }
    $targetPosition = 0
    if (-not [int]::TryParse($TargetPositionBox.Text.Trim(), [ref]$targetPosition) -or
        $targetPosition -lt 1 -or $targetPosition -gt $script:RuleItems.Count) {
        Set-EditorStatus "Enter a whole position between 1 and $($script:RuleItems.Count)." -Level Warning
        $TargetPositionBox.SelectAll()
        $TargetPositionBox.Focus() | Out-Null
        return
    }
    Move-RuleItemToIndex -Rule $selectedRule -NewIndex ($targetPosition - 1)
}

function Find-NextRule {
    $searchText = $SearchBox.Text.Trim()
    if ([string]::IsNullOrWhiteSpace($searchText)) {
        Set-EditorStatus 'Enter a rule name, connector or identifier to search.' -Level Warning
        return
    }
    for ($offset = 1; $offset -le $script:RuleItems.Count; $offset++) {
        $index = ($script:LastSearchIndex + $offset) % $script:RuleItems.Count
        $rule = $script:RuleItems[$index]
        if ($rule.Name -like "*$searchText*" -or $rule.Connector -like "*$searchText*" -or
            $rule.Identifier -like "*$searchText*") {
            $script:LastSearchIndex = $index
            $RuleGrid.SelectedItem = $rule
            $RuleGrid.ScrollIntoView($rule)
            Set-EditorStatus "Match $($index + 1): $($rule.Name)"
            return
        }
    }
    Set-EditorStatus "No rule matches '$searchText'." -Level Warning
}

function Show-ApplyConfirmation {
    param(
        [int]$MoveCount,
        [object[]]$MicrosoftCloneOperations,
        [bool]$IsStaging,
        [string]$BackupPath
    )
    $microsoftCloneCount = @($MicrosoftCloneOperations).Count
    $confirmationWindow = [System.Windows.Window]::new()
    $confirmationWindow.Title = 'Confirm live ADSync changes'
    $confirmationWindow.Width = 620
    $confirmationWindow.Height = if ($microsoftCloneCount -gt 0) { 480 } else { 340 }
    $confirmationWindow.WindowStartupLocation = 'CenterOwner'
    $confirmationWindow.Owner = $window
    $confirmationWindow.ResizeMode = 'NoResize'
    $confirmationWindow.Background = '#F4F6F8'

    $panel = [System.Windows.Controls.StackPanel]::new()
    $panel.Margin = '22'
    $warning = [System.Windows.Controls.TextBlock]::new()
    $warning.FontFamily = 'Bahnschrift SemiBold'
    $warning.FontSize = 22
    $warning.Foreground = if ($IsStaging) { '#006B5B' } else { '#A12622' }
    $warning.Text = if ($IsStaging) { 'Apply on STAGING server' } else { 'Apply on ACTIVE server' }
    $panel.Children.Add($warning) | Out-Null

    $validation = [System.Windows.Controls.TextBlock]::new()
    $validation.Margin = '0,14,0,0'
    $validation.FontFamily = 'Bahnschrift SemiBold'
    $validation.FontSize = 15
    $validation.TextWrapping = 'Wrap'
    if ($microsoftCloneCount -gt 0) {
        $validation.Foreground = '#C62828'
        $validation.Text = "WARNING: $microsoftCloneCount Microsoft standard rule(s) will be cloned and the original rule(s) disabled."
    }
    else {
        $validation.Foreground = '#006B5B'
        $validation.Text = 'Validation: no Microsoft standard rule will be cloned.'
    }
    $panel.Children.Add($validation) | Out-Null

    if ($microsoftCloneCount -gt 0) {
        $cloneListLabel = [System.Windows.Controls.TextBlock]::new()
        $cloneListLabel.Margin = '0,12,0,5'
        $cloneListLabel.FontWeight = 'SemiBold'
        $cloneListLabel.Text = 'Microsoft standard rules to clone:'
        $panel.Children.Add($cloneListLabel) | Out-Null

        $cloneList = [System.Windows.Controls.ListBox]::new()
        $cloneList.Height = [Math]::Min(126, 12 + (38 * $microsoftCloneCount))
        $cloneList.Background = 'White'
        $cloneList.BorderBrush = '#B9C5CC'
        $cloneList.BorderThickness = '1'
        $cloneList.Padding = '4'
        foreach ($operation in $MicrosoftCloneOperations) {
            $cloneItem = [System.Windows.Controls.TextBlock]::new()
            $cloneItem.Text = "$($operation.RuleName) [$($operation.Connector)]`n$($operation.Placement) $($operation.AnchorRuleName)"
            $cloneItem.TextWrapping = 'Wrap'
            $cloneItem.Margin = '2'
            $cloneList.Items.Add($cloneItem) | Out-Null
        }
        $panel.Children.Add($cloneList) | Out-Null
    }

    $details = [System.Windows.Controls.TextBlock]::new()
    $details.Margin = '0,12,0,12'
    $details.TextWrapping = 'Wrap'
    $customRecreationCount = $MoveCount - $microsoftCloneCount
    $details.Text = "$MoveCount relative move(s) will be applied on $($env:COMPUTERNAME).`nCustom rule recreations: $customRecreationCount`nThe scheduler will be paused and restored automatically.`nA new pre-Apply safety snapshot will be created under:`n$BackupPath`n`nThis tool does not restore Entra Connect configuration."
    $panel.Children.Add($details) | Out-Null

    $buttons = [System.Windows.Controls.StackPanel]::new()
    $buttons.Orientation = 'Horizontal'
    $buttons.HorizontalAlignment = 'Right'
    $buttons.Margin = '0,18,0,0'
    $cancel = [System.Windows.Controls.Button]::new()
    $cancel.Content = 'Cancel'
    $cancel.Width = 95
    $cancel.Margin = '0,0,8,0'
    $cancel.IsCancel = $true
    $apply = [System.Windows.Controls.Button]::new()
    $apply.Content = if ($IsStaging) { 'Apply on STAGING' } else { 'Apply on ACTIVE' }
    $apply.Width = 145
    $apply.Background = if ($IsStaging) { '#006B5B' } else { '#A12622' }
    $apply.Foreground = 'White'
    $apply.IsDefault = $true
    $buttons.Children.Add($cancel) | Out-Null
    $buttons.Children.Add($apply) | Out-Null
    $panel.Children.Add($buttons) | Out-Null
    $confirmationWindow.Content = $panel

    $script:ConfirmationAccepted = $false
    $cancel.Add_Click({ $confirmationWindow.Close() })
    $apply.Add_Click({
            $script:ConfirmationAccepted = $true
            $confirmationWindow.Close()
        })
    $confirmationWindow.ShowDialog() | Out-Null
    return $script:ConfirmationAccepted
}

$MoveTopButton.Add_Click({ Move-SelectedRule -Direction Top })
$MoveUp10Button.Add_Click({ Move-SelectedRule -Direction Up10 })
$MoveUpButton.Add_Click({ Move-SelectedRule -Direction Up })
$MoveDownButton.Add_Click({ Move-SelectedRule -Direction Down })
$MoveDown10Button.Add_Click({ Move-SelectedRule -Direction Down10 })
$MoveBottomButton.Add_Click({ Move-SelectedRule -Direction Bottom })
$MoveToPositionButton.Add_Click({ Move-SelectedRuleToPosition })
$TargetPositionBox.Add_KeyDown({
        param($eventSource, $keyEventArgs)
        if ($keyEventArgs.Key -eq [System.Windows.Input.Key]::Enter) {
            Move-SelectedRuleToPosition
            $keyEventArgs.Handled = $true
        }
    })
$RuleGrid.Add_SelectionChanged({
        if ($null -ne $RuleGrid.SelectedItem) {
            $TargetPositionBox.Text = [string]($script:RuleItems.IndexOf($RuleGrid.SelectedItem) + 1)
        }
    })
$FindNextButton.Add_Click({ Find-NextRule })
$SearchBox.Add_KeyDown({
        param($eventSource, $keyEventArgs)
        if ($keyEventArgs.Key -eq [System.Windows.Input.Key]::Enter) {
            Find-NextRule
            $keyEventArgs.Handled = $true
        }
    })
$RuleGrid.Add_KeyDown({
        param($eventSource, $keyEventArgs)
        if ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) {
            if ($keyEventArgs.Key -eq [System.Windows.Input.Key]::Up) {
                Move-SelectedRule -Direction Up
                $keyEventArgs.Handled = $true
            }
            elseif ($keyEventArgs.Key -eq [System.Windows.Input.Key]::Down) {
                Move-SelectedRule -Direction Down
                $keyEventArgs.Handled = $true
            }
            elseif ($keyEventArgs.Key -eq [System.Windows.Input.Key]::PageUp) {
                Move-SelectedRule -Direction Up10
                $keyEventArgs.Handled = $true
            }
            elseif ($keyEventArgs.Key -eq [System.Windows.Input.Key]::PageDown) {
                Move-SelectedRule -Direction Down10
                $keyEventArgs.Handled = $true
            }
            elseif ($keyEventArgs.Key -eq [System.Windows.Input.Key]::Home) {
                Move-SelectedRule -Direction Top
                $keyEventArgs.Handled = $true
            }
            elseif ($keyEventArgs.Key -eq [System.Windows.Input.Key]::End) {
                Move-SelectedRule -Direction Bottom
                $keyEventArgs.Handled = $true
            }
        }
    })
$ResetButton.Add_Click({ Set-RuleCollection -Rules @($script:OriginalRules | Sort-Object OriginalOrder) })
$RefreshButton.Add_Click({
        if (@(Get-ADSyncRuleOrderMovePlan -OriginalRules $script:OriginalRules -DesiredRules (Get-DesiredRules)).Count -gt 0) {
            $answer = [System.Windows.MessageBox]::Show(
                $window, 'Discard the current plan and reload the live ADSync rules?', 'Reload live rules',
                [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Warning
            )
            if ($answer -ne [System.Windows.MessageBoxResult]::Yes) { return }
        }
        Update-LiveRules -CreateBackup -BackupLabel 'ManualReload'
    })
$BackupButton.Add_Click({
        try {
            Set-EditorEnabled -Enabled $false
            $backup = New-ADSyncRuleOrderBackup -BackupRoot $BackupRoot -Label 'ManualBackup'
            $BackupText.Text = "Snapshot: $($backup.Path)"
            $BackupText.ToolTip = $backup.Path
            Set-EditorStatus "Safety snapshot complete: $($backup.Path). This is not an Entra Connect recovery backup."
        }
        catch {
            Set-EditorStatus $_.Exception.Message -Level Error
        }
        finally {
            Set-EditorEnabled -Enabled $true
            Update-PlanPreview
        }
    })
$RestoreOrderButton.Add_Click({
        try {
            $currentMoves = @(Get-ADSyncRuleOrderMovePlan -OriginalRules $script:OriginalRules -DesiredRules (Get-DesiredRules))
            if ($currentMoves.Count -gt 0) {
                $answer = [System.Windows.MessageBox]::Show(
                    $window,
                    'Discard the current plan and load a saved rule order?',
                    'Restore rule order only',
                    [System.Windows.MessageBoxButton]::YesNo,
                    [System.Windows.MessageBoxImage]::Warning
                )
                if ($answer -ne [System.Windows.MessageBoxResult]::Yes) { return }
            }

            $dialog = [System.Windows.Forms.FolderBrowserDialog]::new()
            $dialog.Description = 'Select an editor safety snapshot. Only rule order will be loaded.'
            $dialog.ShowNewFolderButton = $false
            if (Test-Path -LiteralPath $BackupRoot -PathType Container) {
                $dialog.SelectedPath = $BackupRoot
            }
            if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }

            Set-EditorEnabled -Enabled $false
            Set-EditorStatus 'Validating the safety snapshot and preparing its saved rule order...'
            $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
            $backupSequence = @(
                Get-ADSyncRuleOrderBackupSequence `
                    -BackupPath $dialog.SelectedPath `
                    -CurrentRules $script:OriginalRules
            )
            Set-RuleCollection -Rules $backupSequence
            $restoreMoves = @(Get-ADSyncRuleOrderMovePlan -OriginalRules $script:OriginalRules -DesiredRules (Get-DesiredRules))
            if ($restoreMoves.Count -eq 0) {
                Set-EditorStatus 'The live rule order already matches the selected safety snapshot.'
            }
            else {
                Set-EditorStatus "ORDER RESTORE PLAN ONLY: $($restoreMoves.Count) move(s) loaded. Rule definitions and states are unchanged. Review before Apply." -Level Warning
            }
        }
        catch {
            Set-EditorStatus $_.Exception.Message -Level Error
            [System.Windows.MessageBox]::Show(
                $window,
                $_.Exception.Message,
                'Unable to restore rule order',
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Error
            ) | Out-Null
        }
        finally {
            Set-EditorEnabled -Enabled $true
            Update-PlanPreview
        }
    })
$ExportPlanButton.Add_Click({
        try {
            $moves = @(Get-ADSyncRuleOrderMovePlan -OriginalRules $script:OriginalRules -DesiredRules (Get-DesiredRules))
            $dialog = [Microsoft.Win32.SaveFileDialog]::new()
            $dialog.Filter = 'CSV files (*.csv)|*.csv'
            $dialog.FileName = "EntraIDConnect-SyncRules-Order-MovePlan-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            if ($dialog.ShowDialog($window)) {
                $moves | Export-Csv -LiteralPath $dialog.FileName -Delimiter ';' -NoTypeInformation -Encoding UTF8
                Set-EditorStatus "Plan exported: $($dialog.FileName)"
            }
        }
        catch {
            Set-EditorStatus $_.Exception.Message -Level Error
        }
    })
$ApplyButton.Add_Click({
        try {
            $moves = @(Get-ADSyncRuleOrderMovePlan -OriginalRules $script:OriginalRules -DesiredRules (Get-DesiredRules))
            if ($moves.Count -eq 0) { return }
            $microsoftCloneOperations = @(Get-MicrosoftCloneOperations -Moves $moves)
            $scheduler = Get-ADSyncScheduler
            if (-not (Show-ApplyConfirmation `
                        -MoveCount $moves.Count `
                        -MicrosoftCloneOperations $microsoftCloneOperations `
                        -IsStaging ([bool]$scheduler.StagingModeEnabled) `
                        -BackupPath $BackupRoot)) {
                return
            }
            Set-EditorEnabled -Enabled $false
            $script:IsApplying = $true
            Set-EditorStatus "Applying $($moves.Count) live move(s)..." -Level Warning
            $window.Dispatcher.Invoke([action]{}, [System.Windows.Threading.DispatcherPriority]::Render)
            $confirmationToken = if ($scheduler.StagingModeEnabled) {
                "APPLY $($env:COMPUTERNAME)"
            }
            else {
                "APPLY ACTIVE $($env:COMPUTERNAME)"
            }
            $result = Invoke-ADSyncRuleOrderMovePlan `
                -MovePlan $moves `
                -ExpectedFingerprint $script:LiveFingerprint `
                -BackupRoot $BackupRoot `
                -ConfirmationToken $confirmationToken `
                -AllowActiveServer:(!$scheduler.StagingModeEnabled) `
                -Confirm:$false
            [System.Windows.MessageBox]::Show(
                $window,
                "Apply completed.`nOperations: $($result.Operations.Count)`nPre-Apply safety snapshot: $($result.Backup.Path)`n`nNo synchronization profile was started.`nEntra Connect configuration recovery is outside this tool.",
                'Entra ID Connect sync rules order applied',
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            ) | Out-Null
            Update-LiveRules -CreateBackup -BackupLabel 'PostApply'
        }
        catch {
            Set-EditorStatus $_.Exception.Message -Level Error
            [System.Windows.MessageBox]::Show(
                $window, $_.Exception.Message, 'Apply failed',
                [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error
            ) | Out-Null
            Set-EditorEnabled -Enabled $true
            Update-ServerState
            Update-PlanPreview
        }
        finally {
            $script:IsApplying = $false
        }
    })

$window.Add_ContentRendered({
        if (-not $script:Initialized) {
            $script:Initialized = $true
            Update-LiveRules -CreateBackup -BackupLabel 'InitialLoad'
        }
    })

Set-EditorEnabled -Enabled $false
$script:IsApplying = $false
$window.Add_Closing({
        param($eventSource, $closingEventArgs)
        if ($script:IsApplying) {
            $closingEventArgs.Cancel = $true
        }
    })
$window.ShowDialog() | Out-Null