@{
    AllowedGroups = @{
        't0-mathias' = @(
            'GG-Tier0-AD-Admins-JIT',
            'Domain Admins'
        )
        't1-sophie' = @(
            'GG-ServerOps-Prod-Admins-JIT'
        )
    }

    MaxTtlByGroup = @{
        'GG-Tier0-AD-Admins-JIT'       = 30
        'GG-ServerOps-Prod-Admins-JIT' = 240
        'Domain Admins'                = 30
    }

    LogPath = 'C:\Logs\JIT-Broker.csv'
}