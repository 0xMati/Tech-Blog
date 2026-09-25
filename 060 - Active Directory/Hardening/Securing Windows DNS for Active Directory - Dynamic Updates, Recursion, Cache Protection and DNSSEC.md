---
title: "Securing Windows DNS for Active Directory: Dynamic Updates, Recursion, Cache Protection and DNSSEC"
date: 2026-09-24
---

# Securing Windows DNS for Active Directory: Dynamic Updates, Recursion, Cache Protection and DNSSEC

DNS is part of the Active Directory control plane. Changing a DC locator record can redirect authentication traffic; exposing recursion can turn a domain controller into an amplification service; and granting DNS administration can provide a path to Tier 0. DNS hardening must therefore protect both the data and the server that answers for it.

> **TL;DR**
>
> - Keep AD DNS internal, patched and inside the Tier 0 boundary.
> - Use AD-integrated zones with **secure-only dynamic updates**.
> - Give DHCP a dedicated DNS update identity when it registers records for clients.
> - Restrict recursion, forwarding, zone transfers and management access to their actual consumers.
> - Preserve cache pollution protection, source-port randomization and cache locking.
> - DNSSEC authenticates DNS data; it does not encrypt queries or prevent denial of service.

## 1. Start with the threat, not the checkbox

| Threat | Likely effect | Primary controls |
|---|---|---|
| Unauthorized dynamic update | Redirected clients or broken service discovery | Secure-only updates, record ACLs, controlled DHCP identity |
| Zone enumeration or transfer | Internal namespace disclosure | Disable or restrict zone transfers, restrict management |
| Cache poisoning or spoofed response | Resolver returns attacker-selected data | Pollution protection, source-port randomization, cache locking, DNSSEC |
| Open recursion and amplification | Resource exhaustion or attack traffic toward third parties | Network isolation, recursion scopes/policies, RRL where appropriate |
| Privileged DNS configuration change | Forest-wide redirection or code execution opportunity | Tier 0 administration, least privilege, auditing |
| Stale or malicious registration | Authentication and application failures | Aging/scavenging, DHCP ownership design, monitoring |

DNSSEC does not replace the other controls. Secure dynamic update protects writes to an AD-integrated zone, whereas DNSSEC lets a resolver validate signed answers. They solve different problems.

## 2. Treat AD DNS as Tier 0

A DNS server that hosts AD locator zones can influence how clients and administrators reach domain controllers. When DNS runs on a DC, it already executes inside the forest security boundary.

- Administer DNS-enabled DCs only from Tier 0 workstations and accounts.
- Keep the DNS role, operating system and management tools patched.
- Do not install unrelated agents, plug-ins or application roles on a DC.
- Limit DNS management protocols and TCP/UDP 53 at network boundaries.
- Never expose an AD DNS server directly to the Internet as a public authoritative or recursive resolver.
- Separate public DNS hosting from the internal AD namespace.

Membership in `DNSAdmins` is privileged. It grants broad control over the DNS service and zones and must not become a convenience role for application teams. Prefer a narrowly delegated ACL on a specific zone or record set when that is the actual requirement, and monitor all privileged group membership.

## 3. Require secure dynamic updates

Only AD-integrated zones support secure dynamic updates. The client and DNS server establish a Kerberos security context; the DNS server then evaluates the directory ACL before writing the record.

Audit every AD-integrated zone:

```powershell
Get-DnsServerZone |
    Where-Object IsDsIntegrated |
    Select-Object ZoneName, ReplicationScope, DynamicUpdate
```

The expected value for an AD namespace is normally `Secure`. `NonsecureAndSecure` allows unauthenticated clients to create or replace records and should not be used for a normal domain zone.

Set a zone to secure-only updates after confirming it is AD-integrated:

```powershell
$zone = Get-DnsServerZone -Name 'contoso.com'

if (-not $zone.IsDsIntegrated) {
    throw 'The zone must be AD-integrated before secure-only updates can be enabled.'
}

Set-DnsServerPrimaryZone -Name $zone.ZoneName -DynamicUpdate Secure
```

Secure-only does not mean every authenticated principal may overwrite every name. The principal that creates a `dnsNode` becomes its owner, and its ACL controls later changes. This ownership model is why DHCP failover and records created by different registrars need deliberate design.

## 4. Design DHCP ownership explicitly

Windows clients and DHCP servers negotiate responsibility for A and PTR records through DHCP option 81. In the normal Windows default, the client registers A and DHCP registers PTR; administrators can instead configure DHCP to register both.

When multiple DHCP servers register names with their own computer identities, one server can own a record that another server later needs to update. The preferred operational pattern is:

1. create a standard domain user used only for DHCP DNS updates;
2. configure the same credentials on every authorized DHCP server;
3. deny interactive logon and do not grant additional privileges;
4. protect and rotate the credential through an established procedure;
5. reconfigure the credential after restoring the DHCP database because it is not included in that backup.

`DnsUpdateProxy` addresses ownership interoperability, but records created by its members are not secured in the same way. If the group is required for legacy-client proxy registration, combine it with dedicated update credentials as documented by Microsoft. Do not simply add DHCP servers to `DnsUpdateProxy` and assume the records are protected.

If DHCP runs on a domain controller, dedicated DNS update credentials are especially important. Without them, the DHCP service inherits the DC's ability to modify records in secure AD-integrated zones.

> For a Windows DHCP client whose DHCP server owns DNS registration, use `ipconfig /renew` to retrigger the DHCP negotiation. Microsoft warns that `ipconfig /registerdns` bypasses DHCP and can change record ownership, preventing later DHCP updates.

### 4.1 DHCP failover does not automatically synchronize every configuration change

DHCPv4 failover synchronizes lease state between the two partners. Scope configuration is copied when failover is established, but subsequent configuration changes require an explicit replication operation, whether initiated manually or by a separately configured management workflow.

| Data or setting | Verification needed |
|---|---|
| Lease state | Healthy failover communication and state; do not confuse it with scope configuration |
| Scope properties, reservations, scope options and policies | Replicate the reviewed source configuration, then compare the partner |
| Dedicated DNS update credentials | Configure and verify the intended identity on both servers; do not assume scope replication distributes credentials |
| DNS record ownership and ACLs | Verify actual registration/update behavior; healthy DHCP failover does not repair an existing DNS ownership conflict |

Read the relationship from both servers for one scope before choosing the source:

```powershell
Import-Module DhcpServer -ErrorAction Stop
$sourceServer = 'dhcp01.corp.example'
$partnerServer = 'dhcp02.corp.example'
$scopeId = [ipaddress]'192.0.2.0'

foreach ($server in $sourceServer, $partnerServer) {
    Get-DhcpServerv4Failover -ComputerName $server -ScopeId $scopeId -ErrorAction Stop |
        Select-Object @{Name='QueriedServer';Expression={$server}},
            Name, PartnerServer, Mode, State, ScopeId
    Get-DhcpServerv4Scope -ComputerName $server -ScopeId $scopeId -ErrorAction Stop |
        Select-Object @{Name='QueriedServer';Expression={$server}},
            ScopeId, Name, StartRange, EndRange, SubnetMask, LeaseDuration, State
}
```

Replace the documentation scope address with the intended real scope. Retain both configurations and compare reservations, options, policies and DNS update settings as well as the displayed scope properties. The small view above is not a complete backup.

Then preview only that scope's replication from the server holding the reviewed desired configuration:

```powershell
Invoke-DhcpServerv4FailoverReplication -ComputerName $sourceServer `
    -ScopeId $scopeId -WhatIf
```

After review, apply without `-WhatIf` and compare the same scope on the partner. This copies source settings **to the partner and overwrites its scope settings**; it is not a two-way merge. Do not omit the scope/relationship selector unless replication of every failover scope is intentional, and do not resolve disagreement by blindly replicating in both directions.

For partners on different supported Windows Server versions, Microsoft's guidance is to make changes and initiate replication from the newer OS. Preserve that direction in the management process. If a change must be reversed, restore the selected known-good configuration deliberately; another replication from the wrong side can destroy the remaining good copy.

DHCP failover communication uses TCP 647 between partners and requires working time synchronization. This is different from AD replication and from the DHCP client/relay path. Verify both lease continuity and secure DNS updates by each partner after the change.

See [Microsoft's DHCP failover overview](https://learn.microsoft.com/en-us/windows-server/networking/technologies/dhcp/dhcp-failover) and [Invoke-DhcpServerv4FailoverReplication](https://learn.microsoft.com/en-us/powershell/module/dhcpserver/invoke-dhcpserverv4failoverreplication) for the replication scope and direction.

## 5. Restrict zone transfers

AD replication replaces zone transfers between DNS-enabled DCs that host an AD-integrated zone. A transfer is still relevant when an authorized secondary DNS server requires a copy.

Allow AXFR/IXFR only to explicit secondary servers or, where appropriate, servers listed in the zone's NS records. Never enable transfer to any server on an internal zone merely for troubleshooting.

```powershell
Get-DnsServerZone |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, SecureSecondaries
```

For a zone that must transfer only to its declared name servers:

```powershell
Set-DnsServerPrimaryZone -Name 'partners.contoso.com' `
    -SecureSecondaries TransferToZoneNameServer
```

Network controls should also restrict TCP 53 between the primary and approved secondaries. DNS commonly uses UDP 53 for ordinary queries, but TCP 53 is required for transfers and can also be used for large or retried query responses.

## 6. Bound recursion and forwarding

An authoritative response comes from zone data hosted by the server. A recursive response is assembled by querying other servers or forwarders on the client's behalf. An AD DNS server often needs recursion for internal clients to resolve names outside its authoritative zones, but that does not justify recursion from every network.

```powershell
Get-DnsServerRecursion
Get-DnsServerForwarder
Get-DnsServerRootHint
```

Apply these rules:

- allow DNS queries only from approved internal networks;
- use controlled forwarders or root hints according to the organization's egress model;
- use conditional forwarders for specific external or trusted namespaces;
- do not point domain members or DC DNS client settings directly at public resolvers;
- disable recursion on servers intended to be authoritative-only;
- use DNS policies and recursion scopes when one server must provide different recursion behavior to different client networks.

Response Rate Limiting (RRL) reduces repeated equivalent responses and can limit amplification abuse. It is defense in depth, not permission to expose an internal DNS server publicly. Audit the current state before changing thresholds:

```powershell
Get-DnsServerResponseRateLimiting
```

Baseline legitimate traffic and test exceptions before enforcing RRL, especially on a busy internal resolver.

## 7. Preserve cache defenses

Modern Windows DNS includes several protections against cache poisoning:

- **source-port randomization (socket pool)** makes a forged reply harder to match to an outstanding query;
- **cache pollution protection** prevents unrelated names in a response from contaminating the cache;
- **cache locking** prevents cached data from being overwritten for a percentage of its TTL.

Inspect the supported cache settings:

```powershell
Get-DnsServerCache |
    Select-Object EnablePollutionProtection, LockingPercent,
        MaxTTL, MaxNegativeTTL, MaxKBSize
```

Keep pollution protection enabled and cache locking at the modern default unless a documented compatibility case proves otherwise. Reducing either value to work around a resolution problem weakens the resolver and usually masks an authoritative-data or forwarding defect.

Clearing a cache is a diagnostic action, not hardening:

```powershell
# Clear the recursive cache on the DNS server.
Clear-DnsServerCache -Force

# Clear only the local Windows DNS client cache.
Clear-DnsClientCache
```

These are different caches. Clearing one does not clear the other or change authoritative zone data.

## 8. Keep the Global Query Block List intentional

Windows DNS uses a Global Query Block List to protect names associated with automatic proxy discovery and transition technologies, historically including `wpad` and `isatap`. Inspect it rather than replacing it from an old build document:

```powershell
Get-DnsServerGlobalQueryBlockList
```

Removing `wpad` from the list can expose clients to proxy auto-discovery redirection. If the organization intentionally deploys WPAD, document the ownership, record ACL, web service and client policy as one security design. Adding arbitrary business names to this list is not a substitute for DNS ACLs or a protective DNS service.

DNS suffix devolution is a DNS **client** search behavior, not a server-side cache defense. Restricting the suffix search list can reduce ambiguous short-name resolution, but it does not authenticate DNS answers.

## 9. Use DNSSEC for data authenticity

DNSSEC signs zone data. A validating resolver uses DNSKEY, DS and RRSIG records to verify origin and integrity and uses NSEC or NSEC3 to authenticate nonexistence.

DNSSEC provides:

- origin authentication;
- data integrity;
- authenticated denial of existence.

DNSSEC does **not** provide:

- confidentiality for queries or answers;
- protection against traffic analysis;
- availability against denial-of-service attacks;
- authorization for dynamic updates;
- proof that the signed data was semantically correct when an administrator entered it.

Before signing a production zone, design the trust-anchor distribution, KSK/ZSK lifecycle, rollover monitoring, parent DS publication where applicable, algorithm compatibility and recovery procedure. A signed zone with expired keys can turn an integrity control into a resolution outage.

Inspect signed-zone state and test that clients can request DNSSEC data:

```powershell
$zoneName = 'secure.contoso.com'

Get-DnsServerDnsSecZoneSetting -ZoneName $zoneName
Get-DnsServerSigningKey -ZoneName $zoneName
Get-DnsServerTrustPoint

Resolve-DnsName "app.$zoneName" -Type A -DnssecOk
```

Do not use `nslookup.exe` to validate DNSSEC behavior; its internal client is not DNSSEC-aware. Use `Resolve-DnsName` and verify the resolver's validation policy and trust anchors, not merely the presence of an RRSIG record.

## 10. Audit changes and high-volume activity

DNS Server audit events are enabled by default and record configuration, zone and record changes. Forward the `Microsoft-Windows-DNSServer/Audit` channel from Tier 0 systems to protected central storage.

High-value audit events include:

| Event | Meaning |
|---|---|
| 515 / 516 | Record created or deleted administratively |
| 519 / 520 | Record created or deleted by dynamic update |
| 521 | Record scavenged |
| 525-531 | DNSSEC signing and key rollover operations |
| 541 | Server setting changed |
| 557 | Listen addresses changed |
| 564 | Zone reloaded from Active Directory |

Inspect diagnostic settings without enabling verbose packet logging:

```powershell
Get-DnsServerDiagnostics | Format-List
```

The Analytical channel records query, response and update activity, but it is disabled by default. Enable it only for a scoped investigation or a deliberately sized monitoring pipeline. Legacy debug logging can consume disk and CPU rapidly and should be filtered, bounded and disabled after capture.

## 11. Read-only hardening inventory

This inventory changes nothing and highlights the main review surfaces:

```powershell
Import-Module DnsServer

$server = $env:COMPUTERNAME

$zones = Get-DnsServerZone -ComputerName $server
$cache = Get-DnsServerCache -ComputerName $server
$recursion = Get-DnsServerRecursion -ComputerName $server

$zones |
    Select-Object ZoneName, ZoneType, IsDsIntegrated, ReplicationScope,
        DynamicUpdate, SecureSecondaries

[pscustomobject]@{
    Server = $server
    RecursionEnabled = $recursion.Enable
    SecureResponse = $recursion.SecureResponse
    PollutionProtection = $cache.EnablePollutionProtection
    CacheLockingPercent = $cache.LockingPercent
}

Get-DnsServerForwarder -ComputerName $server
Get-DnsServerGlobalQueryBlockList -ComputerName $server
Get-DnsServerResponseRateLimiting -ComputerName $server
Get-DnsServerDiagnostics -ComputerName $server
```

Interpret each result against the server's role. Recursion enabled on an internal resolver may be correct; recursion reachable from an untrusted network is not. Zone transfers disabled on a purely AD-integrated deployment may be correct; a controlled secondary design needs explicit transfer targets.

## 12. Hardening baseline

- [ ] AD zones are integrated and set to secure-only dynamic updates.
- [ ] DHCP DNS registrations use a dedicated, minimally privileged identity where required.
- [ ] `DNSAdmins` and all delegated zone ACLs are reviewed and monitored.
- [ ] AD DNS is unreachable from untrusted networks.
- [ ] Recursion and forwarding are limited to the intended clients and destinations.
- [ ] Zone transfers are disabled or restricted to explicit secondaries.
- [ ] Cache pollution protection and cache locking remain enabled.
- [ ] RRL is evaluated for exposed authoritative workloads and tested before enforcement.
- [ ] DNSSEC is deployed only with owned key rollover and validation operations.
- [ ] DNS audit events are centrally retained; high-volume diagnostics are temporary.
- [ ] Aging and scavenging are configured from measured DHCP and registration behavior, not generic timers.

## References

- [Dynamic DNS Update in Windows and Windows Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update)
- [DNS zones in DNS Server on Windows Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/zone-types)
- [What is DNSSEC on DNS Server in Windows Server?](https://learn.microsoft.com/en-us/windows-server/networking/dns/dnssec-overview)
- [Validate and secure DNS responses using DNSSEC](https://learn.microsoft.com/en-us/windows-server/networking/dns/validate-dnssec-responses)
- [Enable DNS Logging and Diagnostics in Windows Server](https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-logging-and-diagnostics)
- [DnsServer PowerShell module](https://learn.microsoft.com/en-us/powershell/module/dnsserver/?view=windowsserver2025-ps)
