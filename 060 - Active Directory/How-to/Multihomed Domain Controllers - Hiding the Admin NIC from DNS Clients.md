# Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients
🗓️ Published: 2026-07-20

## Introduction

Picture this: everything works… *most* of the time. Users authenticate, group policies apply, shares open. Then, seemingly at random, someone complains that logon is slow, a mapped drive won't connect, or an app throws a timeout. You check five minutes later — it's fine again. 🤷

Welcome to the wonderful world of the **multihomed domain controller**.

A *multihomed* DC is simply a domain controller with **more than one network card**. This happens more often than you'd think: a dedicated administration/out-of-band network, an inter-forest trust routed over a management link, a backup VLAN… Whatever the reason, the moment your DC has a second NIC, it will happily **register that second IP address in DNS** — and your clients, who can't even reach that network, will sometimes be handed that unreachable IP.

That's the whole problem in one sentence: **the DC advertises an IP the clients can't talk to, and DNS occasionally serves it.**

In this article we'll:

- Demystify **how a DC registers itself in DNS**.
- Understand **why** the failures are intermittent.
- Fix it properly with a **rock-solid baseline** (stop publishing the admin IP, and clean up what's already there).
- Go further with an **optional, surgical refinement** using DNS Policies and Zone Scopes — including all the sharp edges nobody warns you about.

Our lab setup for the whole article:

| Item | Value |
|---|---|
| Domain | `contoso.com` |
| Domain controller | `MM-DC1` (DC + DNS) |
| **Production** NIC (DC — *every* client queries DNS here) | `192.168.99.1` |
| **Administration** NIC (OOB/management — to hide) | `172.16.1.1` |
| Ordinary client network (no route to the admin net) | e.g. `10.0.0.0/24` |
| Admin workstation network | `172.16.1.0/24` |

> 💡 Throughout the article, remember the golden rule we're aiming for: **the admin NIC (`172.16.1.1`) must never end up in a DNS answer given to a normal client.**

> 🗺️ **One routing assumption that makes the whole story consistent.** Admin workstations sit on `172.16.1.0/24`, but they point their DNS at the DC's **production** IP `192.168.99.1` (over a route) — **never** at `172.16.1.1`. So the admin NIC is a *pure management interface* (RDP, WinRM, backup, monitoring…), never a DNS resolver for anyone. That single decision is what lets us safely stop the DNS server from listening on the admin IP (Part 3, Step 3️⃣) **without** cutting the admins off — and it keeps Part 4 meaningful. (It assumes the route is **un-NATted**, so the DC still sees the real `172.16.1.x` source address — more on that in Part 4.)

---

## Part 1 — DNS 101: How does a client even find a Domain Controller?

Before fixing anything, let's understand what's happening under the hood. If you already know all this, skip to Part 2.



### 🔹 What is a DNS record, really?

DNS is basically a giant phone book. You ask "what's the IP of `MM-DC1.contoso.com`?" and it answers "`192.168.99.1`". The entry that maps a name to an IPv4 address is called an **A record**.

```text
MM-DC1.contoso.com   →   A   →   192.168.99.1
```

Simple. The catch: a single name can have **several** A records.

```text
MM-DC1.contoso.com   →   A   →   192.168.99.1   (production NIC)
MM-DC1.contoso.com   →   A   →   172.16.1.1   (administration NIC)
```

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-02-34.png>)

Now we have a problem waiting to happen. Which one does the client get?

### 🔹 Round-robin: DNS deals the cards

When a name has multiple A records, the DNS server hands them out in a **rotating order** — this is called **round-robin**. First client gets `192.168.99.1` on top, next client gets `172.16.1.1` on top, and so on. It's a primitive load-balancing trick.

For a normal service with two reachable IPs, round-robin is fine. But here, **one of the two IPs is a dead end for clients**. So roughly *half the time*, the client is told to go talk to `172.16.1.1` — a network it can't even route to. Hello, random failures. 👋

> 🧠 **This is the root cause of the "it works intermittently" symptom.** Nothing is broken. DNS is doing exactly what it was designed to do — it just doesn't know that one of those IPs is unreachable for clients.

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-03-09.png>)

### 🔹 "Netmask ordering" — a partial helper, not a fix

Windows DNS has a feature called **netmask ordering** (aka subnet prioritization): if the client's own subnet matches one of the returned records, DNS floats that record to the top. Sounds like it could save us, right?

Not quite. Netmask ordering **reorders** the list; it does **not remove** the bad IP. The unreachable `172.16.1.1` is still in the response, just lower in the list. Many resolvers only try the first IP, but some fail over, cache the wrong one, or ignore ordering entirely. It reduces the pain, it doesn't cure it. We need the admin IP to **not be there at all**.

---

## Part 2 — Who keeps registering the admin IP? (There are THREE culprits)

Here's the key insight that trips up most people. On a domain controller, **three different components** register records in DNS, and you must tame **all of them** — otherwise you fix one and another silently puts the bad IP back.

### 🔹 Culprit #1 — the DNS Client service (per-NIC registration)

Every network adapter in Windows has a checkbox: *"Register this connection's addresses in DNS"*. When enabled (the default), the **DNS Client** service dynamically registers an A record for the host name using **that NIC's IP**.

So your admin NIC, left with defaults, cheerfully registers:

```text
MM-DC1.contoso.com   →   A   →   172.16.1.1
```

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-04-22.png>)

That's culprit #1: the host's own A record via the admin card.


### 🔹 Culprit #2 — the Netlogon service (the DC locator records)

This is the sneaky one. A domain controller is not just any server — it advertises a whole catalog of **SRV records** and special A records so that clients can *locate* domain services (LDAP, Kerberos, Global Catalog…). This is the job of the **Netlogon** service.

Netlogon re-registers this catalog **on startup and roughly every hour**. And critically: it registers records for **every bound IP address on the DC**. That includes the admin NIC.

Among the things Netlogon publishes is the **root-of-zone A record** — the record for `contoso.com` itself (shown as *"(same as parent folder)"* in the DNS console). Internally this is called the **`LdapIpAddress`** record. If the admin IP is bound, Netlogon adds `172.16.1.1` there too.

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-05-18.png>)

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-05-45.png>)

> ⚠️ **This is why fixing only the NIC checkbox isn't enough.** You untick the box, delete the record… and within the hour Netlogon puts `172.16.1.1` right back into the zone. Whack-a-mole. 🔨

### 🔹 Culprit #3 — the DNS Server service itself (the one everyone forgets)

Here's the culprit almost every tutorial misses — and the one that quietly defeats the other two fixes. **If the DC also runs the DNS Server role** (nearly all of them do), the DNS Server service **registers a host A record for every IP address it is configured to _listen on_**.

By default, DNS listens on **all** of the server's IPs — including the admin NIC. So even after you untick the NIC checkbox (culprit #1) *and* muzzle Netlogon (culprit #2), the DNS Server calmly re-adds:

```text
MM-DC1.contoso.com   →   A   →   172.16.1.1
```

…straight into its own zone, **ignoring the DNS Client settings entirely** (it's a different service). This is spelled out in Microsoft **KB 2023004**, which lists **three** services responsible for the host A record: Netlogon, the DNS Server service, and the DHCP/DNS Client.

> 🕵️ **How to catch it red-handed.** `repadmin /showobjmeta <DC> "<dnsNode DN>"` on the `dnsRecord` attribute shows the **Originating DSA** (the DC that last wrote the record). In the lab it pointed at the DC itself, with a version counter climbing to `Ver: 245` while the admin IP kept reappearing — proof the DNS Server was re-writing the record on its own.

### 🔹 Summary of the three sources

| Culprit | Registers | Controlled by |
|---|---|---|
| **DNS Client** | Host A record (`MM-DC1`) via each NIC | Per-adapter "Register this connection" setting |
| **Netlogon** | Root-of-zone A (`LdapIpAddress`), `_msdcs` records, SRV records — for **all** bound IPs | `DnsAvoidRegisterRecords` registry value |
| **DNS Server service** | Host A for **every IP it listens on** | DNS Server **"Listen On"** interfaces list |



To win, we address **all three**. Let's go.

---

## Part 3 — The Baseline Fix (do this first, always)

The strategy: **make the admin IP stop being published**, then **clean up** whatever is already in DNS. Four steps. This alone solves the intermittent-failure problem for clients.

### 1️⃣ Stop the admin NIC from registering itself

Run this **on each DC**, targeting the **administration** adapter only (leave the production NIC alone!).

First, identify your adapters so you use the right name:

```powershell
# List adapters with their names and indexes
Get-NetAdapter | Format-Table Name, InterfaceIndex, InterfaceDescription, Status
```

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-06-43.png>)

Say the admin card is named `Admin`. Disable its DNS registration:

```powershell
# On the ADMINISTRATION NIC only
Set-DnsClient -InterfaceAlias "Admin" `
    -RegisterThisConnectionsAddress $false `
    -UseSuffixWhenRegistering $false
```

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-07-30.png>)

- `RegisterThisConnectionsAddress $false` → the DNS Client stops registering the host A record via this NIC.
- `UseSuffixWhenRegistering $false` → it also stops registering the connection-specific suffix. Belt and suspenders.

Verify:

```powershell
Get-DnsClient | Select-Object InterfaceAlias, RegisterThisConnectionsAddress
```

> 🛠️ **The registry equivalent** (handy for GPO or scripting): on the admin interface key
> `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`
> the cmdlet sets **`RegistrationEnabled = 0`** for that NIC. (It does **not** set the broader,
> server-wide `DisableDynamicUpdate` — a different switch you don't need here, and one that would
> also stop your *production* NIC from registering.)

That neutralizes **culprit #1**. But Netlogon (culprit #2) is still out there.

### 2️⃣ Stop Netlogon from re-publishing the admin IP

Netlogon reads a registry value telling it which record **types** it should *not* register. It lives here:

`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters` → **`DnsAvoidRegisterRecords`** (a `REG_MULTI_SZ`, i.e. a multi-line list).

The record most likely to hurt you is the **root-of-zone A record** (`LdapIpAddress`) — the *"(same as parent folder)"* entry that ends up pointing at `172.16.1.1`. Tell Netlogon to skip it:

```powershell
$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'

Set-ItemProperty -Path $key -Name 'DnsAvoidRegisterRecords' `
    -Type MultiString -Value @('LdapIpAddress')

Restart-Service Netlogon
```

After the restart, Netlogon stops publishing that root A record entirely.

> 🔸 **Is your DC a Global Catalog?** Then there's a second A record that leaks: `gc._msdcs.contoso.com` (internally the `GcIpAddress` record). It only exists on GC servers, and it aggregates every bound IP the same way — so it can hand out `172.16.1.1` too. If (and only if) you see the admin IP show up on `gc._msdcs`, add `GcIpAddress` alongside `LdapIpAddress`:
>
> ```powershell
> Set-ItemProperty -Path $key -Name 'DnsAvoidRegisterRecords' `
>     -Type MultiString -Value @('LdapIpAddress','GcIpAddress')
>
> Restart-Service Netlogon
> ```

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-20-08-36.png>)

> ⚠️ **Know the limitation — this is important.** `DnsAvoidRegisterRecords` filters by **record type**, **not by IP address**. Netlogon has no way to say "publish `192.168.99.x` but not `172.16.x`". It's all-or-nothing *per record type*. That's why the truly *selective* lever — the one that cares about *which NIC* — is **Step 1**. Step 2 is here to suppress the zone-root entries that would otherwise leak the admin IP because they aggregate every bound address.

> 📎 **Start minimal, expand only if it leaks.** `LdapIpAddress` (the zone-root A) is the usual troublemaker; `GcIpAddress` (the `gc._msdcs` A) is next in line on a GC. Both are **A records that carry an IP** — those are the ones worth suppressing here. Leave the **SRV** mnemonics (`Ldap`, `Dc`, `Gc`, `Kdc`…) alone: they point at the host *name* `MM-DC1.contoso.com`, which Step 1 already cleaned up — carpet-bombing them will break DC location. Add records one at a time, verify, repeat.

### 3️⃣ Stop the DNS Server from listening on (and auto-registering) the admin IP

This is the step the forums forget — and without it, the two fixes above are silently undone (this is exactly what culprit #3 does). Tell the DNS Server service to **listen only on the production IP**, so it stops auto-registering the admin address.

There is **no** `-ListenAddresses` parameter on `Set-DnsServerSetting`; the reliable, long-standing way is `dnscmd` — the CLI equivalent of unticking the admin IP under **DNS console → server Properties → Interfaces → _Listen on only the following IP addresses_**:

```powershell
# Restrict DNS listening to the production IP only
dnscmd MM-DC1 /ResetListenAddresses 192.168.99.1

Restart-Service DNS
```

Verify what the service **actually** listens on — don't trust `Get-DnsServer` here, its `ListenAddresses` reads back empty on some versions. Check the live sockets instead:

```powershell
Get-NetTCPConnection -LocalPort 53 -State Listen |
    Select-Object LocalAddress, LocalPort | Sort-Object LocalAddress -Unique
```

The admin IP (`172.16.1.1`) must **not** appear — only `192.168.99.1` (plus the loopbacks `127.0.0.1` / `::1`).

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-21-10-57-58.png>)

> 🧭 **Also check the zone's Name Servers tab.** DNS console → zone `contoso.com` → Properties → **Name Servers**: if `172.16.1.1` is listed for this DC, remove it. (It's often just a live reflection of the A records — but verify.)

> ⛔ **Don't reach for the global `DisableDynamicUpdate`.** You'll find advice to set `DisableDynamicUpdate = 1` on `HKLM\...\Tcpip\Parameters` (server-wide). Skip it: it's too broad (it also kills the **production** NIC's registration) and — proven in the lab — **unnecessary** once this Listen On step is done. Note too that `Restart-Service Dnscache` is blocked by Windows, so that setting would only take effect after a reboot anyway.

That neutralizes **culprit #3** — the real reason the admin IP kept coming back.

### 4️⃣ Clean up the records that are already there

Steps 1, 2 and 3 stop **future** registrations. They do **not** retroactively delete what's already sitting in the zone. Time to sweep. Run these on the DNS server hosting the zone — and remember there are **two zones** to check: `contoso.com` **and** `_msdcs.contoso.com` (the DC-locator machinery keeps `gc` A records and GUID-based CNAMEs there too).

First, *look* before you delete — scan **both** zones for any A record in the admin range:

```powershell
$adminPrefix = '172.16.'

'contoso.com','_msdcs.contoso.com' | ForEach-Object {
    Write-Host "=== Zone: $_ ===" -ForegroundColor Cyan
    Get-DnsServerResourceRecord -ZoneName $_ -RRType A |
        Where-Object { "$($_.RecordData.IPv4Address)" -like "$adminPrefix*" } |
        Format-Table HostName, @{n='IP';e={"$($_.RecordData.IPv4Address)"}}
}
```

> 💡 **Why the `"$(...)"` quoting matters.** `RecordData.IPv4Address` is an `IPAddress` **object**, not a string. A bare `-like "172.16.*"` comparison silently matches **nothing**. Forcing it to a string with `"$($_.RecordData.IPv4Address)"` makes the filter actually work. (Ask me how I know. 😅)

Now delete whatever showed up. The most reliable way is to **fetch the record object first, then remove it by `-InputObject`** — the `-Name`/`-RecordData` form is finicky about the IP type and often throws *"Failed to get … record"*:

```powershell
'contoso.com','_msdcs.contoso.com' | ForEach-Object {
    $zone = $_
    Get-DnsServerResourceRecord -ZoneName $zone -RRType A |
        Where-Object { "$($_.RecordData.IPv4Address)" -like "$adminPrefix*" } |
        ForEach-Object {
            Write-Host "Removing $($_.HostName) -> $($_.RecordData.IPv4Address) from $zone" -ForegroundColor Yellow
            Remove-DnsServerResourceRecord -ZoneName $zone -InputObject $_ -Force
        }
}
```

> 🧹 This one loop cleans **both** zones and every offending record (host A, the zone-root *"(same as parent folder)"* `@` record, `gc`…) in a single pass — no need to know each name in advance. Repeat the whole cleanup for **every DC** you've hardened.

> 🔁 **On AD-integrated zones, harden every DC *before* you clean, and clean every DC before you sync.** Each record is a value of the **non-linked** multi-valued attribute `dnsRecord`, which AD replicates **as one block** with last-writer-wins at the *attribute* level (unlike a *linked* attribute such as `member`, which replicates per value). Deleting on one DC normally propagates fine (it bumps the version / writes a tombstone). The record **resurrects** only when another DC is **still actively re-registering** the admin IP: that DC's version keeps climbing, so its full value set — admin IP included — wins the conflict and overwrites your clean copies (the mysterious "it comes back after ~15 min"). So: apply Steps 1–3 on **all** DCs first (stop the re-registration), **then** purge on all DCs, **then** `repadmin /syncall /AdePq` — never sync while one DC is still dirty or still re-registering.

> ✅ A *"Failed to get … record"* / *record not found* error just means that particular record wasn't there — harmless, carry on.

### ✅ Validate the baseline

Force a fresh registration and confirm the admin IP does **not** come back:

```powershell
# Re-register and restart the locator
ipconfig /registerdns
Restart-Service Netlogon

# Wait a moment, then re-check BOTH zones
'contoso.com','_msdcs.contoso.com' | ForEach-Object {
    Get-DnsServerResourceRecord -ZoneName $_ -RRType A |
        Where-Object { "$($_.RecordData.IPv4Address)" -like "172.16.*" }
}
```

If that last command returns **nothing**, 🎉 you're done — clients will now only ever receive `192.168.99.1`.

A couple of good-hygiene checks while you're here:

```powershell
# Make sure the production NIC has the lower (preferred) metric
Get-NetIPInterface | Sort-Object InterfaceMetric |
    Format-Table InterfaceAlias, AddressFamily, InterfaceMetric
```

> 🧭 **Fun fact / sanity note:** Microsoft has always recommended *against* multihomed domain controllers precisely because of this DNS behavior (and routing quirks). If you can avoid the second NIC entirely, do — but when a management network is a hard requirement, the four steps above are your friend.

![](<./assets/Multihomed Domain Controllers - Hiding the Admin NIC from DNS Clients/2026-07-20-17-15-35.png>)

> ⚠️ **Caveat before you go further — "Listen On" and "reachability" are two sides of the same coin.**
> Step 3️⃣ removed the admin IP from the DNS server's **Listen On** list. Remember that *listening* and *auto-registering* are **coupled**: dropping `172.16.1.1` from Listen On kills the rogue A record **and** stops the DC from answering **any** DNS query sent to `172.16.1.1:53`.
>
> That's usually exactly what you want — but it has a consequence:
>
> - ✅ **If the admin subnet can route to the DC's production IP** (`192.168.99.1`) — our setup — admin clients point their DNS at `192.168.99.1`, present their real `172.16.1.0/24` source address (route must be **un-NATted**), and everything below (Part 4) still works. No conflict. This is the recommended design.
> - ⛔ **If the admin subnet is fully isolated** (no route to `192.168.99.1`) **and** you still need this DC to serve DNS to those admin clients, then you **cannot** apply Step 3️⃣ on this DC — the admin clients would lose their only resolver.
>
> In that isolated case the trade-off flips: you **keep** `172.16.1.1` in Listen On (so the DC stays reachable), which means the DNS Server **will** keep auto-registering `MM-DC1 → 172.16.1.1`. And here's the catch most people miss: **dynamic auto-registration always writes into the _default_ scope.** So the default scope now holds *both* `192.168.99.1` **and** `172.16.1.1` — and the vanilla Part 4 policy (admin subnet → `AdminScope`, *everyone else* → default) would hand your **production** clients that polluted default scope. The double-resolution bug is back. ❗
>
> Part 4 as written only works because Step 3️⃣ ran first and left the **default scope clean** — `AdminScope` then merely *adds* an answer for admins. Take Step 3️⃣ away and that premise collapses: `AdminScope` hides nothing from prod clients, because prod clients read the **polluted default scope**, not `AdminScope`.
>
> In theory you could patch it by adding a second scope — a static **`ProdScope`** holding *only* `192.168.99.1` — and a policy routing every non-admin query for `MM-DC1` into it, so prod clients never touch the dirty default scope. It works on paper, but it's **not worth it in practice:**
>
> - `ProdScope` is **static** — dynamic registration only ever writes the default scope, so you now **hand-maintain** the DC's own prod A record forever, and it never self-heals (IP change, scavenging, rebuild… all manual).
> - Scopes and policies **don't replicate** (see Part 5), so you repeat this static plumbing on **every DC**, for **every DC name**.
> - You're permanently papering over a record you can't delete — any gap in the policies and the admin IP leaks straight back out.
>
> Compare that to Step 3️⃣: one command, the admin record simply **never exists**, nothing to filter, self-healing. The lesson is blunt — **make the admin subnet route to the prod IP so you *can* run Step 3️⃣.** The isolated design is a last resort, not a goal.
>
> | Scenario | You sacrifice | You keep |
> |---|---|---|
> | **Baseline (Step 3️⃣)** | The DC no longer answers DNS on the admin IP | One clean default scope, self-healing, nothing to filter |
> | **Isolated admin subnet** | A lot of simplicity: a static, hand-maintained `ProdScope` on every DC, forever | The DC stays reachable by admins **and** the admin record stays hidden from everyone else |
>
> Bottom line: **Part 4 is not just a nicety** — in an isolated-admin-network design it's the *only* thing that can hide the admin IP at all. But it's a permanent, hand-maintained workaround. If you can reach the prod IP over a route, do Step 3️⃣ and skip the whole mess.

---

## Part 4 — The Optional Refinement: DNS Policies & Zone Scopes

Everything above **hides** the admin IP from clients. But what if you *still* want the admin IP to be resolvable — **only** for machines on the admin network? For example, your admin workstations should reach `MM-DC1` at `172.16.1.1`, while everyone else keeps getting `192.168.99.1`.

> 🧩 **Prerequisite — this only makes sense with asymmetric reachability.** This refinement assumes the admin workstations on `172.16.1.0/24` **can** actually reach `172.16.1.1` (they're on that network), while ordinary clients **cannot**. It also assumes those admins query DNS on the DC's prod IP `192.168.99.1` over an **un-NATted** route, so the DC still sees their real `172.16.1.x` source. If the admin network is genuinely isolated (no route to the prod IP) or NATted, stop at Part 3 — serving an IP nobody can route to just recreates the original bug.

That's where **DNS Policies** and **Zone Scopes** come in (Windows Server **2016+**). This is a *refinement layered on top of* the baseline — never a replacement for it. And there is **no GUI** for this: it's PowerShell (or `dnscmd`) all the way.

### 🔹 How it works

A **Zone Scope** is a second, independent copy of records that lives inside the same zone. A zone always has a **default scope**; you can add one or more **custom scopes** alongside it.

- **Default scope** = the zone's normal records. Dynamic updates (DNS Client + Netlogon) only ever write **here**.
- **Custom scope** (e.g. `AdminScope`) = records **you** add manually (static only — nothing updates it automatically).

A **Query Resolution Policy** then decides *which scope* answers a given request, based on **where the query came from** (client subnet) and **what name** was asked (FQDN).

So the four building blocks are:

| Object | Role | Cmdlet |
|---|---|---|
| **Client Subnet** | Defines the *source* network of the requester | `Add-DnsServerClientSubnet` |
| **Zone Scope** | The extra scope holding admin records (zone-level) | `Add-DnsServerZoneScope` |
| **Record in scope** | The actual admin A record (static) | `Add-DnsServerResourceRecord … -ZoneScope` |
| **Query Policy** | Maps subnet + FQDN → scope | `Add-DnsServerQueryResolutionPolicy` |

Let's build them in order. **All of this runs on the DNS server (the DC).**

### 1️⃣ Define the admin *source* network

This is the subnet **from which admin machines send their DNS queries** — the source IP they present to the DC. Not the DC's admin IP; the *requester's* IP.

```powershell
Add-DnsServerClientSubnet -Name "AdminSubnet" -IPv4Subnet "172.16.1.0/24"

# Multiple admin networks? List them:
# Add-DnsServerClientSubnet -Name "AdminSubnet" -IPv4Subnet "172.16.1.0/24","10.99.0.0/24"

Get-DnsServerClientSubnet   # verify
```

> ☝️ **Gotcha — DNS forwarders.** Client-subnet matching only works if the admin machines query the DC **directly**. If they go through an intermediate DNS forwarder, the authoritative DC sees the *forwarder's* IP as the source, not the admin's — and the policy won't match the way you expect. (In a simple, forwarder-free setup, you're fine.)

> 🛑 **Gotcha — NAT on the admin→prod route.** Same trap, different cause. Because our admins reach the DC's prod IP `192.168.99.1` *across a route*, that route must **not** NAT their traffic. If the gateway rewrites the source to its own IP, the DC sees that instead of `172.16.1.x`, the `ClientSubnet` match fails, and the admin quietly falls through to the default scope (getting `192.168.99.1` instead of `172.16.1.1`). Keep the admin→prod path routed, not NATted.

### 2️⃣ Create the scope — at the ZONE level

A crucial point that confuses everyone: **a zone scope is created on the *zone* (`contoso.com`), never on a record (`MM-DC1`)**. `MM-DC1` isn't a zone — it's just an A record living *inside* the zone.

```powershell
Add-DnsServerZoneScope -ZoneName "contoso.com" -Name "AdminScope"

Get-DnsServerZoneScope -ZoneName "contoso.com"   # verify
```

### 3️⃣ Put the admin record into the scope (static)

Now add the admin A record — but **into `AdminScope`**, not the default drawer:

```powershell
Add-DnsServerResourceRecord -ZoneName "contoso.com" -A `
    -Name "MM-DC1" -IPv4Address "172.16.1.1" -ZoneScope "AdminScope"
```

Remember: this drawer is **static**. Nothing refreshes it automatically. If the admin IP ever changes, you update it here by hand.

### 4️⃣ Create the policy that routes admin queries to the scope

Finally, the receptionist. This is the object that **ties it all together**: *if* the query comes from the admin subnet **AND** asks for a specific DC name, *then* answer from `AdminScope`.

```powershell
Add-DnsServerQueryResolutionPolicy -Name "AdminPolicy_MM-DC1" `
    -Action ALLOW `
    -ClientSubnet "EQ,AdminSubnet" `
    -Fqdn "EQ,MM-DC1.contoso.com" `
    -ZoneScope "AdminScope,1" `
    -ZoneName "contoso.com"

Get-DnsServerQueryResolutionPolicy -ZoneName "contoso.com"   # verify
```

Let's decode every parameter, because each one matters:

- `-ClientSubnet "EQ,AdminSubnet"` → match only queries **coming from** the admin network.
- `-Fqdn "EQ,MM-DC1.contoso.com"` → match only queries **for this exact name**.
- `-ZoneScope "AdminScope,1"` → send matches to `AdminScope`. (More on that `,1` below.)
- `-ZoneName "contoso.com"` → the policy applies to this zone.

The criteria are **cumulative (AND)**: a query must be from the admin subnet **and** ask for `MM-DC1.contoso.com` for the policy to fire. Anything else falls through to the default scope.

### 🔹 What's that `,1` in `"AdminScope,1"`?

It's a **weight**, used for load-balancing **when a policy points at several scopes**. The syntax is `"ScopeName,Weight"`, and you separate multiple scopes with `;`:

```powershell
# Example of weighting across two scopes (NOT what we want here):
# -ZoneScope "ScopeA,3;ScopeB,1"   → ~3 answers from A for every 1 from B
```

In our case there's **only one scope**, so the weight is irrelevant — `1` is just the conventional default. Leave it as is.

> 🧩 Don't confuse **weight** (splits traffic *between scopes*) with **`-ProcessingOrder`** (decides which *policy* is evaluated first when you have several). With a single scope and a single policy, neither matters much yet.

---

## Part 5 — The Sharp Edges of Zone Scopes (read this before you deploy)

Zone scopes are powerful but full of gotchas. These are the ones that will bite you if you don't know them.

### ⚠️ Gotcha #1 — There is NO fallback *inside* a scope

This is the big one. Once a query is routed **into** `AdminScope`, resolution happens **only there**. If the requested record isn't in that drawer, the client gets an **empty answer / NXDOMAIN** — DNS does **not** fall back to the default scope.

Scopes are **separate record sets**, not layers that stack. There is no "look in admin, and if it's missing, check prod."

**Consequence:** if you naïvely routed the *entire zone* to `AdminScope` for the admin subnet, your admins would resolve **only** the handful of records you manually placed there — and lose everything else in the zone (other servers, CNAMEs, and all those SRV records). You'd break their production resolution.

### ✅ Why targeting the FQDN saves you

This is exactly why the policy uses `-Fqdn "EQ,MM-DC1.contoso.com"` instead of matching the whole zone. Watch how it plays out:

| Query from admin subnet | Name requested | Policy fires? | Scope used | Result |
|---|---|---|---|---|
| ✔ Yes | `MM-DC1.contoso.com` | ✅ Yes (both criteria) | `AdminScope` | Admin IP `172.16.1.1` |
| ✔ Yes | `fileserver.contoso.com` | ❌ No (FQDN ≠ MM-DC1) | **default** | Normal prod IP |
| ✔ Yes | `anything-else.contoso.com` | ❌ No | **default** | Normal prod resolution |

The key realization: **for every name except `MM-DC1`, the policy never triggers**, so those queries **never enter** `AdminScope` — and therefore never hit the "no fallback" wall. They flow to the default scope like always. The "no fallback" rule only applies *after* routing; the FQDN filter makes sure we only route the names we've actually populated.

### ⚠️ Gotcha #2 — 1-to-1 correspondence is mandatory

Every name you want served from the admin scope needs **both**:

1. a **record inside the scope**, and
2. an **FQDN entry in a policy**.

Get this wrong and:

- Record in scope but **no** FQDN in a policy → nothing routes there → the record is **never served**.
- FQDN in a policy but **no** record in the scope → queries get routed into an **empty drawer** → **empty answer** for that name.

You can list several FQDNs in one policy (`-Fqdn "EQ,MM-DC1.contoso.com,MM-DC2.contoso.com"`), but every one of them must have its matching record in the scope. Keep the scope **minimal** — just the DC A records you truly need. Resist the urge to recreate SRV/`_msdcs` in there; that path leads to madness.

### ⚠️ Gotcha #3 — Scopes and policies do NOT replicate

Records in an AD-integrated zone replicate between DCs via Active Directory. But **zone scopes and DNS policies are *local* to each DNS server** — they do **not** replicate.

**Consequence:** you must recreate the client subnet + scope + record + policy on **every DC** that should apply this behavior (or push them via a script). Forgetting one DC means inconsistent answers depending on which server a client happens to hit.

| Element | Created where | Replicates between DCs? |
|---|---|---|
| **Zone scope** | On the DNS server, bound to the zone | ❌ No — per server |
| **Query policy** | On the DNS server, on the zone | ❌ No — per server |
| **Client subnet** | On the DNS server | ❌ No — per server |
| **Record inside a custom scope** | In the scope (static) | ❌ No — per server |

---

## TL;DR

- A **multihomed DC** publishes **all** its IPs in DNS. Thanks to **round-robin**, clients randomly get the **admin IP they can't reach** → intermittent failures.
- **Three** components register that IP: the **DNS Client** (per-NIC), **Netlogon** (DC-locator records, including the zone-root `LdapIpAddress`), and — the one everyone forgets — the **DNS Server service**, which auto-registers a host A for **every IP it listens on**. Fix **all three**.
- **Baseline (do this first):**
  1. `Set-DnsClient -RegisterThisConnectionsAddress $false` on the **admin NIC**.
  2. `DnsAvoidRegisterRecords = LdapIpAddress` under Netlogon, then restart it.
  3. `dnscmd <DC> /ResetListenAddresses <prodIP>` + `Restart-Service DNS` so DNS stops **listening on** (and registering) the admin IP. Also clear the admin IP from the zone's **Name Servers** tab.
  4. **Purge** the leftover `172.16.x` A records (host + zone-root `@` + `_msdcs`) — on **every** DC, *then* `repadmin /syncall` (or one replica resurrects it).
- **Optional refinement** (Server 2016+): **DNS Policies / Zone Scopes** let the **admin subnet** still resolve the admin IP — but:
  - **No fallback** inside a scope → always **target the DC FQDN**, never the whole zone.
  - **1-to-1**: each name = one record in the scope **+** one FQDN in a policy.
  - Scopes/policies **don't replicate** → configure **every DC**.
- Golden rule, once more for the road: **the admin NIC must never appear in a DNS answer served to a normal client.** 🧙

---

> 📝 *Personal note: multihomed DCs are officially discouraged by Microsoft. If a management network is unavoidable, the baseline in Part 3 is the real fix — Part 4 is just the elegant cherry on top when admins need targeted resolution.*
