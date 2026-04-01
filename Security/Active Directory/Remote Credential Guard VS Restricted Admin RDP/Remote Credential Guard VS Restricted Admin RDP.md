# Remote Credential Guard vs Restricted Admin RDP — Deep Dive
🗓️ Published: 2026-04-01

Let's talk about one of the most underrated attack surfaces in enterprise environments: **your RDP sessions**.

Every time you RDP into a server with your shiny Domain Admin credentials, you're basically leaving a copy of your keys on the remote machine's doormat. If that server is compromised — and let's be honest, it's not a matter of *if* but *when* — an attacker gets your Kerberos tickets, NTLM hashes, or even your plaintext password straight from LSASS memory. Welcome to **Pass-the-Hash**, **Pass-the-Ticket**, and all their friends.

Microsoft gave us two weapons to fight this: **Remote Credential Guard** and **Restricted Admin mode**. Both prevent your credentials from being stored on the remote host — but they work *very* differently under the hood, and picking the wrong one can either break your day or give you a false sense of security.

This article goes deep into both, with full implementation details. If you run a **tiering model**, manage **PAWs**, or simply care about not getting pwned — this one's for you.

🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard

---

### 💥 The Problem: Why Standard RDP Is Basically Handing Out Your Keys

Here's what happens during a *normal* RDP session — the kind most of us use every day without thinking twice:

1. You type your credentials in the RDP client
2. Those credentials are sent to the remote host
3. The remote host caches them in **LSASS memory** (because Windows needs them for SSO to other resources)
4. You do your work, disconnect, go grab a coffee
5. **Your credentials are still sitting in LSASS on that server** ☕

Now imagine an attacker lands on that server. They run a certain well-known tool (rhymes with *Bimikatz*), dump LSASS, and boom — they have your NTLM hash, your Kerberos TGT, maybe even your plaintext password if WDigest is enabled.

From there:
- **Lateral movement** — they use your hash to authenticate to other servers (*"Thanks for the Domain Admin creds, mate!"*)
- **Privilege escalation** — if you RDP'd with a Tier 0 account to a Tier 1 server, congrats, your Tier 0 is now compromised from a lower-trust zone
- **Post-disconnection risk** — you disconnected 3 hours ago? Doesn't matter. Your creds are still there, waiting to be harvested

This is not theoretical. This is **the #1 way attackers move laterally in Active Directory environments**. And the fix is surprisingly simple — just stop sending credentials to remote hosts.

---

### 🛡️ Restricted Admin Mode — The "I Don't Trust This Server At All" Option

Restricted Admin mode was introduced in **Windows 8.1 / Server 2012 R2** (KB2871997). Think of it as the paranoid option — and sometimes paranoia is a virtue.

**How it works under the hood:**

1. You launch `mstsc.exe /restrictedAdmin`
2. Your credentials **never leave your machine**. Not the hash, not the TGT, nothing.
3. On the remote host, your session authenticates to the network using the **server's own machine account** (`SERVERNAME$`) — not your user account
4. You're logged in as a local admin. You can do local work. But the moment you try to access a file share or RDP somewhere else... you're `SERVERNAME$`. Good luck with that.

**In practice:** It's like wearing a full hazmat suit to visit a friend's house. Very safe, but you can't really shake hands with anyone else while you're there.

```cmd
mstsc.exe /restrictedAdmin
```

**The good:**
- ✅ Credentials are **never sent** — nothing to steal, period
- ✅ Protected after disconnection — zero residual risk
- ✅ Works with NTLM *and* Kerberos

**The not-so-good:**
- ❌ **No SSO** — forget about accessing file shares, SQL servers, or anything else from that session
- ❌ **No multi-hop RDP** — you can't RDP from that session to another server with your identity
- ❌ **Requires local Administrators group** — not just Remote Desktop Users. This can conflict with least-privilege if you're not careful
- ⚠️ **Machine account PtH** — an attacker on that host could use the machine's credentials to authenticate *as the machine* to other systems. Less damage than a DA hash, but worth knowing

---

### 🔒 Remote Credential Guard — The Best of Both Worlds

Remote Credential Guard landed in **Windows 10 version 1607 / Server 2016**, and honestly, it's kind of brilliant.

**How it works under the hood (this is the cool part):**

1. You launch your RDP session (with policy or `/remoteGuard` switch)
2. Your credentials **never leave your machine**. Ever. The TGT stays home.
3. When the remote session needs a Kerberos ticket — say you open `\\fileserver\share` — the remote host says *"Hey client, I need a ticket for this SPN"*
4. Your **client machine** performs the Kerberos authentication locally, gets the Service Ticket, and sends just that ticket back through the RDP channel
5. The remote host uses the ticket. It never saw your TGT, your hash, or your password.

**In practice:** It's like having a personal assistant who holds your wallet. You point at what you want, they pay for it, but the cashier never sees your credit card. Magic. 🪄

```cmd
mstsc.exe /remoteGuard
```

**The good:**
- ✅ **Full SSO** — file shares, SQL, other RDP sessions... everything works seamlessly
- ✅ **Multi-hop RDP** — yes, you can RDP from that session to another host, and it still works
- ✅ **Credentials never touch the remote host** — Mimikatz finds nothing interesting
- ✅ Only needs **Remote Desktop Users** membership (not local admin)

**The catches (because there's always a catch):**
- ⚠️ **Kerberos only** — NTLM fallback is explicitly blocked. If your DNS or SPNs are wonky, the connection just fails. No fallback, no mercy.
- ⚠️ **AD domain-joined required** — both machines must be able to do Kerberos (client can be Entra ID joined → AD host, as long as Kerberos works)
- ⚠️ **No RD Gateway / Connection Broker** — direct connections only
- ⚠️ **No compound authentication** — device claims aren't forwarded
- ⚠️ **Session-bound risk** — while the session is active, an attacker on the remote host *could* use the open Kerberos channel to request tickets on your behalf. Once you disconnect → channel closed, game over for them. It's a time-limited window, not zero risk.

---

### ⚖️ Comparison Table

| Feature | Standard RDP | Remote Credential Guard | Restricted Admin |
|---------|-------------|------------------------|-----------------|
| **Credentials sent to remote host** | ✅ Yes | ❌ No | ❌ No |
| **SSO to other resources** | ✅ Yes | ✅ Yes | ❌ No (uses machine account) |
| **Multi-hop RDP** | ✅ Yes | ✅ Yes | ❌ No |
| **Credentials exposed after disconnect** | ⚠️ Yes (cached in LSASS) | ❌ No | ❌ No |
| **Pass-the-Hash protection** | ❌ No | ✅ Yes | ✅ Yes |
| **Risk during active session** | Credential theft | Ticket requests via channel | Local attacks only |
| **Authentication protocol** | Any (NTLM/Kerberos) | **Kerberos only** | Any (NTLM/Kerberos) |
| **Required group membership** | Remote Desktop Users | Remote Desktop Users | **Administrators** |
| **Minimum OS** | Any | Win 10 1607 / Server 2016 | Win 8.1 / Server 2012 R2 |
| **Works via RD Gateway** | ✅ Yes | ❌ No | ✅ Yes |
| **Domain join required** | No | Yes (Kerberos) | No |

---

### 🎯 So... Which One Do I Use?

Great question. Here's the cheat sheet:

**Go with Remote Credential Guard when:**
- You're administering servers from a **PAW** (this should be your default)
- You need **SSO** — file shares, SQL, RSAT tools from the remote session
- Both machines are **domain-joined** and Kerberos is working properly
- You're NOT going through an **RD Gateway** or **RD Connection Broker**
- Basically: **all day-to-day privileged RDP sessions**

**Go with Restricted Admin when:**
- You're doing **helpdesk support** on a potentially compromised machine (*"Help, my PC is acting weird"* — yeah, we've all been there)
- The remote host might already be owned — you don't even want session-bound Kerberos risk
- You don't need network access from the session (just local troubleshooting)
- The target doesn't support Remote Credential Guard (older OS, no Kerberos)
- You're connecting through an **RD Gateway**

**TL;DR from Microsoft:** Helpdesk → Restricted Admin. Admin work → Remote Credential Guard. Standard RDP with privileged accounts → **never, ever, please stop doing that**. 🙏

---

### 🔧 Implementation: Remote Host Configuration

Alright, let's get our hands dirty. First, the server side.

Remote hosts must allow delegation of nonexportable credentials. This single setting enables **both** Remote Credential Guard and Restricted Admin — so configure it once on all your servers and you're covered.

**Via Group Policy (recommended):**

```
Computer Configuration > Administrative Templates > System > Credentials Delegation
  → "Remote host allows delegation of nonexportable credentials" = Enabled
```

**Via Registry:**

```
Path:  HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
Name:  AllowProtectedCreds
Type:  DWORD
Value: 1
```

**Via PowerShell (quick test):**
```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" `
    -Name "AllowProtectedCreds" -Value 1 -PropertyType DWord -Force
```

---

### 🔧 Implementation: Client Configuration

Now the client side — this is where you choose *which* mode your admins will use. And this is where it gets interesting, because you can enforce it.

**Via Group Policy (recommended):**

```
Computer Configuration > Administrative Templates > System > Credentials Delegation
  → "Restrict delegation of credentials to remote servers" = Enabled
```

Then choose one of the following options in the dropdown:

| Option | Behavior |
|--------|----------|
| **Require Remote Credential Guard** | Only Remote Credential Guard is allowed. If it fails, the connection is blocked |
| **Require Restricted Admin** | Only Restricted Admin mode is allowed |
| **Restrict Credential Delegation** | Prefers Remote Credential Guard, falls back to Restricted Admin if RCG is not supported. **Recommended option** |

**Via Registry:**

```
Path:  HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation
Name:  RestrictedRemoteAdministration
Type:  DWORD
Value: 0 = Disabled
       1 = Require Restricted Admin
       2 = Require Remote Credential Guard
       3 = Restrict credential delegation (prefer RCG, fallback to RA)
```

And also set the type:

```
Name:  RestrictedRemoteAdministrationType
Type:  DWORD
Value: 2
```

**Via PowerShell (quick test):**
```powershell
# Enable "Restrict Credential Delegation" (prefer RCG, fallback to RA)
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
New-ItemProperty -Path $path -Name "RestrictedRemoteAdministration" -Value 3 -PropertyType DWord -Force
New-ItemProperty -Path $path -Name "RestrictedRemoteAdministrationType" -Value 2 -PropertyType DWord -Force
```

---

### ⚡ Quick Test Without GPO (Try It Right Now!)

Don't want to deploy a GPO just to test? No problem. You can try both modes immediately:

**Remote Credential Guard:**
```cmd
mstsc.exe /remoteGuard
```

**Restricted Admin:**
```cmd
mstsc.exe /restrictedAdmin
```

**How to verify it's actually working** — hop on the remote host and run:
```powershell
klist
```

- **Standard RDP:** you'll see your user's TGT and service tickets. An attacker's dream. 😱
- **Remote Credential Guard:** you'll see service tickets, but **no TGT** — those are being fetched from your client via the RDP channel. The remote host is just a ticket consumer, not a ticket holder.
- **Restricted Admin:** you'll see tickets for `SERVERNAME$` (the machine account), not your user.  Your identity isn't even on that box.

Pretty neat difference, right?

---

### ⚠️ Known Limitations and Gotchas (Read This Before You Deploy!)

Every security feature comes with trade-offs. Here's what will bite you if you don't plan ahead:

**Remote Credential Guard gotchas:**
- 🔥 **Kerberos or bust** — if DNS is misconfigured or SPNs are wrong, NTLM fallback is blocked and the connection simply fails. No error message will tell you *"hey, fix your DNS"*. You'll just stare at a black screen. Test your Kerberos first!
- 🚫 **No RD Gateway / Connection Broker** — direct connections only. If your architecture relies on RDS infrastructure, this won't work.
- 🚫 **No compound authentication** — device claims don't survive the hop. If a file server requires a device claim → access denied.
- 🚫 **Only the Windows Desktop app** (`mstsc.exe`) — the UWP Remote Desktop app is not supported. Yes, really.
- ⏰ **Session-bound risk** — an attacker on the remote host can abuse the Kerberos channel *while you're connected*. Disconnect = channel closed. Keep sessions short!
- 🔒 **No Entra ID-only remote hosts** — the target must be AD domain-joined. Entra ID → AD is fine, Entra ID → Entra ID is not.

**Restricted Admin gotchas:**
- 👑 **Requires local Administrators group** — not Remote Desktop Users. In a least-privilege world, this is awkward. You'll need to manage this via LAPS or dedicated admin groups.
- 🤖 **Machine account authentication** — network access from the session uses `SERVERNAME$`. Most file shares don't grant access to machine accounts, so expect *"Access Denied"* everywhere.
- 💔 **No SSO** — this is the #1 complaint. If your workflow involves opening RSAT, connecting to SQL, or mapping drives from the remote session... Restricted Admin will make you miserable.

**Both modes:**
- The remote host **must** have the *"Allow delegation of nonexportable credentials"* policy enabled. Forget this and nothing works.
- GPO changes require a **gpupdate or reboot**. Coffee break! ☕

---

### 📋 Recommended GPO Strategy for a Tiering Model

Here's a battle-tested GPO setup that works well in production:

| Scope | Policy | Value |
|-------|--------|-------|
| **All admin workstations (PAW)** | Restrict delegation of credentials to remote servers | **Restrict Credential Delegation** (prefer RCG, fallback RA) |
| **All servers (Tier 0, 1, 2)** | Remote host allows delegation of nonexportable credentials | **Enabled** |
| **Helpdesk workstations** | Restrict delegation of credentials to remote servers | **Require Restricted Admin** |

**What this gives you:**
- PAW users automatically get Remote Credential Guard when they RDP. If for some reason RCG can't work (e.g., hitting a 2012 R2 server), it falls back to Restricted Admin. Either way, credentials are never exposed. 🎯
- Helpdesk team *always* uses Restricted Admin — because the machines they connect to might already be compromised
- All servers accept both modes — one server-side policy covers everything

**Don't stop here! Layer it up with:**
- **Windows LAPS** — automated local admin password management. If you're still using the same local admin password across servers... we need to talk.
- **Protected Users group** — for Tier 0 accounts. Blocks NTLM, forces Kerberos, disables credential caching. Brutal but effective.
- **Credential Guard (VBS)** — on PAWs, to protect LSASS with virtualization-based security. Even if an attacker gets admin on your PAW, they still can't dump creds.
- **Network-level tiering** — use firewall rules to prevent Tier 0 credentials from ever touching lower-tier systems. Because the best defense against credential theft on a Tier 1 server is... never putting Tier 0 creds there in the first place.

---

### 🏁 Wrapping Up

If there's one takeaway from this article, it's this: **stop using standard RDP with privileged accounts**. Today. Right now.

Remote Credential Guard gives you the best balance of security and usability for daily admin work. Restricted Admin is your go-to for high-risk scenarios where you don't trust the target at all.

Both are free, built into Windows, and take 10 minutes to deploy via GPO. There's really no excuse anymore. Your future self (and your CISO) will thank you. 🍻

---

### 🔗 References

- 🔗 https://learn.microsoft.com/en-us/windows/security/identity-protection/remote-credential-guard
- 🔗 https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview
- 🔗 https://download.microsoft.com/download/7/7/A/77ABC5BD-8320-41AF-863C-6ECFB10CB4B9/Mitigating-Pass-the-Hash-Attacks-and-Other-Credential-Theft-Version-2.pdf
