# How Domain Controllers are Located Across Trusts

🗓️ Published: 2026-07-02

## Introduction

Here's THE question that comes up on repeat from multi-forest customers:

> "Do I need to add subnets from Forest A to Forest B so that clients find the correct DC across the trust?"

Short answer, for those of you itching to get back to /r/sysadmin: **no**. 🎉

Long answer: stick with me, because understanding the *why* is way more fun than memorizing the recipe. We're going to fire up Wireshark, get our hands dirty in the DNS/LDAP/Netlogon packets, and watch **DCLocator** do its magic live.

> ⚠️ **Quick point of clarification before we dive in**
>
> This post is about the scenario where **the subnets in the two forests do not overlap** (the client's IP from Forest A isn't covered by any subnet in Forest B). This is the classic *resource forest* setup with separate networks: federating via trust, corporate forest ↔ perimeter (DMZ) forest, etc.
>
> If your two forests have **conflicting** subnets (e.g. `10.1.1.0/24` means site "Detroit" in Forest A but means site "Siberia" in Forest B), that's a whole different beast, with its own gotchas. That'll be a future post.

## 🔹 Where's my DC? How a client finds its DC

Let's start at the beginning: how your workstation (or any domain member) finds a domain controller at startup.

For the demo, I configured **port mirroring** on my Hyper-V VMs and intercepted the entire network conversation from another VM. I filtered the traffic down to the trio we care about: **DNS, LDAP, and Netlogon**.

At startup, the first thing a domain member wants to do is authenticate. Well… almost. Before that, it needs to find a DC (local, hopefully 🙏). So it sends a DNS query to its primary DNS server, simply looking for an **LDAP server** in its own DNS domain.

My client queried DC01 (its primary DNS) for `_ldap._tcp.dc._msdcs.corp.milt0r.com`.

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-53-13.png)
*Figure 1 – First DNS queries at start*

The first frame shows the DNS query, the second shows the response. In the response data, we get a list of **all the SRV records**. Digging into the frame details, we can see every DC with an LDAP SRV record registered in the **global SRV list** — in other words, all the DCs in the forest configured to register their SRV records globally.

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-53-49.png)
*Figure 2 – DNS Response Frame Details*

Next, the client picks one of those "ARecord" entries and queries the hostname. Here it asks its DNS for the IP of `dc04.corp.milt0r.com` and gets back `10.2.1.11`.

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-54-21.png)
*Figure 3 – DNS Query: Round 2*

Notice that, from just that initial query for `_ldap._tcp.dc._msdcs.corp.milt0r.com`, we've already resolved the IP of a DC that's supposed to be hosting the LDAP service. Not bad. 😎

## 🔹 Anybody home? The famous LDAP "ping"

Netlogon now has everything it needs to contact the DC. Using the resolved IP, the client sends a **UDP ping** — really a UDP LDAP query — to the DC.

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-54-36.png)
*Figure 4 – UDP LDAP "ping" conversation*

DC04 replies to that "ping" as a **Netlogon SAM Response**. If no response comes back, the client tries another DC. The payload contains:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-54-53.png)
*Figure 5 – More frame details*

Check that out: **`ClientSiteName`**. The response to the UDP LDAP query tells the client which **site** it belongs to. Now you know. 🧙 That value ends up written into the client's registry, under the Netlogon key:

```
HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\DynamicSiteName
```

But we're **still not** connected to a local DC. The `DcSiteName` property says DC04 lives in **CORPDR**. We want a local DC. To really go into the weeds, we can enable Netlogon **debug logging** and look for MAILSLOT entries in the log:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-55-06.png)
*Figure 6 – Netlogon.log with debug level logging*

The log tells us plainly: DC04 is **not** a local DC, so it's going to try to find one in a closer site. Right after that, we see a new DNS query — another LDAP SRV, but this time it looks a little different:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-55-27.png)
*Figure 7 – Site-specific DNS query*

Instead of querying for any DC like it did at startup, the service now performs a **site-specific query**: `_ldap._tcp.CORPHQ._sites.dc._msdcs.corp.milt0r.com`. DNS returns the SRV records for all the DCs in the **CORPHQ** site. Frame details:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-55-39.png)
*Figure 8 – Site-specific DNS reply – frame details*

Each A Record entry contains info about an SRV record. We now know that **DC02** is hosting LDAP on port 389. So we'd logically expect a DNS query for DC02:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-55-52.png)
*Figure 9 – DNS query for the DC's A Record*

Based on the response, Netlogon retries its UDP LDAP ping, this time to `10.1.1.11`. **And there you have it!** From this point on, any process using DCLocator or `DsGetDcName` will use the site-specific queries.

But "how does that help you cross-forest?" you ask. Great question. 👇

## 🔹 Finding DCs Cross-Forest: the trust steps in

I have a **forest trust** configured between `corp.milt0r.com` and `dmz.milt0r.com`. I've also got a **stub zone** on my primary DNS pointing to `dmz.milt0r.com`. From my client, Win8, I open `cmd.exe` and run `nltest` to find a DC in the other forest:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-56-06.png)
*Figure 10 – nltesting…*

The network trace reveals something interesting. At boot, my machine ran that generic query against the global SRV list. But when I crossed the forest trust to find a DC in the other forest, here's what it did:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-56-21.png)
*Figure 11 – Cross-trust DNS query – site-specific*

The very first query to the trusting forest looks for `_ldap._tcp.CORPHQ._sites.dc._msdcs.dmz.milt0r.com`. Weird. We don't even know whether **CORPHQ** is a valid site in `dmz.milt0r.com`… and according to that "Name Error" in the response, it isn't! 🤔

So we learn something key: **the first DNS query for a DC in another forest looks for a site with the same name as the client's site in its own forest.** Since it didn't find one, the client falls back to the global list:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-56-36.png)
*Figure 12 – Cross-trust DNS query – non site-specific*

This one returns a response. From there, we see the same behavior as in the local forest: a DNS query for the hostname we want, then a UDP LDAP ping.

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-56-47.png)
*Figure 13 – A Record query and LDAP ping*

And the corresponding MAILSLOT entry in the Netlogon debug log:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-56-57.png)
*Figure 14 – More Netlogon logs*

## 🔹 The trick: make the site names match

So how do I make sure I find a DC across the trust in a "local" site (or the site I actually want)?

By now you've probably guessed it: you just need to **create a site in the trusting forest with the same name as the site in the trusted forest**. I jump onto OLDDC01 in the DMZ forest, fire up *Sites and Services*, and add a new site:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-57-12.png)
*Figure 15 – It's a 2003 DC, hence OLDDC01 😅*

The site doesn't even **need to contain any DCs**. You just want it connected to a site that should service the authentications and LDAP queries. The rest happens automatically via **Automatic Site Coverage**: DCs linked to empty sites recognize the other site has no DCs and register SRV records there so clients find a "close enough" DC. When that happens, Netlogon drops a little message like this:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-57-24.png)
*Figure 16 – Automatic Site Coverage event log message*

And now, running that trusty `nltest` again:

![](assets/How%20Domain%20Controllers%20are%20Located%20Across%20Trusts/2026-07-02-22-57-37.png)
*Figure 17 – Cross-trust DNS query – site-specific and… it works! 🎯*

The first query is, once again, site-specific… except this time it returns a **valid response**. Next, it queries the A record, then performs the LDAP ping. From there, authentication happens against the site-specific foreign DC. By matching the site name, we can **predict and control** which DCs we'll reach across the forest trust.

## Conclusion

By now you should have a solid grasp of how **DCLocator** finds DCs in the workstation's domain, and how to steer it toward specific DCs across a forest trust.

To sum up:

- ✅ **No need** to register all your subnets in the trusting forest.
- ✅ You **do** need matching **site names** between the two forests.
- ✅ And a **topology** that reflects how you want traffic to flow. Don't match a site name off some site that contains DCs but is poorly connected and unreliable, or you'll send clients to the wrong place.

And keep that **caveat** from the top in mind: this method works great when the subnet in Forest A doesn't exist in Forest B. With conflicting subnet definitions, you can hit some unintended side effects. That'll be the subject of a future post. 👀

---

> 📝 Original article: Tom Moser, *AskPFEPlat* — first published on TechNet on May 5, 2013.
> Source: [How Domain Controllers are Located Across Trusts](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/how-domain-controllers-are-located-across-trusts/ba-p/256180)
