# Why “Low success rate of active name resolution” shows up — even when Reverse DNS works fine
📅 Published: 2025-10-21

You’ve seen it before in Defender for Identity:  
> *Low success rate of active name resolution*  
and you’re thinking — “But DNS works, so why is this thing still yelling at me?”

Let’s break it down 👇

---

## The real story behind NNR

Each MDI sensor tries to match IPs it sees on the wire to actual hostnames using a mix of methods:

| Type | Method | Port |
|------|---------|------|
| 🟢 **Primary** | NTLM over RPC | TCP 135 |
|  | NetBIOS | UDP 137 |
|  | RDP | TCP 3389 |
| 🟡 **Fallback** | Reverse DNS (PTR lookup) | UDP 53 |

If RPC/NetBIOS/RDP all fail, the sensor falls back to **Reverse DNS**.  
It still gets a name — but not the juicy context that comes with an active handshake (like NTLM target info or NetBIOS name).

---

## Why the alert pops up

The “Low success rate of *active* name resolution” alert fires when:

- The sensor has enough daily NNR attempts, **and**
- **More than two-thirds of the active methods** (RPC, NetBIOS, RDP) fail **> 90%** of the time.

It’ll close once failures drop below 60%.

Key thing: **Reverse DNS doesn’t count** toward the “active” metric.  
So even if PTR lookups work perfectly, the health alert *still triggers* if the actives are dead.

---

## Why some sensors are red and others green

Not all sensors live the same life.  
Each one reports its own NNR success rates — and that depends entirely on what traffic it sees.

| Factor | What it means |
|---------|----------------|
| **Traffic type** | Some sensors see internal Windows traffic (RPC OK ✅). Others see DMZ / Linux / NAT (everything blocked ❌). |
| **Port reachability** | 135/137/3389 open in one site, filtered in another. |
| **Methods enabled** | Some sensors have fewer active methods — fewer ways to fail. |
| **PTR zones** | One DNS has reverse zones, another doesn’t. |
| **Sensor placement** | A sensor in a clean LAN? Happy. One in a hybrid DMZ? Sad. |

So two sensors in the same tenant can have totally different health results — not because of config, but because of *what they actually see*.

---

## Opening ports from Domain Controllers or MDI Sensors is *not* a security issue

This one comes up all the time:  
> “We can’t open TCP/135 or UDP/137 from our Domain Controllers — that’s a security risk!”

Let’s clear that up once and for all

### 1. Direction matters

The MDI sensor — whether installed directly on a Domain Controller or running standalone —  
**initiates outbound connections** to other devices on ports **135 (RPC)**, **137 (NetBIOS)**, or **3389 (RDP)**.  

That means:
- The DC **is not exposing** new listening services to the network.  
- It’s just sending *queries* to endpoints.

> These are **outbound, short-lived client connections**, not inbound exposure points.

### 2. It’s all internal

MDI doesn’t talk to random internet hosts.  
All these requests target **internal devices**.
If your internal network is so compromised that a simple outbound RPC from a DC is dangerous… you already have bigger problems.

### 3. Port filtering ≠ segmentation

Blocking 135/137/3389 from the DC doesn’t improve your security posture.  
It only:
- breaks name resolution telemetry,
- reduces detection visibility,
- and triggers unnecessary “Low success rate of active name resolution” alerts.

Proper segmentation is about **who can authenticate to the DC**, not **which internal port numbers the DC can query**.

## TL;DR

- **Reverse DNS** is a working fallback ✅  
- But it doesn’t “heal” the **Active Name Resolution** score ❌  
- If RPC / NetBIOS / RDP fail >90%, the alert stays red 🔴  
- It’s expected — not a bug
- Open required ports from DC to Devices

---

## What you can do

1. **Fix the basics** → open ports TCP 135 / UDP 137 / TCP 3389 between sensors and internal hosts.  
2. **Keep at least one primary method enabled** somewhere — DNS-only mode isn’t fully supported globally.  
3. **Recheck after change** — once active methods drop below 60% failure, the alert auto-closes.

---

> Reverse DNS keeps you visible.  
> Active methods keep you smart.  
> MDI only calls you “healthy” when you’re both.

