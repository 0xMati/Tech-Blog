# 🔐 OAuth 2.0 — Overview and Introduction

🗓️ Published: 2025-05-28

Imagine you want to let an app use some of your data from another service — like letting a photo app access your pictures on a cloud storage — but without giving the app your password. How can you do that safely?  

That’s where **OAuth 2.0** comes in. It’s a framework that lets you authorize an application to access your data on another service, without sharing your password directly. Instead, you give the app a special key — called an **access token** — that allows it limited access to your data for a certain time.  

### Why use OAuth 2.0?  
- ✅ You don’t have to share your password with every app you use.  
- ✅ You control exactly what the app can do and what data it can see.  
- ✅ You can take back access whenever you want without changing your password everywhere.  
- ✅ You avoid the risk of password theft by apps or websites.  

This makes OAuth 2.0 a trusted way to delegate access, used by many big companies like Google, Facebook, Microsoft, and more.  

In this article, we’ll explore the key concepts behind OAuth 2.0 and the main ways (called **flows**) apps use it to get access to your data securely.  

---

## 🧩 Key Concepts of OAuth 2.0

Before we dive into how OAuth 2.0 works, let’s meet the main characters in the story:

- 👤 **Resource Owner**: That’s usually you — the person who owns the data or stuff. For example, your Google account or Facebook profile.  
- 🗄️ **Resource Server**: This is the place where your data lives and is kept safe. Think of Google’s Contacts API or Facebook’s friend list.  
- 📱 **Client**: This is the app or website that wants to use your data. Maybe it’s a game like Candy Crush that wants to see your Facebook friends so you can play together.  
- 🔐 **Authorization Server**: The gatekeeper who checks if the app has permission to get your data and then gives it a special key (token) to use.  

### 🗝️ Tokens

OAuth 2.0 uses magic keys called **tokens** to open the doors to your data:

- 🔑 **Access Token**: The key that lets the app access your data for a little while (like one hour). For example, Candy Crush might get an access token to look at your friends so it can invite them.  
- 🔄 **Refresh Token**: A special key that lets the app get a new access token when the old one expires — so you don’t have to log in again and again. Google apps often use this to keep you logged in.  

### 🎯 Scope

Not every app needs all your data. The **scope** is like a permission slip that tells what the app can do. For example, a calendar app might only ask to see your events but not change them. When you log in with Google and see a screen asking “This app wants to see your email and contacts,” that’s the scope at work.  

### 🔒 HTTPS is a Must

Because these tokens are special and secret, OAuth 2.0 makes sure everything travels safely over **HTTPS** — like a secret tunnel — so nobody can peek or steal your keys. When you log in with Facebook or Google, you’re using HTTPS to keep your data safe.  

---

## 🚦 OAuth 2.0 Flows — How Apps Get Permission

Now that we know the players and the magic keys (tokens), let’s see how apps actually get those keys.  

OAuth 2.0 defines several ways — called **flows** — that apps use to get permission to access your data. Each flow is like a different path to get the key, depending on what kind of app it is and how safe it needs to be.

Here are the main flows:

- 🔑 **Authorization Code Grant**:  
  Used by apps running on a server or mobile devices. It’s the safest and most common way. The app first gets a temporary code, then trades it for an access token. It often uses a secret code called PKCE to make it extra safe.

- ⚡ **Implicit Grant**:  
  Used mostly by apps running inside your browser (like single-page apps). It skips the temporary code and gets the token right away, but it’s less secure because the token is exposed in the browser.

- 🤖 **Client Credentials Grant**:  
  Used when the app talks to the server by itself, without any user involved — like a service or backend system. The app just proves who it is and gets a token.

- 🔐 **Resource Owner Password Credentials Grant**:  
  This one is like giving your password directly to the app. It’s old-fashioned and not recommended anymore, but still used sometimes for legacy reasons.

- 📺 **Device Code Grant**:  
  Used when your device can’t show a web browser, like a smart TV or game console. The device shows a code and you use another device (like your phone) to authorize the app.

Each flow has its own special use case and level of security.

---

## 🔐 Authorization Code Grant — The Most Common and Secure Flow

Imagine you’re using a website or a mobile app that wants to access your data on another service, like your Google profile or Facebook friends. This app needs your permission, but you don’t want to give it your password.  

The **Authorization Code Grant** flow helps with this by using a secret code as a middle step — kind of like a ticket — before giving the app the actual key (access token).

### 📝 How It Works (Step-by-Step)

1. The app sends you to the service’s login page (for example, Google).  
2. You log in and give permission to the app to access your data.  
3. The service sends a special **authorization code** back to the app (not the access token yet).  
4. The app sends this code, along with its secret, to the service’s authorization server.  
5. The server checks the code and secret, then sends back the **access token**.  
6. The app uses the access token to get your data from the resource server.  

### 🛡️ Why This Is Safe

- The access token is never exposed directly to your browser or device.  
- The app has to prove it owns the secret before getting the token.  
- If someone steals the authorization code, they can’t get a token without the secret.  

### 🎯 Real-Life Example

When you sign into a new app with **“Sign in with Google”**, you’re often using this flow. You’re sent to Google’s login page, then after you approve, the app gets an authorization code. The app then exchanges that code for tokens to access your data securely.

## 🔐 PKCE — Proof Key for Code Exchange

Sometimes apps can’t keep a secret safe — like mobile apps or single-page apps running in your browser. This makes it easier for attackers to steal the authorization code and get access tokens.  

That’s why we have **PKCE** — it’s like a secret handshake between the app and the authorization server to make sure no one else can use the authorization code.

### How PKCE Works (Simple Version)

1. When the app starts the login, it creates a random secret called the **code verifier**.  
2. It then makes a hashed version called the **code challenge** and sends that with the login request.  
3. After you log in and the app gets the authorization code, the app sends the **code verifier** to the authorization server.  
4. The server checks that the **code verifier** matches the **code challenge** it got earlier.  
5. If it matches, the server sends the access token. If not, it refuses.

This way, even if someone steals the authorization code, they can’t get a token without the secret code verifier.

### Real-Life Example

Google and Microsoft require PKCE for mobile and JavaScript apps. It’s now the recommended way to make the Authorization Code flow extra secure.

---

## ⚡ Implicit Grant — Quick but Less Secure

Sometimes, apps run entirely inside your browser — like single-page apps built with JavaScript. These apps can’t keep secrets very well because everything happens on your device.

The **Implicit Grant** flow lets these apps get an access token right away — without waiting for a code exchange. But this comes with some risks.

### How It Works (Simple Steps)

1. The app sends you to the authorization server’s login page (like Facebook).  
2. You log in and give permission.  
3. Instead of sending a code, the server sends the **access token** directly back in the URL fragment (after the `#` symbol).  
4. The app grabs the token from the URL and uses it to access your data.

### Why It’s Riskier

- The token is visible in the browser and can be exposed to malicious scripts.  
- There’s no refresh token, so when the token expires, you have to log in again.  
- Because of these risks, this flow is now discouraged when better alternatives (like Authorization Code with PKCE) exist.

### Real-Life Example

Old JavaScript apps and some early single-page apps used this flow. Facebook used to support it, but most providers now recommend Authorization Code with PKCE instead.

---

## 🤖 Client Credentials Grant — When No User Is Involved

Sometimes, an app or service needs to talk to another service all by itself — without anyone logging in. For example, a backend server talking to a cloud storage API.

The **Client Credentials Grant** flow is made for this kind of situation.

### How It Works (Simple Steps)

1. The app (client) proves who it is by sending its own credentials (like a username and password for apps).  
2. The authorization server checks the client’s identity.  
3. If everything is okay, it sends back an **access token**.  
4. The app uses this token to access the resource server.

### No User Needed!

This flow is perfect for machine-to-machine communication, like a website automatically backing up files to Google Cloud Storage.

### Real-Life Example

A service that syncs data between two cloud apps without asking a user every time uses this flow. For example, a monitoring service accessing a cloud API.

---

## 📺 Device Code Grant — For Devices Without a Browser

Some devices, like smart TVs or game consoles, don’t have a good way to show a web browser for you to log in. But they still need your permission to access your data.

The **Device Code Grant** flow solves this problem.

### How It Works (Simple Steps)

1. The device shows you a code on the screen (like a PIN).  
2. You use another device that has a browser — like your phone or computer — to go to a special website.  
3. On that website, you enter the code and log in to give permission.  
4. The device keeps asking the authorization server if permission was granted.  
5. Once you approve, the device gets an **access token** and can access your data.

### Real-Life Example

When you sign in to Netflix or YouTube on your smart TV, you often see a code and instructions to visit a website on your phone or computer to authorize the device.

---

## 🔐 Resource Owner Password Credentials (ROPC) — Old and Risky

This flow is a bit old-fashioned and should be avoided if possible.

It asks you to give your username and password directly to the app. That means the app gets your real login details, which can be risky.

### How It Works (Simple Steps)

1. You give your username and password to the app.  
2. The app sends those credentials to the authorization server.  
3. If they are correct, the server sends back an **access token**.  
4. The app uses the token to access your data.

### Why Avoid This Flow?

- It exposes your password to the app, which might not be trustworthy.  
- It doesn’t allow multi-factor authentication easily.  
- It’s mainly used for legacy apps or special cases where other flows are not possible.

### Real-Life Example

Some older enterprise systems still use this flow during migrations, but most modern apps avoid it.

---

## 📝 Summary

OAuth 2.0 is like a magic key system that lets apps access your data safely — without giving them your password.  

There are different ways (flows) for apps to get these keys, depending on the type of app and how secure it needs to be:  

- **Authorization Code Grant** is the safest and most common way, using a secret code first and often PKCE for extra protection.  
- **Implicit Grant** is quick but less secure, mostly used by apps running inside your browser.  
- **Client Credentials Grant** is for apps talking to services without any user involved.  
- **Device Code Grant** helps devices without browsers get permission through another device.  
- **Resource Owner Password Credentials Grant** is old and risky — avoid it when you can!  

Using OAuth 2.0, you stay in control of your data, decide what apps can do, and keep your password safe.

---

Thanks for reading! Feel free to explore OAuth further and try out some flows with popular services like Google or Facebook.


## 📚 Sources & Further Reading

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)  
- [OAuth 2.0 and OpenID Connect in plain English](https://oauthdebugger.com/)  
- [Understanding OAuth 2.0 (BubbleCode)](http://www.bubblecode.net/fr/2016/01/22/comprendre-oauth2/)  
- [DigitalOcean Tutorial on OAuth 2.0](https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2)  
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)  
- [Facebook Login for the Web (OAuth 2.0)](https://developers.facebook.com/docs/facebook-login/web)  
- [OWASP OAuth 2.0 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)  
- [Mozilla Developer Network: HTTP Access Control (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)  
- [YouTube: OAuth 2.0 Explained](https://www.youtube.com/watch?v=996OiexHze0)  

