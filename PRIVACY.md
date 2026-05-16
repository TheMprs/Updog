# Privacy Policy — UpDog

**Last updated: May 2026**

UpDog is a Gmail Add-on that analyzes emails for phishing and malware indicators. This policy explains what data leaves your device during analysis and why.

---

## What UpDog does with your email

When you open an email, UpDog reads it using the Gmail API and sends it to a private backend for analysis. The backend runs entirely in memory — **no email content, subject lines, body text, or attachment content is ever written to disk or stored in any database.**

Once the analysis is complete, the backend returns a score and a list of findings. Nothing is retained.

---

## Data sent to third-party services

To perform its analysis, UpDog sends limited, targeted data to the following external services:

### Google Safe Browsing API
- **What is sent:** URLs extracted from the email body
- **Why:** To check whether any link in the email is a known phishing or malware URL
- **Note:** URLs may contain personal tokens (e.g. `unsubscribe?user=...`). Only the URL strings themselves are sent — no email body, sender, or subject.
- **Google's privacy policy:** https://policies.google.com/privacy

### RDAP (domain registries)
- **What is sent:** The sender's domain name (e.g. `example.com`)
- **Why:** To check how recently the domain was registered — newly registered domains are a common phishing signal
- **Note:** Queries go directly to the authoritative registry for the domain's extension (e.g. Verisign for `.com`), or to rdap.org as a fallback. No email content is sent.

### HaveIBeenPwned
- **What is sent:** The sender's domain name
- **Why:** To check whether the sender's domain has been involved in a known data breach — shown as an informational warning, not a score penalty
- **Note:** This is a read-only lookup. No email content is sent.

### HaveIBeenPwned (user-initiated only)
- **What is sent:** Your Gmail address
- **Why:** To check whether your personal email address appears in any known breach
- **This only happens if you explicitly click "Check if I was exposed."** It is never sent automatically.
- **HaveIBeenPwned's privacy policy:** https://haveibeenpwned.com/Privacy

### IANA (startup only)
- **What is sent:** Nothing — UpDog fetches a public registry file from IANA once at startup to build its list of RDAP servers. No user data is involved.

---

## Gmail permissions

UpDog requests the following OAuth scopes:

| Scope | Reason |
|-------|--------|
| `gmail.readonly` | Read the currently open email for analysis |
| `gmail.addons.execute` | Run as a Gmail Add-on |
| `script.external_request` | Send analysis requests to the backend and third-party services |
| `userinfo.email` | Identify your account for the "Check if I was exposed" feature |

UpDog does not send, modify, delete, or share your emails. It only reads the email you are currently viewing.

---

## Data retention

- **Email content:** Never stored. Processed in memory and discarded after each analysis.
- **Analysis results:** Displayed in the sidebar and discarded. Not logged or stored.
- **Your email address:** Only used if you initiate the breach check. Not stored.

---

## Contact

If you have questions about this policy, contact: nisim.yuval41@gmail.com
