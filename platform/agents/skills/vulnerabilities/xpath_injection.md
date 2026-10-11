---
name: xpath-injection
description: XPath / XQuery injection for authentication bypass and data extraction when XML lookups are keyed on user input
---

# XPath Injection

XPath injection occurs when user-controlled input is concatenated into an XPath query that queries an XML document. Because XPath is a full query language with booleans, functions, and string operators, an attacker can alter the expression to bypass checks or extract data. It is the XML-document analogue of SQLi and often lives beside LDAP/XPath user lookups.

## Attack Surface

- User lookups / login forms backed by XML docs (`users.xml`), XPath `//user[name=$input]`, `string(...)` style queries
- REST/SOAP/XML-RPC endpoints that take an identifier and run an XPath/XQuery
- Admin consoles that render "profile by name" from XML stores

## Detection (probe)

- **Error-based**: send an expression that breaks syntax to see stack/parser details:
  `'` , `"` , `' or '1'='1` , `" or "1"="1` , `')]|//*['` , `&apos;`
- **Boolean-blind**: `' or 1=1` vs `' or 1=2` — compare login success
- **XML entities**: the parser may interpret `&apos;`/`&quot;` — use entity encodings to survive XML pre-parsing

## Exploitation (method, payloads stay in the deterministic executor)

- **Auth bypass**: `admin' or '1'='1`, `' or 'a'='a'` for the login lookup
- **Data extraction**: `string(//users/user[1]/password)` , `count(//user)` , boolean probes on substring
- **Universal match → count**: `//*[contains(name(),'u')]` to enumerate nodes; iterate indices
- Combine with the app's knowledge of the XML schema (element names) from error/duplicate responses

## Confirmation

- Submit the working query via the deterministic executor (`bash`/`http_request`/`curl`), capture a response snippet that proves the injected XPath changed the result (extra rows, password string, authenticated view), then record with `submit_finding`.
