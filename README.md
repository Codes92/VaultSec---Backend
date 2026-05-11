# VaultSec
**An open-source security platform that combines encrypted secret storage with a security tool suite and real-time threat intelligence - built as a portfolio project to demonstrate practical security engineering. 
Designed to be accessible for everyday users while offering useful tools for developers and security practitioners.
Stores credentials with zero-knowledge encryption, inspect SSL certificates, analyse DNS records, decode JWTs, generate hashes, and stay informed with live security news.**

# Technical stack
## Backend
**Runtime:** Node.js
**Framework:** Express
**Database:** PostgreSQL
**Authentication:** JWT, Argon2
**Encryption:** AES-256-GCM (Node crypto)
**TOTP:** otplib
**Security headers:** Helmet
**Rate limiting:** express-rate-limit
**RSS parsing:** rss-parser

## Frontend
**Framework:** React
**Build tool:** Vite
**Routing:** React Router
**Icons:** Lucide React
**HTTP client:** Fetch API

## External APIs
**HaveIBeenPwned** - password breach checking
**Cloudflare DNS over HTTPS** - DNS Lookups
**CISA, Krebs on Security, BleepingComputer** - security news feeds
**NVD/OSV** - CVE vulnerability data

# Architecture and security decisions
