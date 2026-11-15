# Email domain: SPF, DKIM and DMARC

What this covers: making your sign-up and reset emails reach the inbox. Read it for MAIL-001 and MAIL-002. After reading you can set up the records and test them.
Last checked: 2026-11-13.

**In five sentences.** SPF lists which servers may send mail for your domain. DKIM adds a signature that proves a message was not altered and came from you. DMARC tells receivers what to do when SPF or DKIM fail and where to send reports. Mailbox providers increasingly reject or hide mail that lacks them. Your email provider gives you the exact records to paste.

1. In your email provider (Resend, SendGrid, Postmark, SES and similar), add your sending domain and copy the DNS records it shows.
2. Open the DNS settings of your domain registrar or DNS host and add each record exactly as shown (type, name, value). SPF and DMARC are TXT records; DKIM is usually a CNAME or TXT.
3. Add a DMARC record at `_dmarc.yourdomain` such as `v=DMARC1; p=none; rua=mailto:you@yourdomain` and tighten `p` to `quarantine` later.
4. Wait for DNS to update (minutes to hours) and click "Verify" in the provider.
5. In Supabase, Authentication, SMTP settings, enter the provider's SMTP credentials so sign-up and reset mail uses it. The built-in sender is for testing and is heavily limited.
6. Send a test to a Gmail address, open "Show original", and check SPF, DKIM and DMARC all say PASS.
