# Backups and a restore drill

What this covers: turning on backups for your database and proving one restore works. Read it for DB-016 and REL-007. After reading you can state what is backed up, how far back, and how long a restore takes.
Last checked: 2026-11-13. Backup features depend on the plan; check the provider's current pricing page.

1. **Find out what you have.** Open the provider's backups page (Supabase: Database, Backups; Firebase: Firestore, Disaster recovery and scheduled backups; managed Postgres: the backups tab). Note whether backups are daily or point-in-time and how long they are kept.
2. **Turn on the best option your plan allows.** Prefer point-in-time recovery for data you cannot recreate. <!-- unverified: which plans include it -->
3. **Take a manual export now.** Supabase CLI: `supabase db dump -f backup.sql` (needs the project linked). Firestore: a managed export to a storage bucket. Store it outside the same account.
4. **Back up uploaded files separately.** Database backups usually do not include storage buckets.
5. **Restore drill.** Create a scratch project, restore the latest backup into it, open the app against it, and write down how long it took and what was missing. Do this once before launch and after any big change.
6. **Record it** in `RUNBOOK.md`: where backups are, how to restore, the date of the last drill.
