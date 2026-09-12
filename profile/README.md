# Distronode Corporation

**We build [District AI](https://www.distronode.com) — a 24/7 AI receptionist for small businesses and the trades.**

A real phone number that answers every call, books the job, and writes it up afterward. No
gated sales call and no form: the live demo on our site answers in your browser right now.

## What it actually does

- **Answers the phone**, in a voice and with an opening line you write and approve.
- **Books into the calendar you already use** — Google Calendar or Microsoft 365 — under your
  own credentials.
- **Writes up every call**: transcript, summary, and the details you asked it to collect.
- **Costs what the meter says.** Per-minute pricing published plainly, with spending caps you
  set. The bill should never be the frightening part of owning a phone line.

## How it is built

Real-time voice infrastructure, run like it matters.

| | |
|---|---|
| **Voice** | LiveKit for media and SIP, with the speech and language models selected per region |
| **Telephony** | Direct carrier integrations, with numbers available in the US, Canada and the EU |
| **Regions** | Four independent deployments — United States, Canada, European Union, Asia-Pacific — each with its own database |
| **Clients** | Web, plus native Android and iOS apps |

**Data residency is a property of the deployment, not a promise in a brochure.** Each region
runs its own origin and its own database, and we publish a per-data-type map of where your
information lives, alongside our sub-processors and privacy commitments. Where something is
*not* in region, we say so on the page rather than rounding up.

## Open source

We run on open source and contribute back.

- **[District Scheduler](https://github.com/distronode-corporation/district-scheduler)** is our
  Apache-2.0 fork of [Calnode](https://github.com/Calnode/calnode), and the booking, meetings
  and notetaker engine behind District AI. It adds a PostgreSQL-backed multi-tenant mode that
  uses row-level security for isolation, and a PostgreSQL-only container image. Public, with
  the architecture and audit documents that go with it.
- **[Calnode](https://github.com/Calnode/calnode)** is the upstream scheduling server. We send
  our changes back: fixes for event-type duplication, booking-page clarity, calendar
  reconnection and locale handling are merged upstream and ship to every Calnode deployment,
  not only ours. PostgreSQL and multi-tenancy were declined upstream on architectural grounds,
  so the fork carries them.

Contributions are authored with AI assistance under human review, and our commits say so.

## Contact

**Distronode Corporation** — federally incorporated in Canada, corporation number 1793333-9

RBC WaterPark Place, 20 Bay Street, 11th Floor
Toronto, Ontario, M5J 2N8, Canada

[distronode.com](https://www.distronode.com) · [distronode@distronode.com](mailto:distronode@distronode.com)
