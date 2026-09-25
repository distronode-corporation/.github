# Distronode Corporation

**A Canadian telecommunications company. We provide business phone numbers, calls and texts in Canada, the United States and Europe, and we build [District AI](https://www.distronode.com), the 24/7 receptionist that answers them.**

Pick a local number or keep the one your customers already know. Every call is answered, the
appointment is booked, and the call is written up afterward. No gated sales call and no form:
the live demo on our site answers in your browser right now.

## What it does

- **Answers the phone**, in a voice you choose, with an opening line you write and approve.
- **Books the appointment** while the caller is still on the line, and gives you a booking
  page of your own that works with Google Calendar, Microsoft 365 and Apple Calendar.
- **Writes up every call**: who called, what they wanted, and the full transcript.
- **Priced in the open.** Plans from $39 a month, per-minute rates published, and spending
  caps you set.

## How it is built

Our own phone infrastructure, run like a phone company.

| | |
|---|---|
| **Voice** | LiveKit for live calls, on our own servers in every region |
| **Telephony** | Direct carrier connections, with local numbers in the United States, Canada and Europe |
| **Regions** | Four independent deployments (United States, Canada, Europe, Asia-Pacific), each with its own database |
| **Apps** | Web, plus native Android and iOS |

**Where your data lives is a property of the deployment, not a promise in a brochure.** We
publish a map of where each kind of data is kept, alongside the companies that help us run
the service and our privacy commitments. Where something is *not* kept in your region, we
say so on the page rather than rounding up. The technical detail is in the
[Sovereign portal](https://www.distronode.com/sovereign).

## Open source

District AI runs on open-source software, and we publish our own work the same way, under
Apache-2.0. Both projects, and everything we run on, are on
[one page](https://www.distronode.com/open-source).

- **[bridgewatch](https://github.com/distronode-corporation/bridgewatch)** is our tray monitor
  for GitLab CI and GitHub Actions, for macOS and Linux. It shows one row per push with every
  downstream pipeline under it, tells a scheduled pipeline from a push, and reports whether
  the thing you care about actually deployed. Version 1.0.0 was released on September 19,
  2026, as a signed macOS app, a .deb and an AppImage.
- **[District Scheduler](https://github.com/distronode-corporation/district-scheduler)** is our
  fork of [Calnode](https://github.com/Calnode/calnode), and the scheduling engine behind
  District AI's bookings. It adds a multi-tenant mode on PostgreSQL, with row-level security
  as the isolation. Switched off, it behaves as upstream Calnode.
- **Fixes go upstream.** Our fixes for event-type duplication, booking-page clarity, calendar
  reconnection and locale handling are merged into Calnode and ship to every Calnode
  deployment, not only ours. PostgreSQL and multi-tenancy were declined upstream on
  architectural grounds, so the fork carries them.

Contributions are authored with AI assistance under human review, and our commits say so.

## Contact

**Distronode Corporation**, federally incorporated in Canada, corporation number 1793333-9

RBC WaterPark Place, 20 Bay Street, 11th Floor
Toronto, Ontario, M5J 2N8, Canada

[distronode.com](https://www.distronode.com) · [opensource@distronode.com](mailto:opensource@distronode.com)
