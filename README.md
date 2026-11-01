# RoomSync

A starter roommate-compatibility website built with plain HTML, CSS, JavaScript and Node.js.

## Requirements
- Node.js 20 or newer
- npm

## Run locally
1. Open this folder in VS Code.
2. Open a terminal in this folder.
3. Run `npm install`.
4. Copy `.env.example` to `.env` and set a long random `SESSION_SECRET`.
5. Run `npm start`.
6. Visit http://localhost:3000

SQLite is created automatically in `data/roomsync.db`.

## Important limitations
This is a development starter, not a production-ready housing service. It is intended for adults aged 18+ only. The server enforces women-with-women and men-with-men matching. This starter has no email verification, password reset, real-time chat, identity verification, moderator dashboard or durable production session store. Do not deploy it publicly until those features, security testing, privacy/legal review and persistent hosting/database have been addressed. Free hosting tiers have limits and may sleep or delete local files.
