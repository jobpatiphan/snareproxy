# bogbogprox — คู่มือใช้งาน (Usage Guide)

Web security proxy สาย Rust — จับ HTTPS, intercept, repeater, intruder, scanner,
session handling และทำงานเป็นทีมได้. เอกสารนี้สอนใช้ตั้งแต่ติดตั้งจนถึง team mode.

---

## 1. ติดตั้ง & รันครั้งแรก

```bash
# build (ต้องมี Rust + cmake; ดู prerequisites ด้านล่างถ้าจะ build ตัว desktop)
cargo build

# สร้าง CA เฉพาะเครื่อง (ครั้งเดียว)
./target/debug/bogbogproxd ca generate
#   จะพิมพ์ path ของ cert ออกมา — เอาไป "ติดตั้งใน trust store ของ browser/OS"
./target/debug/bogbogproxd ca path        # ดู path ของ CA cert

# รัน daemon
./target/debug/bogbogproxd run
#   proxy     : http://127.0.0.1:8888   ← ตั้ง browser/tool ให้ใช้ proxy นี้
#   dashboard : http://127.0.0.1:9000/  ← เปิดในเบราว์เซอร์เพื่อดู/คุม traffic
```

**ตั้ง proxy ที่ browser** เป็น `127.0.0.1:8888` (หรือใช้ curl):
```bash
curl -x http://127.0.0.1:8888 --cacert "$(./target/debug/bogbogproxd ca path)" https://example.com
```
เปิด `http://127.0.0.1:9000/` จะเห็น flow วิ่งเข้ามาสดๆ

### 1.1 ต่อ browser/client เข้า BogBogProx — 3 ทางเลือก
BogBogProx เป็น **proxy** ไม่ผูกกับ browser ตัวไหนเอง — จับเฉพาะ client ที่ชี้มาที่ `127.0.0.1:8888`.
เลือกตามงาน:

| ทางเลือก | คำสั่ง / วิธี | เหมาะกับ | ข้อควรรู้ |
|---|---|---|---|
| **A. Throwaway Chromium** | `bogbogproxd browser --url <url>` | ทดสอบเว็บทั่วไปเร็ว ๆ | Chromium ยิง background telemetry (gvt1/google/c2dm) ปน — ใช้ filter `host:<target>` ซ่อน; anti-bot ตรวจจับได้ |
| **B. Manual proxy** | ตั้ง proxy `127.0.0.1:8888` ใน browser/OS + import CA (`bogbogproxd ca path`) | เบราว์เซอร์จริงของคุณ | ต้อง trust CA เอง |
| **C. Stealth browser (nodriver/CDP)** | spawn ผ่าน [[stealth-browser-mcp]] ด้วย `proxy="http://127.0.0.1:8888"` + `browser_args=["--ignore-certificate-errors"]` | **pentest/CTF ที่มี anti-bot** | undetectable + ไม่ต้อง import CA (ignore cert) + telemetry น้อยกว่า A. BogBogProx MITM decrypt ได้ครบ → capture + writeup ตามปกติ |

> **แนะนำสำหรับงาน CTF/lab จริง = C** — traffic ทั้งหมด (ผ่าน Cloudflare/anti-bot) วิ่งเข้า BogBogProx
> ให้ capture/annotate/writeup ได้ ในขณะที่ browser ยัง stealth. verified: spawn stealth browser
> ชี้ proxy BogBogProx → navigate เป้าหมาย → flow (HTTPS decrypt แล้ว) โผล่ใน dashboard ทันที.

BogBogProx เก็บ body สูงสุด 16 MiB ต่อ request/response; body ที่ใหญ่กว่านี้ยังถูก
ส่งผ่านครบ แต่ capture จะแสดง `body_truncated` และไม่อนุญาตให้ replay แบบไม่ครบ.

เปลี่ยนพอร์ตได้: `bogbogproxd run --proxy 127.0.0.1:9999 --api 127.0.0.1:9001`
CLI ดู flow: `bogbogproxd flows` · ล้าง: `bogbogproxd flush`

---

## 2. Dashboard — ทัวร์เครื่องมือ (แถบบนสุด)

| ปุ่ม/ช่อง | ทำอะไร |
|---|---|
| **filter** | HTTPQL — กรอง flow (§3.11) |
| **scope** | จำกัด intercept เฉพาะ host (คั่นด้วย comma) |
| **⏸ Req / ⏸ Resp** | เปิด/ปิด intercept request / response |
| **⚙ M&R** | Match & Replace rules |
| **🔑 Session** | ตัวแปร + macro (auto token) |
| **⚠ Findings** | ผลสแกน (passive+active) + report |
| **🗺 Sitemap** | host/path ที่จับได้ |
| **🔌 WS** | ข้อความ WebSocket |
| **⚖ Compare** | diff สองอย่าง |
| **🎲 Seq** | วิเคราะห์ความสุ่มของ token |
| **🔧 Decoder** | Base64/URL/Hex/JWT |
| **🔔 Popups** | desktop notification ตอน AI ทำงาน |

คลิก flow แถวใดก็ได้ → เห็น request/response (แท็บ Request/Response) + ปุ่ม
**↻ Resend · ✎ Edit · ⚔ Intruder · 🛡 Scan**

---

## 3. ฟีเจอร์ทีละอัน

### 3.1 Intercept (หยุด/แก้ traffic)
1. กด **⏸ Req: on** (จะเป็นสีแดง). อยากหยุด response ด้วยกด **⏸ Resp: on**.
2. เลือก scope ก่อนได้ (เช่น `target.com`) ไม่งั้นดักทุก host.
3. พอมี request วิ่งเข้า → editor เด้งขึ้น แสดง raw request แก้ได้.
4. **Forward ▶** (Ctrl+Enter) ส่งต่อ · **Drop ✕** ทิ้ง (client ได้ 403).
   บน **TUI** ใช้ `i` toggle, `f` forward, `d` drop.

### 3.2 Repeater (ยิงซ้ำ/แก้แล้วยิง)
- คลิก flow → **↻ Resend** ยิงซ้ำเดิม, หรือ **✎ Edit** เปิด editor 2 ช่อง
  (ซ้าย=request แก้ได้, ขวา=response) → **Send ▶** (Ctrl+Enter).

### 3.3 Intruder (fuzz payload)
1. คลิก flow → **⚔ Intruder**.
2. ในช่องซ้าย ใส่ `§` ตรงตำแหน่งที่อยากยิง payload.
3. ช่องขวา วาง payload (บรรทัดละ 1 อัน), ตั้ง marker/threads.
4. **Run ▶** → ตาราง status/length/ms ต่อ payload (มองหา length/status ที่ต่าง).

### 3.4 Match & Replace (แก้อัตโนมัติ)
- **⚙ M&R** → เลือก part (req url/header/body หรือ resp header/body), ใส่ regex
  + replacement (`$1` = capture group), **Add**. ติ๊ก enable/disable, 🗑 ลบ.
- ใส่ `{{ตัวแปร}}` ใน replacement เพื่อ inject ค่าจาก Session (§3.5).

### 3.5 Session handling (auth อัตโนมัติ)
เอาไว้ให้ token สดเสมอ:
1. **🔑 Session** → เพิ่ม **Macro**: ตั้ง name/method/url ของ endpoint login,
   `extract` = regex ดึง token (เช่น `"token":"([^"]+)"`), `→ var` = ชื่อตัวแปร (เช่น `token`).
2. กด **▶ run** ที่ macro → ค่าถูกดึงมาเก็บใน variable (เห็นในส่วน Variables).
3. เพิ่ม M&R rule: part=`req header`, pattern=`(?i)^authorization:.*`,
   replace=`Authorization: Bearer {{token}}`.
   → ทุก request จะถูกใส่ token ปัจจุบัน. หมดอายุก็กด run macro ใหม่.

### 3.6 Passive Scanner (สแกนอัตโนมัติ)
- เปิดอยู่ default. ทุก response ถูกตรวจ: missing CSP/HSTS/X-Frame-Options,
  cookie ไม่มี HttpOnly/Secure, version disclosure, reflected param.
- ดูผลที่ **⚠ Findings** (มี badge นับ). dedup ต่อ host.

### 3.7 Active Scanner (ยิง probe)
- คลิก flow ที่มี query param → **🛡 Scan** → ยิง XSS + SQLi probe เข้าทุก param,
  ผลเป็น Medium finding ถ้าพบ indicator ที่ต่างจาก baseline. เปิด Findings ดู.

### 3.8 Findings → Report / Writeup
- ใน **⚠ Findings** มีลิงก์ **report ↗** (Markdown) และ **SARIF ↓** (เอาเข้า CI ได้).
  หรือ API: `GET /api/v1/report?format=md|sarif`.

#### Writeup curation (Burp-style comments + narrated export)
- **Annotate a flow** — เลือก flow แล้วกด **📝 Note** ใน detail pane: ใส่ **Label** (หัวข้อ section),
  **Note** (คำอธิบายว่าทำไม step นี้สำคัญ), **Step** (ลำดับ), **Highlight payload** (substring ที่จะ
  spotlight ใน transcript), และ **สี** (row highlight แบบ Burp). API: `POST /api/v1/flows/:id/note`
  (`{label,note,step,highlight,color,include}` — partial patch), `DELETE` เพื่อลบ,
  `GET /api/v1/annotations` ดูทั้งหมด. flow ที่ annotate จะโชว์ comment + แถบสีในตาราง.
- **📝 Writeup panel** (toolbar) — render flow ที่ annotate แล้วเป็น **Markdown เล่าเรื่อง**: label เป็น
  หัวข้อ, note เป็น prose, request/response เป็น ```http transcript แบบ **smart** — secret ใน header
  ถูก **redact**, JSON body **pretty-print**, payload ถูก **spotlight** (`«…»`), body ยาวถูกตัดรอบ payload —
  ปิดท้ายด้วย findings ที่ correlate ตาม host. กด **⧉ Copy Markdown** วางลง report ได้เลย.
- **API/AI:** `GET /api/v1/report?format=writeup` (ใช้ flow ที่ annotate เรียงตาม step),
  หรือ `&flows=1,2,3` เจาะจงเอง, `&highlight=<payload>` spotlight ทั่วทุก flow, `&redact=false`
  เก็บค่า secret ดิบ, `&all=true` เอาทุก flow ที่ capture.

### 3.9 Decoder / Comparer / Sequencer
- **🔧 Decoder**: วาง text กดปุ่ม Base64/URL/Hex/JWT (▸ encode, ◂ decode).
- **⚖ Compare**: วางสองอย่าง กด Compare → บรรทัดที่ต่างไฮไลต์.
- **🎲 Seq**: วาง token (บรรทัดละ 1) → Analyse → verdict STRONG/WEAK + entropy.

### 3.10 Sitemap / WebSocket / GraphQL
- **🗺 Sitemap**: host→path ที่จับได้ (คลิกเปิด flow).
- **🔌 WS**: ข้อความ WebSocket (ทิศทาง ▲ send / ▼ recv). *หมายเหตุ:* จับ wss:// (ผ่าน MITM).
- **GraphQL**: ถ้า request เป็น GraphQL (path มี graphql หรือ body มี `query`)
  แท็บ Request จะ pretty-print query + variables ให้อัตโนมัติ.

### 3.11 HTTPQL (filter)
ในช่อง filter พิมพ์: `field:value` คั่นด้วยเว้นวรรค (= AND), `!` = not.
- fields: `status host path method mime source`
- ตัวอย่าง: `status:4 host:api` · `method:POST !mime:json` · `source:intruder`

---

## 4. AI / MCP (ให้ Claude ขับ)

`bogbogprox-mcp` เป็น stdio MCP server. ต่อ MCP client (เช่น Claude Code) เข้า:
```jsonc
// ตัวอย่าง config MCP
{ "command": "/path/to/target/debug/bogbogprox-mcp",
  "env": { "BOGBOGPROX_API": "http://127.0.0.1:9000", "BOGBOGPROX_AGENT": "claude",
           "BOGBOGPROX_TOKEN": "optional-team-session-token" } }
```
Tools: `proxy_list_flows`, `proxy_get_flow`, `proxy_stats`, `repeater_send`,
`intruder_run`, `active_scan`, `annotate_flow` (ติด label/note/step/highlight ให้ flow),
`report_writeup` (render flow ที่ annotate → Markdown writeup เล่าเรื่อง redact+highlight พร้อมวาง).
ทุกครั้งที่ AI เรียก tool จะเด้งขึ้น dashboard
(banner ม่วง 🤖) — เปิด **🔔 Popups** ให้เด้ง desktop notification ด้วยได้.

---

## 5. Faces อื่น

- **TUI** (over SSH ได้): `./target/debug/bogbogprox-tui` — `j/k` เลื่อน, `r` resend,
  `i` intercept, `f/d` forward/drop, `q` ออก. ต่อ remote/TLS:
  `bogbogprox-tui --api https://bogbogprox.example --token <session-token>` (หรือ `BOGBOGPROX_TOKEN`).
- **Desktop** (native window): `./target/debug/bogbogprox-desktop`
  หรือชี้ remote: `BOGBOGPROX_URL=http://host:9000/ ./target/debug/bogbogprox-desktop`
  > build ตัว desktop ต้องมี deps: `sudo apt install -y libwebkit2gtk-4.1-dev build-essential libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev libsoup-3.0-dev pkg-config`

---

## 6. Team mode (ทำงานเป็นทีม)

หลายคนทำ engagement เดียวกัน เห็น flow/finding/config ของกันสด.

### 6.1 เตรียม Postgres
```bash
# (ตัวอย่างบน Debian/Kali)
sudo pg_ctlcluster 18 main start
sudo -u postgres psql -c "CREATE ROLE bogbogprox LOGIN PASSWORD 'bogbogprox';"
sudo -u postgres psql -c "CREATE DATABASE bogbogprox OWNER bogbogprox;"
```

### 6.2 รัน team server
```bash
./target/debug/bogbogproxd run \
  --postgres postgres://bogbogprox:bogbogprox@127.0.0.1:5432/bogbogprox \
  --auth-token "SUPER-SECRET-PROJECT-TOKEN"
```
- Production แนะนำใช้ `BOGBOGPROX_POSTGRES` และ `BOGBOGPROX_AUTH_TOKEN` แทน CLI flags
  เพื่อไม่ให้ secrets ปรากฏใน process list/shell history.
- `--postgres` = ใช้ store ที่แชร์กัน (แทน SQLite ในเครื่อง).
- `--auth-token` = ทีมต้องมี token นี้ถึงเข้าได้. **ไม่ใส่ = local ไม่มี auth.**
- ⚠️ **วางหลัง TLS / reverse proxy (nginx/caddy) ก่อน expose ออกเน็ต** — API/SSE เป็น http.

### 6.3 ฝั่งผู้ใช้ (operators)
- เปิด `http://<team-server>:9000/` → เจอหน้า **join** → ใส่ project token + ชื่อ → Join.
- ตั้ง browser ให้ proxy ไปที่ team proxy (`<team-server>:8888`).
- เห็น flow/finding ของทุกคนสด, config (rules/scope/vars/macros) แชร์กัน,
  toolbar โชว์ **👤 ใครออนไลน์**. ใครเพิ่ม rule คนอื่นเห็นทันที (panel reload).

### 6.4 หลาย proxy (topology B, ไม่บังคับ)
รัน `bogbogproxd ... --postgres <same-url>` หลายตัว (คนละ proxy port) ชี้ Postgres เดียวกัน —
event จะ sync ข้าม process ผ่าน Postgres LISTEN/NOTIFY อัตโนมัติ (แต่ละคนรัน proxy ของตัวเอง
แต่เห็น flow ของทุกคน). Rules/scope/scanner/vars/macros เก็บใน Postgres และ reload
เข้า daemon อื่นอัตโนมัติ. Intercept queue เป็นของ proxy ต้นทาง จึงต้อง forward/drop
ผ่าน UI ที่ต่อ daemon ตัวนั้น.

---

## 7. Config & ไฟล์

- CA: `~/.config/bogbogprox/ca/` (หรือใต้ `$BOGBOGPROX_HOME`)
- Flows (local): SQLite `~/.local/share/bogbogprox/flows.sqlite` (หรือ `$BOGBOGPROX_HOME/data`)
- Rules/scope/scanner/vars/macros: `~/.config/bogbogprox/config.json` — **persist ข้าม restart**
  (team mode เก็บใน Postgres แทน)
- Local directories ถูกสร้างเป็น `0700`; SQLite/config/secret material เป็น `0600` บน Unix.
- Team session หมดอายุเมื่อไม่มี activity 12 ชั่วโมง.
- `BOGBOGPROX_HOME` override ที่อยู่ทั้งหมด (พกพา/เทสต์)

---

## 8. ปัญหาที่เจอบ่อย

- **HTTPS ขึ้น cert error** → ยังไม่ได้ติดตั้ง CA ใน trust store (ดู §1) หรือใช้ `--cacert`.
- **proxy 8080 ชนของอื่น** → default เป็น 8888 อยู่แล้ว; เปลี่ยนด้วย `--proxy`.
- **ต่อ team server ไม่ได้ / 401** → ยังไม่ได้ join / token ผิด / server ไม่ได้เปิด `--auth-token`.
- **desktop build fail** → ยังไม่ลง webkit deps (§5).
