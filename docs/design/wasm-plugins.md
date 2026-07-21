# Design: WASM Plugin Host (Extensions)

> Status: **Draft / design** · Owner: bogbogprox core · Supersedes: DESIGN.md §21 "WASM plugins" notes
> เป้าหมาย: ให้ต่อ **plugin แบบ sandbox ข้ามภาษา** (เขียน Rust/Go/JS/C แล้ว compile เป็น WASM) มาขยายความสามารถได้ — คู่แข่งของ Burp BApp extension แต่ **ปลอดภัยกว่า (sandbox), ข้ามภาษา, ไม่ต้อง JVM**.

---

## 1. Goals / Non-goals

**Goals**
- Plugin **แก้/ตรวจ req/resp** ได้ระดับโปรแกรม (มากกว่า Match&Replace regex).
- Plugin **เพิ่ม passive/active scan check** ของตัวเอง.
- Plugin เรียก **capability ของ host** ได้ (log, ยิง request ผ่าน repeater, add finding, อ่าน/เขียนตัวแปร, kv store).
- **Sandbox by default** — plugin ทำ syscall/filesystem/network เองไม่ได้ ต้องผ่าน host function ที่ operator อนุมัติ (capability-based).
- **ข้ามภาษา** — อะไรก็ได้ที่ compile เป็น WASM component (Rust, TinyGo, C, JS via componentize-js, AssemblyScript).
- **จำกัด resource** — fuel/time/memory limit กัน plugin กิน CPU/RAM ไม่จำกัดใน hot path.

**Non-goals (เฟสแรก)**
- Native plugin (.so/.dll) — ไปทาง WASM อย่างเดียว (ปลอดภัย/พกพา).
- รัน Burp .jar/.bapp ตรงๆ — คนละ ABI (อาจ import wordlist/config ทีหลัง แต่ไม่รันโค้ด Java).
- Plugin UI แบบ arbitrary (custom tab render เอง) — เฟสท้าย (§8).
- Marketplace/signing — เฟสท้าย.

---

## 2. Runtime decision

| ตัวเลือก | ข้อดี | ข้อเสีย |
|---|---|---|
| **wasmtime + Component Model (WIT) + WASI p2** | มาตรฐาน Rust, typed interface (WIT), fuel/epoch limits, componentmodel = ABI สะอาดข้ามภาษา | component model ยังใหม่ (p2 เพิ่ง stabilize), toolchain บางภาษายังไม่นิ่ง |
| wasmtime + core module (raw) | เสถียรกว่า | ABI ดิบ (แลก memory เอง), marshaling เจ็บ |
| wasmer / wasm3 | ทางเลือก | ecosystem/มาตรฐานน้อยกว่า wasmtime |

**Decision (ADR W-001): wasmtime + Component Model + WIT + WASI Preview 2.**
เหตุผล: typed host↔plugin contract (WIT), fuel/epoch สำหรับ limit, และ component model
ให้ plugin ข้ามภาษาโดยไม่ต้อง marshal memory เอง. ยอมรับความใหม่ของ p2 (pin เวอร์ชัน + WIT world versioned).

---

## 3. Interface — WIT world (host ↔ plugin)

`wit/bogbogprox.wit` (ร่าง):
```wit
package bogbogprox:plugin@0.1.0;

interface types {
  record http-request  { method: string, url: string, headers: list<tuple<string,string>>, body: list<u8> }
  record http-response { status: u16, headers: list<tuple<string,string>>, body: list<u8> }
  enum severity { info, low, medium, high }
  record finding { severity: severity, title: string, detail: string }
  variant req-action { forward(http-request), drop, unchanged }
  variant resp-action { forward(http-response), drop, unchanged }
}

// สิ่งที่ HOST ให้ plugin เรียก (capabilities — gated ต่อ plugin)
interface host {
  use types.{http-request, http-response, finding};
  log: func(msg: string);
  add-finding: func(f: finding);
  http-send: func(req: http-request) -> result<http-response, string>;  // ผ่าน repeater (cap: network)
  var-get: func(name: string) -> option<string>;
  var-set: func(name: string, value: string);                            // cap: vars
  kv-get: func(key: string) -> option<list<u8>>;                         // cap: storage
  kv-set: func(key: string, value: list<u8>);
}

// สิ่งที่ PLUGIN ต้อง export (hooks — เรียกโดย host)
world plugin {
  import host;
  use types.{http-request, http-response, req-action, resp-action, finding};
  export metadata: func() -> string;                        // JSON manifest
  export on-request:  func(req: http-request) -> req-action;
  export on-response: func(resp: http-response) -> resp-action;
  export passive-scan: func(req: http-request, resp: http-response) -> list<finding>;
}
```
- ทุก hook เป็น optional (default = unchanged / []).
- โมเดล WIT mirror `bogbogprox-core::model` — convert ที่ boundary.

**Decision (ADR W-002):** WIT world `bogbogprox:plugin@0.x`; hook = on-request/on-response/passive-scan; host cap = log/add-finding/http-send/var/kv.

---

## 4. Capability & sandbox

- WASM sandbox by default: ไม่มี syscall, filesystem, network, clock (ยกเว้นที่ host เปิดให้).
- Plugin ประกาศ capability ที่ขอใน **manifest** (`metadata()`): `["network","vars","storage"]`.
- Host linker จะ **ผูกเฉพาะ host function ที่ operator อนุมัติ** ให้ plugin นั้น. เรียก cap ที่ไม่ได้รับ → trap.
- **WASI**: จำกัดสุด — ไม่ preopen dir, ไม่ให้ socket. เวลา/สุ่ม (ถ้าจำเป็น) ผ่าน host function ที่ควบคุมได้.

**Decision (ADR W-003): capability-based, deny-by-default; manifest ประกาศ, operator อนุมัติต่อ plugin.**

---

## 5. Execution model (สำคัญสุดทางเทคนิค)

wasmtime `Store`/`Instance` เป็น **!Send/!Sync ต่อ instance** แต่ engine เรารัน async หลาย thread.
→ ใช้ **plugin-actor thread** (เหมือน pattern ของ `bogbogprox-store-postgres` DB-actor):
- 1 thread (หรือ pool) เป็นเจ้าของ wasmtime `Engine` + instances.
- hook call จาก engine/handlers ส่ง **job (closure/enum) ผ่าน channel** → actor รัน hook บน instance → ส่งผลกลับ (block รอ เหมือน store ปัจจุบัน).
- Instance-per-plugin; ถ้าต้อง concurrency สูง → pool ของ instance ต่อ plugin (instance pre-instantiation ของ wasmtime ช่วยได้).

**Resource limits ต่อ call:**
- **fuel metering** (`Store::set_fuel`) — จำกัดจำนวน instruction; หมด fuel = trap (กัน infinite loop).
- **epoch interruption** — timeout แบบ wall-clock (thread แยกเดิน epoch; hook เกินเวลา = interrupt).
- **memory limit** — `StoreLimits` จำกัด memory grow ต่อ instance.
- Trap/panic ใน plugin = จับ, log, **disable plugin นั้น** (ไม่ให้ล้ม daemon).

**Decision (ADR W-004): plugin-actor thread(s) เป็นเจ้าของ instances; hook dispatch ผ่าน channel + block (เหมือน store); fuel + epoch + memory limit ต่อ call; trap → disable plugin.**

---

## 6. Hook points ใน pipeline

| Hook | จุดใน pipeline | หมายเหตุ |
|---|---|---|
| `on-request` | engine `handle_request` **หลัง** M&R rules, **ก่อน** intercept | plugin แก้/drop request ได้ (dirty flag เดิม) |
| `on-response` | engine `handle_response` หลัง M&R | แก้/drop response |
| `passive-scan` | หลัง flow เสร็จ (จุดเดียวกับ Scanner) | คืน findings → เข้า `Scanner::record` + broadcast |
| (active) | ผ่าน `http-send` capability | plugin ยิง probe เองแล้ว add-finding |

ลำดับ: built-in (M&R/scanner) → plugins (ตามลำดับ enable). Plugin ที่ drop = จบ chain.

**Decision (ADR W-005):** hook ต่อจาก built-in; on-request/response reuse dirty-rebuild เดิม; passive-scan feed เข้า Scanner เดิม.

---

## 7. Lifecycle & distribution

- Plugin = ไฟล์ **`.wasm` (component)** + manifest (ฝังใน `metadata()` หรือ `plugin.toml` ข้างๆ).
- โฟลเดอร์ `<config_dir>/plugins/*.wasm`; โหลดตอน startup + ผ่าน API.
- Manifest: `{ name, version, capabilities[], hooks[], config_schema? }`.
- Config ต่อ plugin (เช่น API key ของ plugin) เก็บใน settings backend เดิม (local/Postgres).
- Enable/disable ต่อ plugin (persist). Disabled = ไม่ถูกเรียก, ไม่ instantiate.

**API:**
```
GET    /api/v1/plugins                 -> list (name, version, enabled, caps)
POST   /api/v1/plugins                 -> upload .wasm (multipart) + validate
POST   /api/v1/plugins/:id/toggle      -> enable/disable (อนุมัติ caps ตอน enable)
DELETE /api/v1/plugins/:id
```
Web: panel "🧩 Plugins" — list + upload + toggle + แสดง caps ที่ขอ (ให้ operator อนุมัติ).

**Decision (ADR W-006):** plugins dir + upload API; manifest ใน component; config/enabled persist ผ่าน settings backend; UI approve caps ตอน enable.

---

## 8. เฟส (phased delivery)

| เฟส | ทำ | Done เมื่อ |
|---|---|---|
| **P1 · Host + hooks พื้นฐาน** | crate `bogbogprox-plugin` (wasmtime + WIT), plugin-actor, on-request/on-response, host `log`, load จาก dir, fuel/epoch limit, 1 ตัวอย่าง (Rust→wasm) | plugin แก้ header ของ request ที่วิ่งผ่านได้จริง |
| **P2 · Passive scan + findings** | hook `passive-scan` + cap `add-finding` → Scanner; toggle/enable API | plugin เพิ่ม check เอง เห็นใน Findings |
| **P3 · Network + vars/kv** | cap `http-send` (repeater), `var-*`, `kv-*`; active check แบบ plugin | plugin ยิง probe + inject token เองได้ |
| **P4 · Web UI + approval** | panel 🧩 Plugins (upload/toggle/approve caps); config ต่อ plugin | จัดการ plugin จากจอ |
| **P5 · Ecosystem** | HTTPQL custom function, custom UI hook, signing/manifest verify, ตัวอย่างหลายภาษา (Go/JS) | marketplace-ready |

**คุ้มสุดเริ่ม P1** — พิสูจน์ execution model (actor + fuel + WIT) กับ on-request hook ก่อน.

---

## 9. Data model / code changes summary

- **ใหม่:** crate `bogbogprox-plugin` (wasmtime host, WIT bindings, actor, limits, loader); `wit/bogbogprox.wit`; `Plugins` coordinator (list/enable/config); API + Web panel; ตัวอย่าง `examples/plugins/*`.
- **แก้:** engine เรียก `plugins.on_request/on_response` ต่อจาก M&R (reuse dirty); scanner จุดเดียวเรียก `plugins.passive_scan`; settings backend เก็บ plugin config/enabled.
- **ไม่แตะ:** frontends อื่น (คุยผ่าน API เดิม), intercept/repeater/intruder logic.

---

## 10. Risks & open questions

- **Component Model / WASI p2 ยังใหม่** — pin wasmtime, WIT world versioned; toolchain บางภาษา (Go/JS→component) ยังไม่นิ่ง → เริ่มด้วย Rust guest ก่อน.
- **Perf ใน hot path** — ทุก request ผ่าน on-request ของทุก plugin → fuel limit + gate ด้วย "plugin ประกาศว่าสนใจ host/path ไหน" (subscribe filter) เพื่อไม่รันทุก request.
- **Marshaling cost** — copy req/resp เข้า WASM memory ทุก call; body ใหญ่แพง → เคารพ `body_truncated`/16MiB limit เดิม, และให้ plugin ขอ body เฉพาะเมื่อต้องการ (lazy) เป็น optimization ทีหลัง.
- **Instance state** — plugin เก็บ state ข้าม call มั้ย? P1 = stateless ต่อ call (instance reuse ได้แต่ไม่รับประกัน); state ถาวรผ่าน kv cap.
- **Open:** actor เดียว (serialize ทุก plugin call) พอมั้ย หรือต้อง pool ต่อ plugin ตั้งแต่ P1? → วัดจาก P1.
- **Open:** capability approval UX — auto-trust plugin ใน dir ที่ operator วางเอง หรือถามทุกครั้ง?
- **Open:** ควรมี `on-intercept` hook (ให้ plugin ตัดสิน intercept) มั้ย หรือพอแค่ on-request?

---

## 11. ADR log (WASM plugins)

| # | Decision | ที่ปัด | เหตุผล |
|---|---|---|---|
| W-001 | Runtime: **wasmtime + Component Model + WIT + WASI p2** | core module, wasmer/wasm3 | typed contract ข้ามภาษา, fuel/epoch |
| W-002 | Contract: **WIT world** (on-request/response/passive-scan + host caps) | ad-hoc ABI | typed, versioned |
| W-003 | Security: **capability-based deny-by-default** + manifest + approve | ambient authority | sandbox จริง |
| W-004 | Exec: **plugin-actor thread(s)** + fuel/epoch/mem limit; trap→disable | เรียกตรงใน async | wasmtime instance !Send; กัน runaway |
| W-005 | Hooks ต่อจาก built-in; reuse dirty-rebuild + Scanner | pipeline ใหม่ | น้อยที่สุด, เข้ากับ engine เดิม |
| W-006 | Distribution: **.wasm ใน dir + upload API + manifest**; persist ผ่าน settings backend | embed-only | ยืดหยุ่น, จัดการจากจอ |

---

## 12. Next step

เริ่ม **P1**: crate `bogbogprox-plugin` (wasmtime host + `wit/bogbogprox.wit` + plugin-actor + fuel/epoch),
hook `on-request`/`on-response` เข้า engine ต่อจาก M&R, host `log`, โหลดจาก `<config_dir>/plugins/`,
พร้อมตัวอย่าง Rust guest ที่แก้ header. พิสูจน์ execution model ก่อนแล้วค่อยไป scan/network cap.
