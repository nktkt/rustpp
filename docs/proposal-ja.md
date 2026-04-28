# Rust++ — “安全な低レイヤ言語”から“検証可能な大規模システム言語”へ

C++がCに対して「抽象化・型・RAII・ジェネリクス・OOP」を追加したように、**Rust++はRustに対して「検証・効果型・コンポーネント・高度な所有権表現・信頼できるビルド」を追加する上位レイヤ**として考える。

ただし、C++のように複雑性を無制限に積むのではなく、Rust++は次の思想にする。

> **Rustの安全性・ゼロコスト・所有権を壊さず、より大規模なソフトウェア、AI時代の自動生成コード、組込み、クラウド、OS、ロボティクス、検証済みシステムに向けて拡張する。**

Rustにはすでにeditionという後方互換を保ちながら言語変更を導入する仕組みがあり、Rust 2024 EditionはRust 1.85.0で安定化されている。Rust++も「Rustを置き換えるフォーク」ではなく、**edition的・opt-inな上位構文 + ツールチェーン + 標準ライブラリ拡張**として始めるのが現実的である。([Rust Blog][1])

## このリポジトリのMVP実装

このリポジトリには、Rust++の最初の実装スライスとして次を含めている。

- `crates/rustpp-attributes`: `#[component]`, `#[contract]`, `#[requires]`, `#[ensures]`, `#[effects]`, `#[unsafe_boundary]`
- `crates/stdpp`: Rust++用の標準拡張ライブラリ、`refined_type!`、`capability!`、prelude
- `crates/rpp`: `rpp check/test/build/audit/effects/policy/sbom/prove/lower/expand/new`
- `examples/payment_service`: component、contract、effectを使う最小サンプル
- `examples/rpp/minimal.rpp`: `.rpp` lowererの最小サンプル
- `examples/unsafe_boundary.rs`: unsafe boundary監査メタデータのサンプル
- `rustpp.toml`: unsafeとeffectを制限する最小ポリシー

動作確認:

```bash
cargo run -p rpp --bin rpp -- check -- --workspace
cargo test --workspace
cargo run -p payment_service
cargo run -p rpp --bin rpp -- audit .
cargo run -p rpp --bin rpp -- effects .
cargo run -p rpp --bin rpp -- effects --deny Net .
cargo run -p rpp --bin rpp -- policy .
cargo run -p rpp --bin rpp -- sbom
cargo run -p rpp --bin rpp -- lower examples/rpp/minimal.rpp
cargo run -p rpp --bin rpp -- prove .
cargo run -p rpp --bin cargo-pp -- pp check -- --workspace
```

## 1. Rust++の立ち位置

### C → C++ との対応

| 観点 | C → C++ | Rust → Rust++ |
| --- | --- | --- |
| 中心思想 | 手続き型Cに高水準抽象化を追加 | Rustに検証可能性・大規模設計能力を追加 |
| 構造化 | `struct + function` → `class` | `struct + impl + trait` → `component + protocol` |
| メモリ管理 | 手動管理 → RAII | ownership → ownership + region/view/effect |
| 型 | C型 → template / class / overload | trait/generic → contract / refinement / associated protocol |
| マクロ | C macro → template/metaprogramming | proc macro → hygienic reflection / typed codegen |
| エラー処理 | errno → exception | `Result` → typed error/effect/capability |
| 大規模開発 | ヘッダ/リンク地獄を改善しようとした | cargo/cratesを拡張し、信頼性・監査・SBOM・policyを統合 |
| 危険性 | 複雑性と未定義動作が増えた | unsafeをさらに封じ込め、検証可能にする |

Rust++は「Rustにclassを足す」ではなく、**Rustに“証明可能な設計単位”を足す**言語である。

## 2. Rust++の設計原則

1. **Rust互換を最優先**
   既存のRust crateをそのまま使える。Rust++コードは可能な限りRustへ変換できる。

2. **unsafeを消すのではなく隔離・監査する**
   `unsafe`はOS、FFI、組込みでは必要。Rust++では`unsafe module`を明示し、契約・監査ログ・境界型で管理する。

3. **抽象化はゼロコストを基本にする**
   `component`や`contract`は、可能な限りコンパイル時に消える。必要なときだけ実行時チェックを残す。

4. **大規模設計を言語で支援する**
   crate単位ではなく、service、component、capability、effect、policyを第一級概念にする。

5. **AI生成コードに強い言語にする**
   LLMが書いたコードでも、権限・副作用・契約・unsafe境界が型レベルで見えるようにする。

6. **Rust本体への還元を前提にする**
   成功した機能はRust RFCへ戻す。Rust++は永遠の分裂ではなく、実験場にもなる。

Rust公式のロードマップでも、学習曲線の緩和、エコシステム拡張、プロジェクト運営のスケールが重視されている。Rust++はこの方向性をさらに押し進める構想である。([lang-team.rust-lang.org][2])

## 3. Rust++の全体構造

```text
Rust++
├── Language Layer
│   ├── component / protocol
│   ├── contract / invariant / refinement type
│   ├── effect / capability system
│   ├── ownership++ / region / view type
│   ├── async++ / cancellation / structured concurrency
│   └── reflection / typed macro
│
├── Compiler Layer
│   ├── rppc: Rust++ frontend
│   ├── Rustへのlowering
│   ├── borrow/effect/contract checker
│   ├── verifier integration
│   └── rustcとの連携
│
├── Standard Library Layer
│   ├── stdpp
│   ├── actor / service / protocol
│   ├── typed async runtime abstraction
│   ├── policy / audit / tracing
│   └── safe FFI boundary
│
├── Tooling Layer
│   ├── cargo++
│   ├── rpp check
│   ├── rpp prove
│   ├── rpp audit
│   ├── rpp migrate
│   └── rpp lsp
│
└── Ecosystem Layer
    ├── crates.io互換
    ├── trusted crate index
    ├── SBOM / signed build
    ├── embedded profile
    ├── kernel profile
    ├── cloud profile
    └── wasm/edge profile
```

## 4. 言語機能案

### 4.1 `component`：大規模設計の基本単位

Rustの`struct + impl`は強力だが、大規模システムでは「状態」「依存」「権限」「ライフサイクル」「テスト境界」を明示したい。そこでRust++では`component`を導入する。

```rust
component UserService<R: UserRepository> {
    repo: R,
    clock: Clock,

    async fn register(&mut self, email: Email) -> Result<UserId>
        effects(Db, Time)
        requires email.is_valid()
    {
        let user = User::new(email, self.clock.now());
        self.repo.insert(user).await
    }
}
```

Rustへはおおよそ次のようにloweringされる。

```rust
struct UserService<R: UserRepository> {
    repo: R,
    clock: Clock,
}

impl<R: UserRepository> UserService<R> {
    async fn register(&mut self, email: Email) -> Result<UserId> {
        debug_assert!(email.is_valid());
        let user = User::new(email, self.clock.now());
        self.repo.insert(user).await
    }
}
```

`component`はclassではない。継承ではなく、**依存・状態・契約・副作用を明示する構造体**である。

### 4.2 `protocol`：traitより設計意図が強い抽象

Rustのtraitは強力だが、API契約、非同期、権限、副作用、エラー境界をまとめて表現するには不足がある。

```rust
protocol UserRepository {
    async fn insert(&mut self, user: User) -> Result<UserId>
        effects(Db)
        ensures result.is_ok() => self.contains(user.id);
}
```

`protocol`はtraitへ変換されるが、Rust++のcheckerは追加情報を読む。

- この関数はDB権限を使う
- 成功後にユーザーが保存されている必要がある
- async境界を持つ
- mock可能
- policy監査の対象

### 4.3 `contract`：契約プログラミング

Rust++の重要機能は契約である。

```rust
fn withdraw(account: &mut Account, amount: Money) -> Result<()>
    requires amount > 0
    requires account.balance >= amount
    ensures account.balance == old(account.balance) - amount
{
    account.balance -= amount;
    Ok(())
}
```

契約は3段階で扱う。

| モード | 動作 |
| --- | --- |
| debug | 実行時assert |
| release | 重要契約のみ残す |
| verified | SMT solver / static analyzerで検証 |

これにより、AI生成コードや大規模チーム開発でも「仕様」がコード内に残る。

### 4.4 refinement type：値制約つき型

```rust
contract type Email = String
    where self.contains("@");

contract type NonZeroUsize = usize
    where self > 0;
```

これにより、関数の中で毎回チェックするのではなく、**型になった時点で保証済み**にする。

```rust
fn send_mail(to: Email, body: Message) -> Result<()>;
```

Rustの`newtype`パターンをより簡潔にしたものである。

### 4.5 effect / capability system：副作用を型に出す

Rust++では、関数が何をするかを型シグネチャに出す。

```rust
fn read_config(path: Path) -> Result<Config>
    effects(FsRead);

fn connect(addr: SocketAddr) -> Result<Connection>
    effects(Net, Alloc);
```

これにより、次のような制御ができる。

```rust
policy PureComputation {
    deny effects(FsRead, FsWrite, Net, Db, Unsafe);
}
```

使い道は大きい。

| 用途 | 効果 |
| --- | --- |
| AI生成コード | 勝手なファイル読み書きやネットアクセスを検出 |
| 組込み | allocation禁止を型で保証 |
| セキュリティ | crypto key操作をcapabilityで制限 |
| テスト | DBや時刻依存を明示的にmock |
| サーバー | handlerごとの権限監査 |

### 4.6 ownership++：所有権をより表現しやすくする

Rust++では、Rustの所有権を壊さずに表現力を増やす。

| 機能 | 目的 |
| --- | --- |
| `view<T>` | 所有しない読み取りビュー |
| `unique<T>` | 一意所有の明示 |
| `shared<T>` | 共有所有の明示 |
| `pinned<T>` | 移動不可オブジェクトの明示 |
| `region 'r` | ライフタイムを人間が読める領域名にする |
| field projection | 構造体の一部だけ借用しやすくする |

Rustの現在の公式プロジェクト目標にも、組み込み参照`&`の特別扱いをユーザー定義スマートポインタに広げる「Beyond the &」や、trait system、コンパイル高速化、高水準Rustの改善が含まれている。Rust++のownership++はこの方向と相性がよい。([Rust言語][3])

例：

```rust
region Request;

fn handle(req: view<RequestData @ Request>) -> Response {
    // Request領域の間だけ有効な読み取りビュー
}
```

### 4.7 async++：構造化並行性

Rustのasyncは強力だが、runtime、cancellation、drop、trait、stream、timeout、selectなどの設計が分散しがちである。Rust++では構造化する。

```rust
task_group workers {
    spawn fetch_user(id);
    spawn fetch_orders(id);

    timeout 300.ms;

    join all;
}
```

また、async関数の副作用を明示する。

```rust
async fn fetch_user(id: UserId) -> Result<User>
    effects(Net, Db)
    cancel_safe
{
    ...
}
```

async++で扱うもの：

| 機能 | 説明 |
| --- | --- |
| structured concurrency | 親taskが子taskの寿命を管理 |
| cancellation safety | キャンセル時に不変条件が壊れないことを示す |
| async drop | 非同期リソース解放 |
| runtime trait | tokio等に依存しすぎない抽象 |
| effect付きasync | IO、DB、Networkを型に表示 |

### 4.8 unsafe++：危険コードの封じ込め

Rust++では`unsafe`を禁止しない。代わりに、危険領域を明確に分離する。

```rust
unsafe module ffi_crypto
    reason "OpenSSL FFI boundary"
    audit "2026-04"
{
    extern "C" {
        fn EVP_EncryptUpdate(...);
    }

    safe fn encrypt(input: &[u8], key: Key) -> Result<Vec<u8>>
        ensures result.is_ok() => !result.unwrap().is_empty()
    {
        unsafe {
            ...
        }
    }
}
```

unsafe++のルール：

| ルール | 内容 |
| --- | --- |
| unsafe module必須 | FFIやraw pointer領域を明示 |
| reason必須 | なぜunsafeが必要か書く |
| safe wrapper必須 | 外へ出すAPIは安全境界を持つ |
| audit metadata | 誰がいつ確認したか |
| unsafe diff report | unsafe変更だけCIで強調 |
| proof hook | 契約やfuzz結果と紐づける |

### 4.9 reflection++：安全なメタプログラミング

Rustのproc macroは強力だが、型情報との連携やIDE体験が難しいことがある。Rust++では型付きreflectionを導入する。

```rust
derive_schema!(User);

reflect User {
    for field in fields {
        generate_json_mapping(field);
    }
}
```

制約：

- hygieneを守る
- 型チェック後情報を使える
- 生成コードをIDEで見える
- compile errorを人間に返す
- template地獄にしない

C++ templateの反省を活かし、**強力だが読めるメタプログラミング**を目指す。

### 4.10 `stdpp`：Rust++標準ライブラリ

Rust++には`stdpp`を用意する。

```rust
use stdpp::prelude::*;
```

内容：

| モジュール | 役割 |
| --- | --- |
| `stdpp::contract` | 契約・不変条件 |
| `stdpp::effect` | capability/effect |
| `stdpp::component` | component lifecycle |
| `stdpp::actor` | actor / mailbox |
| `stdpp::asyncx` | structured concurrency |
| `stdpp::ffi` | safe FFI boundary |
| `stdpp::audit` | unsafe/security audit |
| `stdpp::policy` | 実行権限・ビルド権限 |
| `stdpp::test` | property test / model test |
| `stdpp::profile` | embedded/cloud/kernel設定 |

## 5. Rust++のプロファイル

Rust++は用途別にプロファイルを分ける。

| Profile | 用途 | 特徴 |
| --- | --- | --- |
| `core++` | no_std、組込み、OS | allocation制御、panic制御、最小機能 |
| `app++` | CLI、Web、業務アプリ | async、component、contract |
| `cloud++` | サーバー、分散システム | tracing、policy、service、actor |
| `kernel++` | カーネル、ドライバ | unsafe監査、pin、FFI、no_std |
| `verify++` | 安全重要システム | contract、proof、model checking |
| `wasm++` | WebAssembly、edge | capability制限、サイズ最適化 |
| `agent++` | AI agent / 自動化 | effect制約、権限管理、監査ログ |

## 6. Rust++で書くサンプル

### Webサービス例

```rust
use stdpp::prelude::*;

capability Db;
capability Net;
capability Time;

contract type Email = String
    where self.contains("@");

protocol UserRepository {
    async fn insert(&mut self, user: User) -> Result<UserId>
        effects(Db)
        ensures result.is_ok() => self.contains(result.unwrap());
}

component UserService<R: UserRepository> {
    repo: R,

    async fn register(&mut self, email: Email) -> Result<UserId>
        effects(Db, Time)
        requires email.len() < 256
    {
        let user = User {
            email,
            created_at: Time::now()?,
        };

        self.repo.insert(user).await
    }
}

service HttpApi {
    route POST "/users" -> create_user;

    async fn create_user(req: Json<CreateUserRequest>) -> HttpResult
        effects(Db, Net, Time)
    {
        let email = Email::try_from(req.email)?;
        let id = self.user_service.register(email).await?;
        Ok(json!({ "id": id }))
    }
}
```

ここでRust++ checkerは次を見る。

- `/users` handlerはDB、Network、Timeを使う
- `Email`は検証済みでなければ作れない
- `register`は256文字未満しか受けない
- `UserRepository`は保存後条件を満たす必要がある
- unsafeは出てこない
- testでは`Db`と`Time`を差し替えられる

## 7. Rust++が追加しないもの

Rust++でやらない方がよいものも明確にする。

| 追加しないもの | 理由 |
| --- | --- |
| Java/C++的なclass継承 | Rustのtrait/compositionと衝突する |
| 暗黙のGC | Rustの所有権モデルを曖昧にする |
| 暗黙の例外 | `Result`文化と相性が悪い |
| 暗黙のnull | `Option`で十分 |
| 暗黙の型変換 | 安全性と可読性を下げる |
| template地獄 | C++の反省点 |
| unsafeの自動隠蔽 | 危険性が見えなくなる |
| 独自package registry強制 | crates.io互換を壊す |

## 8. ツールチェーン計画

### コマンド

```bash
rpp new myapp
rpp check
rpp test
rpp prove
rpp audit
rpp build
rpp migrate
cargo++ build
```

### 役割

| ツール | 役割 |
| --- | --- |
| `rppc` | Rust++ compiler frontend |
| `cargo++` | cargo wrapper |
| `rpp check` | 型・契約・effect確認 |
| `rpp prove` | 契約の静的検証 |
| `rpp audit` | unsafe、依存、権限、SBOM確認 |
| `rpp migrate` | RustからRust++への移行支援 |
| `rpp lsp` | IDE補完、契約表示、effect表示 |
| `rpp expand` | Rustへlowering後のコード表示 |

## 9. 実装アーキテクチャ

### Phase A：Rust上のライブラリとして始める

最初は言語フォークしない。

```rust
#[component]
struct UserService<R: UserRepository> {
    repo: R,
}

#[requires(email.is_valid())]
#[effects(Db, Time)]
async fn register(email: Email) -> Result<UserId> {
    ...
}
```

proc macro、attribute macro、cargo pluginでMVPを作る。

利点：

- すぐ実験できる
- rustc stableで動く
- 既存crateと互換
- 失敗してもRust ecosystemを壊さない

### Phase B：`.rpp`構文を導入

次に専用構文を導入する。

```text
main.rpp
↓ rppc
main.rs
↓ rustc
binary
```

Rust++はRustにloweringされるため、初期段階では独自backend不要である。

### Phase C：checkerを独立させる

次にRust++独自の検査器を足す。

```text
.rpp source
   ↓
parser
   ↓
HIR++
   ├── ownership checker
   ├── effect checker
   ├── contract checker
   ├── unsafe auditor
   └── lowering to Rust HIR/AST
```

### Phase D：rustc連携

成熟後、rustc内部APIやRFC経由で一部機能をRust本体へ還元する。

Rust公式の2026年プロジェクト目標は、年次ゴールとして66件の目標を扱う形になっており、Rust本体も複数年の開発ロードマップを重視している。Rust++も同じく「単発の言語案」ではなく、複数年の実験・検証・還元モデルにするべきである。([Rust言語][4])

## 10. ロードマップ

現在を**2026 Q2開始**とした想定。

### 0〜3か月：構想固定

| 期間 | 目標 | 成果物 |
| --- | --- | --- |
| 2026 Q2 | Rust++ Charter作成 | 設計原則、非目標、互換方針 |
| 2026 Q2 | MVP機能選定 | component、contract、effectに絞る |
| 2026 Q2 | サンプル設計 | Web、CLI、embeddedの3例 |
| 2026 Q2 | GitHub組織作成 | spec、stdpp、rppc、cargo++ |

この段階でやることは「夢を全部詰める」ではなく、**最小のRust++らしさを定義すること**である。

### 3〜9か月：MVP

| 期間 | 目標 | 成果物 |
| --- | --- | --- |
| 2026 Q3 | attribute macro実装 | `#[component]`, `#[requires]`, `#[effects]` |
| 2026 Q3 | `stdpp` alpha | contract/effect/component基盤 |
| 2026 Q3 | `cargo++` alpha | cargo wrapper |
| 2026 Q4 | unsafe audit機能 | unsafe diff、audit metadata |
| 2026 Q4 | LSP prototype | VS Code / RustRover向け表示 |
| 2026 Q4 | 実アプリ試作 | 小規模Web API、CLI、no_std demo |

MVPの成功条件：

- 既存Rust projectに導入できる
- Rustへの変換コードが読める
- unsafe増加が可視化される
- contractがdebug時に動く
- effectがCIで検出できる

### 9〜18か月：Alpha

| 期間 | 目標 | 成果物 |
| --- | --- | --- |
| 2027 H1 | `.rpp` parser | 専用構文 |
| 2027 H1 | lowering engine | `.rpp` → `.rs` |
| 2027 H1 | effect checker | capability違反検出 |
| 2027 H1 | contract verifier prototype | SMT solver連携 |
| 2027 H1 | async++ prototype | task group、cancel safety |
| 2027 H1 | trusted crate policy | dependency audit |

この段階で、Rust++は「Rust用マクロ集」から「Rust上位言語」になる。

### 18〜30か月：Beta

| 期間 | 目標 | 成果物 |
| --- | --- | --- |
| 2027 H2〜2028 H1 | production pilot | 企業・OSSで試験導入 |
| 2027 H2〜2028 H1 | `rpp prove` beta | 契約検証 |
| 2027 H2〜2028 H1 | `rpp migrate` | RustからRust++へ部分移行 |
| 2027 H2〜2028 H1 | profile system | core++ / cloud++ / verify++ |
| 2027 H2〜2028 H1 | FFI++ | C/C++境界の安全wrapper |
| 2027 H2〜2028 H1 | spec v0.9 | 言語仕様草案 |

Betaの成功条件：

- 実プロダクトの一部で使える
- Rust crateとの相互運用が自然
- compile time overheadが許容範囲
- contract/effectの価値が明確
- unsafe監査がCIで実用になる

### 30〜48か月：Rust++ 1.0

| 期間 | 目標 | 成果物 |
| --- | --- | --- |
| 2028 H2〜2030 | Rust++ 1.0 | 安定仕様 |
| 2028 H2〜2030 | stdpp 1.0 | 標準拡張ライブラリ |
| 2028 H2〜2030 | cargo++ 1.0 | ビルド・監査・policy |
| 2028 H2〜2030 | certification mode | safety critical向け |
| 2028 H2〜2030 | RFC還元 | Rust本体への提案 |
| 2028 H2〜2030 | governance設立 | Rust++ Working Group |

1.0では「全部入り」ではなく、次を安定化する。

- component
- protocol
- contract
- effect
- unsafe audit
- Rust lowering
- stdpp core
- cargo++ audit
- LSP support

## 11. 開発体制

### Working Groups

| WG | 担当 |
| --- | --- |
| Language WG | syntax、semantics、仕様 |
| Compiler WG | parser、lowering、checker |
| Verification WG | contract、SMT、proof |
| Tooling WG | cargo++、LSP、CI |
| Ecosystem WG | crates互換、policy、migration |
| Safety WG | unsafe audit、FFI、security |
| Embedded WG | no_std、RTOS、kernel |
| Cloud WG | async、service、observability |

## 12. ガバナンス

Rust++は最初からガバナンスを設計する。

### RFCプロセス

```text
Idea
 ↓
Pre-RFC
 ↓
Prototype
 ↓
Experiment Report
 ↓
RFC
 ↓
Alpha
 ↓
Beta
 ↓
Stable
```

### 安定化条件

| 条件 | 内容 |
| --- | --- |
| Rust互換 | 既存Rust crateと使える |
| lowering透明性 | 生成Rustが読める |
| IDE対応 | 補完・エラー・定義ジャンプ |
| 性能 | 追加コストが測定済み |
| 安全性 | unsafe増加なし、または監査可能 |
| 教育性 | 初心者が理解できる説明がある |
| 実例 | 3つ以上の実プロジェクト導入 |

Rust公式のProject Goalsも、貢献者が目標を提案し、Rustチームが支援する「契約」として位置づけられている。Rust++も同じように、思いつきの機能追加ではなく、champion、実装者、評価指標を持つべきである。([Rust言語][4])

## 13. 成功指標

### 技術指標

| 指標 | 目標 |
| --- | --- |
| Rust crate互換 | 95%以上 |
| Rustへのlowering | 100%表示可能 |
| unsafe可視化 | CIで全検出 |
| contract overhead | release時は原則ゼロまたは明示 |
| compile overhead | MVPでRust比+20%以内、1.0で+10%以内 |
| effect違反検出 | CIで自動検出 |
| no_std対応 | core++で必須 |

### 開発者体験指標

| 指標 | 目標 |
| --- | --- |
| boilerplate削減 | component/protocolで20〜40% |
| unsafe review時間 | audit metadataで短縮 |
| onboarding | Rust経験者が1週間以内に基本利用 |
| IDE満足度 | Rust Analyzer相当の体験 |
| generated code理解 | `rpp expand`で追跡可能 |

### 社会的指標

| 指標 | 目標 |
| --- | --- |
| OSS導入 | 10 project |
| 企業pilot | 3社以上 |
| embedded実例 | 2件 |
| cloud実例 | 2件 |
| verification実例 | 1件 |
| Rust RFC還元 | 2件以上 |

## 14. 最初のMVP仕様

最初のRust++はこれだけでよい。

```rust
#[component]
struct PaymentService<R: PaymentRepository> {
    repo: R,
}

#[contract]
impl<R: PaymentRepository> PaymentService<R> {
    #[requires(amount > 0)]
    #[effects(Db, Time)]
    async fn charge(&mut self, user: UserId, amount: Money) -> Result<PaymentId> {
        self.repo.insert(user, amount).await
    }
}
```

MVP機能：

| 機能 | 実装方法 |
| --- | --- |
| `#[component]` | proc macro |
| `#[requires]` | debug assert生成 |
| `#[ensures]` | debug assert生成 |
| `#[effects]` | lint/checker |
| `#[unsafe_boundary]` | audit metadata |
| `cargo++ audit` | unsafe/dependency report |
| `rpp expand` | 生成Rust表示 |

このMVPなら、言語フォークせずに始められる。

## 15. Rust++のコアメッセージ

Rust++はこう定義するとよい。

> **Rust++ is a verification-oriented, component-based, effect-aware superset of Rust for building trustworthy large-scale systems.**

日本語では：

> **Rust++は、Rustの安全性と性能を保ったまま、契約・副作用・コンポーネント・監査を第一級にした、大規模システム向けのRust上位言語。**

## 16. 最終ロードマップまとめ

```text
2026 Q2
  構想、仕様草案、MVP選定

2026 Q3-Q4
  proc macro MVP
  stdpp alpha
  cargo++ alpha
  unsafe audit
  effect lint

2027 H1
  .rpp parser
  Rust lowering
  contract checker
  effect checker
  async++ prototype

2027 H2 - 2028 H1
  beta
  LSP
  production pilot
  verify++ profile
  embedded/cloud profile

2028 H2 - 2030
  Rust++ 1.0
  stdpp 1.0
  cargo++ 1.0
  RFC還元
  Working Group設立
```

## 17. 一言で言うと

C++が「Cに抽象化を足した言語」なら、Rust++は**「Rustに検証可能性と大規模設計能力を足した言語」**である。

classではなくcomponent。  
exceptionではなくtyped effect。  
template地獄ではなくtyped reflection。  
unsafe放置ではなくunsafe audit。  
巨大な標準runtimeではなくprofile別stdpp。  
Rustのforkではなく、Rustへの実験的上位レイヤ。

これがRust++の現実的で強い方向性である。

[1]: https://blog.rust-lang.org/2025/02/20/Rust-1.85.0/ "Announcing Rust 1.85.0 and Rust 2024 | Rust Blog"
[2]: https://lang-team.rust-lang.org/roadmaps/roadmap-2024.html "Roadmap 2024 - The Rust Language Design Team"
[3]: https://rust-lang.github.io/rust-project-goals/ "Introduction - Rust Project Goals"
[4]: https://rust-lang.github.io/rust-project-goals/2026/ "Overview - Rust Project Goals"
