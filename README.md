# TypeScriptでOAuth 2.0 / OpenID Connectを実装して理解する本 ── サンプルコード

書籍『**TypeScriptでOAuth 2.0 / OpenID Connectを実装して理解する本 ── ライブラリなしでGoogleログインを作る**』の公式サンプルコードリポジトリです。

---

## 📁 ディレクトリ構成

```text
.
├── compose.yml          # ローカルKeycloak起動用Docker Compose
├── ch01/                # 第1章：最小限の認可コードフロー実装（Keycloak + Hono + fetch）
└── ch03/                # 第3章：実務レベルへのセキュリティ強化とGoogle連携
```

- **`ch01/`**: 認可リクエスト、コールバック受信、認可コードとトークンの交換、IDトークンデコードまでを最小限のコードで体験します。
- **`ch03/`**: ディスカバリー（`/.well-known/openid-configuration`）、PKCE、`nonce`、およびJWKS公開鍵を用いたIDトークンの署名・クレーム検証を組み込んだ完全版です。設定を差し替えるだけでKeycloakとGoogleの両方で動作します。

---

## 🚀 クイックスタート

### 1. Keycloakをローカルで起動する

本書では、クラウド設定なしで最速で動かすためにローカルのKeycloakを使用します。

```bash
docker compose up
```

起動後、ブラウザで `http://localhost:8080` を開き、管理コンソールにログインします。
- **ユーザー名**: `admin`
- **パスワード**: `admin`

書籍の手順に従い、Realm（`oauth-book`）、Client（`oauth-book-app`）、User（`alice`）を作成してください。

---

### 2. サンプルコードを実行する

動かしたい章のディレクトリに移動し、依存パッケージのインストールと起動を行います。

#### 第1章を実行する場合:
```bash
cd ch01
npm install

# .env を作成
cp .env.example .env
# .env の OIDC_CLIENT_SECRET をKeycloakで取得した値に編集

npm run dev
```

#### 第3章を実行する場合:
```bash
cd ch03
npm install

# .env を作成
cp .env.example .env
# .env の設定値をKeycloakまたはGoogle Cloud Consoleで取得した値に編集

npm run dev
```

起動後、ブラウザで `http://localhost:3000` にアクセスし、「Login」をクリックしてください。

---

## 🛠 技術スタック

- **Runtime**: Node.js (v18+)
- **Language**: TypeScript
- **Web Framework**: [Hono](https://hono.dev/)
- **Server Adapter**: `@hono/node-server`
- **Identity Provider**: Keycloak / Google

---

## 📄 ライセンス

MIT License
