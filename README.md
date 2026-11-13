# PII Guard Gateway（個人情報自動マスキング・監査証跡ゲートウェイ）

外部AIやローカルLLMへ業務データを連携する前に、**個人情報（PII）や機密数値を自動検知して決定論的にマスキングし、生データを一切残さない改ざん検知付き監査ログ（SHA-256ハッシュチェーン）を記録する**軽量ゲートウェイです。

## 1. 解決する現場の制約
* **個人情報・機密情報の外部流出防止**：自治体・大学・企業などの照会データや申請テキストには、氏名・住所・電話番号・メールアドレス・金額・マイナンバー等が含まれるため、そのまま外部APIやAIへ渡せない。
* **閉域環境での導入性**：外部パッケージのインストールが制限される環境でも動くよう、**Python標準ライブラリのみ（依存ゼロ）**で設計。
* **監査証跡（誰が・いつ・何を処理したか）**：監査ログに個人情報の生データや操作者の実IDを残さず、ハッシュ化IDと検知件数・種別のみをハッシュチェーンで連結して改ざん検知を可能にする。

## 2. アーキテクチャと設計判断
1. **Fail-Closed（安全側倒し）**：不正な入力型やポリシー評価エラー時は処理を即時中断し、無防備なデータ通過を防ぐ。
2. **メモリ内限定トークン復元（In-Memory Token Vault）**：AIへ渡すテキストは `[PERSON_1]` / `[PHONE_1]` 等へ置換し、対応表は外部ファイルやログへ書き出さず、処理セッション内のメモリ上でのみ復元可能とする。
3. **改ざん検知付き監査ログ（Hash-Chained JSONL）**：各レコードが直前レコードの `record_hash`（SHA-256）を保持するため、ログの1行でも改ざんされると `verify-log` コマンドが即時検知する。

## 3. クイックスタート（動作確認・テスト）

```bash
# 1. 全自動テストの実行
python3 -m unittest discover -s tests -v

# 2. サンプルCSVのマスキング＆監査ログ出力
PYTHONPATH=src python3 -m pii_guard.cli sanitize-csv \
  --input examples/sample_inquiries.csv \
  --output out/sanitized_inquiries.csv \
  --audit-log out/audit.jsonl

# 3. 監査ログの改ざん検知チェック
PYTHONPATH=src python3 -m pii_guard.cli verify-log --audit-log out/audit.jsonl
```
