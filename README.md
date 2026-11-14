# PII Guard Gateway：AIへ渡す前に個人情報を置き換える前処理と、改ざんに気づける監査ログ

[![tests](https://github.com/takashi-101/pii-guard-gateway/actions/workflows/tests.yml/badge.svg)](https://github.com/takashi-101/pii-guard-gateway/actions/workflows/tests.yml)

問い合わせ文などのテキストから、氏名・電話・メール・個人番号・住所・金額を検出して `[PERSON_1]` のような目印に置き換え、処理の記録を監査ログに残すツールです。外部へ送信する機能はありません。置き換えた結果を外部のAIなどへ渡すのは、利用する側の処理です。

## 30秒で読む要点
- **置き換えてから渡す**：6つの対象を正規表現（文字の並びのパターン）で検出し、`[PERSON_1]` などのプレースホルダー（置き換え後の目印）にします。元の値との対応表はメモリ上だけに持ち、ファイルやログには書きません。
- **検出できない範囲を明記**：氏名と住所は「氏名：」「住所：」のようなラベルの後ろだけが対象です。対象ごとに、検出する例と検出しない例をテストで固定し、[検出できない範囲](#検出できない範囲) にまとめています。
- **改ざんに気づける監査ログ**：ハッシュチェーン（各行に、直前の行の内容から計算した値＝ハッシュ値を持たせてつないだもの）で、元の値は書かず、件数・種別・時刻・操作者IDのハッシュ値を記録します。値の書き換え・先頭や途中の行の削除・行の入れ替えは `verify-log` で検出します。末尾の行の削除など、検出できない改ざんも書いています。
- **標準ライブラリのみ**：外部パッケージ・有料API・APIキーは使いません。テスト48件と見本データでの実行を、CI（GitHub Actions による自動実行）で Python 3.11 と 3.12 について行います。

## 処理の流れ
1. 入力：文字列（Pythonから呼ぶ場合）、またはCSVの各セル（CLI＝コマンドラインから使う場合）
2. 検出と置き換え：メール → 個人番号 → 電話 → 郵便番号 → 氏名 → 住所 → 金額 → 追加パターン の順に適用します。先に置き換えた部分は、後の規則の対象になりません。
3. 結果：置き換え後のテキスト、種別ごとの件数、対応表（メモリ上のみ）
4. 監査ログ：JSONL（1行に1つのJSONを書く形式）に1行追記します。CLIでは、1件以上置き換えたセルごとに1行です。

## 検出の対象と方法
| 対象 | 検出の条件 | 置き換え後 |
|---|---|---|
| 氏名 | ラベル「氏名」「名前」「申請者」「担当者」「対象者」「担当」の後に「:」か「：」があるとき、その後ろから区切り（改行、`、` `。` `,` `/` `／` `(` `（` `[`）、「様」「さん」「の件」、または末尾の手前まで | `[PERSON_n]` |
| 電話 | 0で始まり、ハイフンで3つに区切った番号（2〜5桁-1〜4桁-3〜4桁）、または0で始まる10〜11桁の連続した数字。前後に数字が続かないこと | `[PHONE_n]` |
| メール | 英数字と `._%+-` からなる部分 ＋ `@` ＋ 英数字・`.`・`-` からなるドメイン ＋ `.` ＋ 英字2文字以上。前後に英数字や日本語の文字が続かないこと | `[EMAIL_n]` |
| 個人番号（マイナンバー） | 4桁-4桁-4桁、または12桁の連続した数字。前後に数字が続かないこと。検査用数字（番号が正しいかを確かめる最後の1桁）は確認しません | `[ID_NUM_n]` |
| 住所 | ラベル「住所」「所在地」の後に「:」か「：」があるとき、その後ろから区切り（氏名と同じ記号）、「の担当」「宛」、または末尾の手前まで | `[ADDRESS_n]` |
| 住所（郵便番号） | 3桁-4桁。前に「〒」があれば含めて置き換えます。前後に英数字や日本語の文字が続かないこと | `[POSTAL_n]` |
| 金額 | 数字（3桁ごとのカンマ可）＋「円」「万円」「億円」（間に空白1つ可） | `[AMOUNT_n]` |

- ラベルは文中のどこにあっても一致します。そのため「お名前：」「現住所：」も対象になります。
- 数字には全角数字（０〜９）も含みます。ただし電話の先頭の0は半角だけです。ハイフンは半角の `-` だけです。
- 同じテキスト内で同じ値は同じ番号になります。番号は `sanitize` を呼ぶたび（CLIではセルごと）に1から振り直します。

## 検出できない範囲
`tests/test_detection_targets.py` で、以下の挙動をそのまま固定しています。例の値はすべて架空です。

**氏名**
- ラベルの無い氏名：`架空 太郎さんから電話がありました`
- ラベルの後に「:」「：」が無いもの：`氏名 架空 太郎`、`氏名　架空太郎`（全角空白）、`氏名＝架空太郎`
- 一覧に無いラベル：`代表者：架空 太郎`、`Name: Taro Kakuu`
- 括弧内の読み仮名：`名前：架空 太郎（カクウ タロウ）` → `名前：[PERSON_1]（カクウ タロウ）`
- CSVの列名はラベルとして扱いません。「氏名」列のセルに `架空 太郎` だけが入っている場合は置き換わりません（`tests/test_cli.py`）。
- 置き換えすぎ：区切りまでをすべて氏名とみなします。`氏名：架空 太郎 です` → `氏名：[PERSON_1]`、`氏名：架空太郎 電話：000-0000-0000` → `氏名：[PERSON_1][PHONE_1]`（「電話：」も氏名に含まれます）

**電話**
- 国際表記 `+81-90-0000-0000`、括弧 `(000)0000-0000`、空白区切り `000 0000 0000`、全角ハイフン `000－0000－0000`、9桁以下 `000000000`
- 全角数字 `０００-００００-００００` は電話として検出しません。先頭の7桁分が郵便番号として置き換わり、`[POSTAL_1]-００００` になります。
- 誤検出：0で始まる日付 `01-02-2026` は `[PHONE_1]` になります。

**メール**
- 日本語の文字に直接続くもの：`kakuu.taro@example.jpまでご連絡ください`、`メールkakuu@example.jp`。前後に空白か記号（「：」「。」など）が必要です。
- 全角の `＠`、`kakuu [at] example.jp` のような表記、日本語を含むアドレス（`架空@example.jp`、`kakuu@例え.jp`）

**個人番号（マイナンバー）**
- 空白区切り `0000 0000 0000`、全角ハイフン `0000－0000－0000`、4-4-4以外の区切り `0000-00000000`、11桁・13桁の数字
- 誤検出：12桁の数字はすべて置き換えます。`注文番号：123456789012` → `注文番号：[ID_NUM_1]`

**住所**
- ラベルの無い住所：`見本県架空市テスト町1-2-3に住んでいます`
- ラベルの後に「:」「：」が無いもの：`住所 見本県架空市テスト町1-2-3`
- 一覧に無いラベル：`送付先：見本県架空市テスト町1-2-3`
- 郵便番号：日本語の文字に直接続くもの（`郵便番号000-0000`、`〒000-0000見本県`）、ハイフンの無いもの `〒0000000`、全角ハイフン `〒０００－００００`

**金額**
- `¥1,500,000`、`1,500,000 JPY`、漢数字 `百五十万円`、`1万5千円`、`5千円`、「円」の無い `150万`、他の通貨 `150万ドル`
- 小数は一部だけ置き換わります：`1.5億円` → `1.[AMOUNT_1]`

## 実行
Python 3.11 以上（CIでは 3.11 と 3.12）。インストールは不要です。リポジトリ直下で実行します。

```
python -m unittest discover -s tests -v
python pii_guard_cli.py sanitize-csv --input examples/sample_inquiries.csv --output out/sanitized_inquiries.csv --audit-log out/audit.jsonl
python pii_guard_cli.py verify-log --audit-log out/audit.jsonl
```

`pii_guard_cli.py` は `src/` を読み込み先に加えて `pii_guard.cli` を呼ぶだけの入口です。環境変数 `PYTHONPATH` の設定は不要です。

### 入力（`examples/sample_inquiries.csv`、架空のデータ）
```
ticket_id,category,body
INQ-001,補助金照会,"氏名：架空 太郎 / 連絡先：000-0000-0000 / メール：kakuu.taro@example.jp / 申請額：150万円の件で確認したい。"
INQ-002,施設利用,"住所：見本県架空市テスト町1-2-3（〒000-0000）の担当：見本 花子様宛てに資料を送付希望。"
INQ-003,マイナンバー関連,"個人番号：0000-0000-0000 の紐付け状況について照会。"
INQ-004,検出できない例,"架空 次郎さんから、kakuu.jiro@example.jpまで返信がほしいと連絡あり。"
```

### `sanitize-csv` の標準出力
```
{"processed_rows": 4, "total_masked_entities": 8, "output": "out/sanitized_inquiries.csv", "audit_log": "out/audit.jsonl"}
```

### 出力（`out/sanitized_inquiries.csv`）
```
ticket_id,category,body
INQ-001,補助金照会,氏名：[PERSON_1] / 連絡先：[PHONE_1] / メール：[EMAIL_1] / 申請額：[AMOUNT_1]の件で確認したい。
INQ-002,施設利用,住所：[ADDRESS_1]（[POSTAL_1]）の担当：[PERSON_1]様宛てに資料を送付希望。
INQ-003,マイナンバー関連,個人番号：[ID_NUM_1] の紐付け状況について照会。
INQ-004,検出できない例,架空 次郎さんから、kakuu.jiro@example.jpまで返信がほしいと連絡あり。
```
INQ-004 は、検出できない例として入れています（ラベルの無い氏名と、日本語の文字に直接続くメールアドレス）。この出力が実際の出力と一致することは `tests/test_cli.py` で確認しています。

### `verify-log` の標準出力
```
{"valid": true, "records": 3}
```
検出のあった3セル（INQ-001〜003 の `body`）で3行です。同じ `--audit-log` を指定して再実行すると追記され、件数が増えます。改ざんを検出した場合は `"valid": false` を出し、終了コード1で終わります。

`out/audit.jsonl` の1行目（実行例。時刻とハッシュ値は実行ごとに変わります）：
```
{"timestamp_utc": "2026-11-14T09:09:00.275783+00:00", "actor_hash": "44bbfadc71917479", "action": "csv_sanitize:body", "status": "ALLOWED", "total_masked": 4, "counts_by_type": {"EMAIL": 1, "PHONE": 1, "PERSON": 1, "AMOUNT": 1}, "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000", "record_hash": "659714642143e5b62443adec666fb03b3f3e82cfbe3d64efd524f042a3e75d88"}
```

## Python から使う
リポジトリ直下で `python` を起動して実行した例です（`#` の後ろは実際の出力）。

```python
import sys
sys.path.insert(0, "src")  # リポジトリ直下で実行する場合
from pii_guard import PIISanitizer

res = PIISanitizer().sanitize("氏名：架空 太郎 / メール：kakuu.taro@example.jp")
print(res.sanitized_text)   # 氏名：[PERSON_1] / メール：[EMAIL_1]
print(res.counts_by_type)   # {'EMAIL': 1, 'PERSON': 1}
print(res.restore("[PERSON_1] 様へ返信しました"))  # 架空 太郎 様へ返信しました
```

- `restore` は、プレースホルダーをそのままの形で含む文字列だけを元に戻します。AIの応答で `[PERSON_1]` が `PERSON_1` のように変わった場合は戻りません。
- `PolicyConfig` で対象ごとに無効にできます（`mask_email`、`mask_phone`、`mask_mynumber`、`mask_postal_code`、`mask_labeled_person`、`mask_labeled_address`、`mask_currency`）。`custom_patterns` に `(種別名, 正規表現)` を渡すと、追加の対象を置き換えます。CLIからは設定できません。
- 監査ログは `AuditLogger(パス).record(操作者ID, 操作名, 結果)` で追記し、`verify_chain()` で `(正しいか, 行数)` を返します。

## 監査ログ
| 項目 | 内容 |
|---|---|
| `timestamp_utc` | 記録した時刻（UTC） |
| `actor_hash` | 操作者ID（CLIの `--actor`、既定値 `operator-01`）の SHA-256（ハッシュ関数の一種）の先頭16文字 |
| `action` | 操作名。CLIでは `csv_sanitize:列名` |
| `status` | 既定値 `ALLOWED`。CLIは常にこの値です |
| `total_masked`、`counts_by_type` | 置き換えた件数と、種別ごとの件数 |
| `prev_hash` | 直前の行の `record_hash`（1行目は0が64個） |
| `record_hash` | `record_hash` 以外の項目をキー順に並べたJSONの SHA-256 |

元の値は書きません（`tests/test_audit_log.py` で確認）。

**`verify-log`（`verify_chain`）で検出する改ざん**（`tests/test_audit_log.py`）
- 項目の書き換え（件数・種別ごとの件数・操作名・状態・時刻・操作者のハッシュ値）と、項目の追加
- 先頭または途中の行の削除
- 行の入れ替え、同じ行の重複
- JSONとして読めない行、JSONのオブジェクトでない行

**検出できないこと**（同じテストファイルで、この挙動を固定しています）
- 末尾の行の削除：残りの行のつながりは正しいため `valid: true` になります。気づくには、`records` の件数を別の場所に控えて比べる必要があります。
- すべての行のハッシュ値を計算し直した書き換え：鍵を使っていないため、誰でも計算し直せます。
- ログファイル自体の削除：ファイルが無い場合は `{"valid": true, "records": 0}`、終了コード0です。
- `actor_hash` はソルト（推測を防ぐために加える値）を使っていません。既定値の `operator-01` のような推測しやすいIDは、候補を総当たりすれば特定できます。

## テスト（48件）
`python -m unittest discover -s tests -v`

| ファイル | 件数 | 内容 |
|---|---|---|
| `tests/test_detection_targets.py` | 21 | 対象ごとの、検出する例・検出しない例・一部だけ置き換わる例・誤検出の例 |
| `tests/test_audit_log.py` | 14 | 改ざんの検出（書き換え・削除・入れ替え・重複・壊れた行）、検出できない改ざん、ログに元の値が無いこと |
| `tests/test_cli.py` | 5 | 見本CSVの出力（このREADMEの記載と一致すること）、列名を使わないこと、番号の振り直し、列の多い行での停止 |
| `tests/test_pii_guard.py` | 8 | 全種別の置き換え、同じ値に同じ番号、復元、Fail-Closed（エラーのときは処理を止め、データを通さない側に倒す設計）、追加パターン |

## 制約
- 正規表現だけで検出します。文の意味は見ていません。文中の人名や地名を見つける処理（固有表現抽出）は行いません。
- 置き換え後のテキストに残った値（[検出できない範囲](#検出できない範囲)）は、そのまま次の処理へ渡ります。送信前の確認は、このツールの範囲外です。
- Fail-Closed：文字列以外の入力は `TypeError`、追加パターンの正規表現が不正な場合は `re.error` で止まり、置き換え前のテキストを返しません。CLIでは、列名より値の多い行があると `TypeError` で止まります。その時点までの行（置き換え済み）は出力ファイルに残ります。
- CSVは UTF-8 で読み書きします。列名（ヘッダー）は置き換えません。

## ファイル構成
```
src/pii_guard/
  sanitizer.py    検出と置き換え（PIISanitizer、PolicyConfig）、監査ログ（AuditLogger）
  cli.py          CLI（sanitize-csv、verify-log）
pii_guard_cli.py  リポジトリ直下からCLIを動かす入口
examples/         見本データ（架空）
tests/            ユニットテスト
.github/workflows/tests.yml  CI（Python 3.11 と 3.12、テストと見本データでの実行）
```

## 根拠（学習）

| 機能 | 裏付けになる学習（発行元・名称・発行日） | 照会先（Credly） |
|---|---|---|
| AIへ渡す前の個人情報の置き換え（氏名・電話・メール・個人番号・住所・金額） | Coursera（認定：IBM）「Generative AI: Impact, Considerations, and Ethical Issues」2026年11月11日 | https://www.credly.com/badges/17087670-8825-43bc-8c8e-b4dd9b98cc8a |
| ハッシュチェーンによる監査ログと改ざんの検出 | Coursera「Google Cybersecurity Professional Certificate(v.2)」2026年11月12日 | https://www.credly.com/badges/90bbb775-f9b8-4aef-bc24-1ed7c67d17e4 |
| 外部へ送信する機能を持たない構成 | Amazon Web Services Training and Certification「AWS Knowledge: Security Champion - Training Badge」2025年11月10日 | https://www.credly.com/badges/ddab077d-58eb-4807-bec1-69e5c6aeb9a5 |

## ライセンス
MIT（[LICENSE](LICENSE)）
