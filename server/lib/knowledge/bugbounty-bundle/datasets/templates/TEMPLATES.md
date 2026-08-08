# Dataset Templates

Place your content like this:

datasets/templates/
  raw/
    <source>/<yyyy-mm>/<slug>.json   (matches report_raw.schema.json)
  normalized/
    <source>/<yyyy-mm>/<id>.json     (matches report_normalized.schema.json)
  patterns/
    <category>/<pattern_id>.json     (matches attack_pattern.schema.json)
  training/
    <category>/<pattern_id>.jsonl    (matches training_example.schema.json)

Tip:
- Keep an allowlist of sources and ensure each report is PUBLICLY disclosed or otherwise permitted to reuse.
- Store the original URL + disclosure date + license note.