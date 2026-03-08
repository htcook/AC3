import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);

for (const sessionId of ['lab-1772928774251-35cb1f66', 'lab-1772928774285-17e79c01']) {
  const [rows] = await conn.execute(
    "SELECT session_id, target_url, llm_analysis_json FROM training_lab_sessions WHERE session_id = ?",
    [sessionId]
  );
  if (!rows.length) { console.log(`Session ${sessionId} not found`); continue; }

  let llm = rows[0].llm_analysis_json;
  if (typeof llm === 'string') llm = JSON.parse(llm);

  console.log(`\n${'='.repeat(60)}`);
  console.log(`Target: ${rows[0].target_url}`);
  console.log(`Session: ${sessionId}`);
  console.log(`${'='.repeat(60)}`);

  console.log(`\nLLM Findings (${llm?.findings?.length || 0}):`);
  for (const f of (llm?.findings || [])) {
    console.log(`  [${(f.severity || '?').toUpperCase()}] ${f.title || 'N/A'} | Cat: ${f.category || 'N/A'}`);
  }

  console.log(`\nAttack Chains (${llm?.attackChains?.length || 0}):`);
  for (const ac of (llm?.attackChains || [])) {
    console.log(`  ${ac.name || '?'} | Impact: ${ac.impact || '?'}`);
  }

  const score = llm?.__accuracyScore;
  if (score) {
    console.log(`\nAccuracy Score:`);
    console.log(`  F1: ${(score.f1Score * 100).toFixed(1)}%`);
    console.log(`  Precision: ${(score.precision * 100).toFixed(1)}%`);
    console.log(`  Recall: ${(score.recall * 100).toFixed(1)}%`);
    console.log(`  TP: ${score.truePositives} | FP: ${score.falsePositives} | FN: ${score.falseNegatives}`);

    const matched = (score.matchDetails || []).filter(d => d.matched);
    const missed = (score.matchDetails || []).filter(d => !d.matched);

    console.log(`\nMatched Ground Truth (${matched.length}):`);
    for (const m of matched) {
      console.log(`  ✅ ${m.groundTruth.title} (${m.groundTruth.severity})`);
    }

    console.log(`\nMissed Ground Truth (${missed.length}):`);
    for (const m of missed) {
      console.log(`  ❌ ${m.groundTruth.title} (${m.groundTruth.severity})`);
    }
  }
}

await conn.end();
