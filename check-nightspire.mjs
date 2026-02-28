import mysql from 'mysql2/promise';

const conn = await mysql.createConnection(process.env.DATABASE_URL);
const [rows] = await conn.execute(
  "SELECT actorId, name, tools, malware, techniques, calderaProfile FROM threat_actors WHERE name LIKE '%Nightspire%' LIMIT 1"
);
if (rows.length > 0) {
  const row = rows[0];
  console.log("actorId:", row.actorId);
  console.log("name:", row.name);
  console.log("tools type:", typeof row.tools, Array.isArray(row.tools));
  console.log("tools:", JSON.stringify(row.tools, null, 2)?.substring(0, 1000));
  console.log("malware type:", typeof row.malware, Array.isArray(row.malware));
  console.log("malware:", JSON.stringify(row.malware, null, 2)?.substring(0, 500));
  console.log("techniques type:", typeof row.techniques, Array.isArray(row.techniques));
  console.log("calderaProfile type:", typeof row.calderaProfile);
  if (row.calderaProfile) {
    console.log("calderaProfile:", JSON.stringify(row.calderaProfile, null, 2)?.substring(0, 1000));
  }
} else {
  console.log("No nightspire actor found");
}
await conn.end();
