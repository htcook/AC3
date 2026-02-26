import fs from 'fs';
const lines = fs.readFileSync('server/lib/passive/index.ts','utf8');
const match = lines.match(/ALL_CONNECTORS.*?\[([^]*?)\]/);
const connectors = match[1].split(',').filter(l => l.trim() && !l.trim().startsWith('//'));
console.log('Total connectors:', connectors.length);
connectors.forEach((c,i) => console.log(i+1, c.trim().split(/\s/)[0]));
