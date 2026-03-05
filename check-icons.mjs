import * as lucide from 'lucide-react';

const icons = ['Play','Square','Shield','ShieldAlert','ShieldCheck','ShieldX','Target','Crosshair','Radar','Bug','Skull','Radio','Globe','Server','Database','MonitorSmartphone','AlertTriangle','CheckCircle2','XCircle','Clock','Loader2','ChevronRight','Eye','FileText','Zap','Lock','Unlock','Activity','Terminal','Network','Wifi','Plus','Search','ArrowRight','Swords','RotateCcw','CircleDollarSign','Coins','Sparkles','ClipboardList','Key','KeyRound','Cloud','CloudOff','Brain','GitBranch','Layers','RefreshCw','Gauge','ExternalLink','ChevronDown','ChevronUp','Wrench','Timer'];

const missing = icons.filter(i => !lucide[i]);
console.log('Missing icons:', missing.length > 0 ? missing.join(', ') : 'NONE');
console.log('Total checked:', icons.length, '| Missing:', missing.length);
