import { useMemo } from "react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

interface TrendDataPoint {
  id: number;
  date: string;
  type: string;
  totalVulns: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  ports: number;
  exploits: number;
  assets: number;
  newFound: number;
  resolved: number;
}

interface VulnTrendChartProps {
  data: TrendDataPoint[];
}

export function VulnTrendChart({ data }: VulnTrendChartProps) {
  const chartData = useMemo(() => {
    return data.map((d) => ({
      date: new Date(d.date).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      }),
      Critical: d.critical,
      High: d.high,
      Medium: d.medium,
      Low: d.low,
      Total: d.totalVulns,
      Exploits: d.exploits,
    }));
  }, [data]);

  if (chartData.length === 0) return null;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={chartData} margin={{ top: 5, right: 10, left: -10, bottom: 5 }}>
        <defs>
          <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="gradLow" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
        <XAxis
          dataKey="date"
          tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }}
          tickLine={false}
          axisLine={false}
        />
        <YAxis
          tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "hsl(var(--card))",
            border: "1px solid hsl(var(--border))",
            borderRadius: "8px",
            fontSize: "11px",
            color: "hsl(var(--foreground))",
          }}
          labelStyle={{ color: "hsl(var(--muted-foreground))", fontSize: "10px" }}
        />
        <Legend
          wrapperStyle={{ fontSize: "10px", paddingTop: "8px" }}
          iconType="circle"
          iconSize={8}
        />
        <Area
          type="monotone"
          dataKey="Critical"
          stackId="1"
          stroke="#ef4444"
          fill="url(#gradCritical)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="High"
          stackId="1"
          stroke="#f97316"
          fill="url(#gradHigh)"
          strokeWidth={2}
        />
        <Area
          type="monotone"
          dataKey="Medium"
          stackId="1"
          stroke="#eab308"
          fill="url(#gradMedium)"
          strokeWidth={1.5}
        />
        <Area
          type="monotone"
          dataKey="Low"
          stackId="1"
          stroke="#3b82f6"
          fill="url(#gradLow)"
          strokeWidth={1.5}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
