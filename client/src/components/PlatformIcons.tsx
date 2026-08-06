/**
 * Platform-specific icons for Bug Bounty Hub.
 * Each icon is a distinctive inline SVG that matches the platform's brand identity.
 */

interface IconProps {
  className?: string;
  size?: number;
}

/** HackerOne — stylized "H1" mark */
export function HackerOneIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M4 4v16" />
      <path d="M4 12h6" />
      <path d="M10 4v16" />
      <path d="M16 8v12" />
      <path d="M14 8h4" />
    </svg>
  );
}

/** Bugcrowd — stylized bug/shield */
export function BugcrowdIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2C7 2 3 6 3 11v2c0 5 4 9 9 9s9-4 9-9v-2c0-5-4-9-9-9z" />
      <path d="M8 8l2 2" />
      <path d="M16 8l-2 2" />
      <circle cx="9" cy="13" r="1.5" fill="currentColor" />
      <circle cx="15" cy="13" r="1.5" fill="currentColor" />
      <path d="M9 17c1.5 1 4.5 1 6 0" />
    </svg>
  );
}

/** Intigriti — stylized "i" with security shield */
export function IntigritiIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 3L4 7v5c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-4z" />
      <circle cx="12" cy="9" r="1" fill="currentColor" />
      <path d="M12 12v5" />
    </svg>
  );
}

/** Synack — angular hawk/falcon mark */
export function SynackIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2L3 9l3 3 6-4 6 4 3-3-9-7z" />
      <path d="M6 12l6 10 6-10" />
      <path d="M12 12v4" />
    </svg>
  );
}

/** YesWeHack — stylized "YWH" monogram */
export function YesWeHackIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M3 4l4 8-4 8" />
      <path d="M21 4l-4 8 4 8" />
      <path d="M9 4l3 6 3-6" />
      <path d="M12 10v10" />
    </svg>
  );
}

/** Open Bug Bounty — open lock with bug */
export function OpenBugBountyIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 018 0" />
      <circle cx="12" cy="16" r="1.5" fill="currentColor" />
      <path d="M12 17.5V19" />
    </svg>
  );
}

/** Immunefi — blockchain shield */
export function ImmunefiIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2L3 7v5c0 5.25 3.4 10.15 8 11.25 4.6-1.1 8-6 8-11.25V7l-8-4z" />
      <path d="M12 8l3 2v4l-3 2-3-2v-4l3-2z" />
    </svg>
  );
}

/** Burp Suite — stylized flame/scanner mark */
export function BurpSuiteIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2C8 6 6 10 6 13a6 6 0 0 0 12 0c0-3-2-7-6-11z" />
      <path d="M12 22c-2 0-3-1-3-3 0-2 1.5-4 3-6 1.5 2 3 4 3 6 0 2-1 3-3 3z" />
    </svg>
  );
}

export function CustomPlatformIcon({ className = "", size = 20 }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  );
}

/** Platform color map — brand colors for each platform */
export const PLATFORM_COLORS: Record<string, string> = {
  hackerone: "text-emerald-400",
  bugcrowd: "text-orange-400",
  intigriti: "text-blue-400",
  synack: "text-blue-500",
  yeswehack: "text-red-400",
  open_bug_bounty: "text-yellow-400",
  immunefi: "text-purple-400",
  burpsuite_pro: "text-orange-500",
  burpsuite_enterprise: "text-orange-600",
  custom: "text-zinc-400",
  manual: "text-zinc-400",
};

/** Platform background color map — for cards and badges */
export const PLATFORM_BG_COLORS: Record<string, string> = {
  hackerone: "bg-emerald-500/10 border-emerald-500/20",
  bugcrowd: "bg-orange-500/10 border-orange-500/20",
  intigriti: "bg-blue-500/10 border-blue-500/20",
  synack: "bg-blue-600/10 border-blue-600/20",
  yeswehack: "bg-red-500/10 border-red-500/20",
  open_bug_bounty: "bg-yellow-500/10 border-yellow-500/20",
  immunefi: "bg-purple-500/10 border-purple-500/20",
  burpsuite_pro: "bg-orange-500/10 border-orange-500/20",
  burpsuite_enterprise: "bg-orange-600/10 border-orange-600/20",
  custom: "bg-zinc-500/10 border-zinc-500/20",
  manual: "bg-zinc-500/10 border-zinc-500/20",
};

/** Get the icon component for a platform */
export function PlatformIcon({
  platform,
  className = "",
  size = 20,
}: {
  platform: string;
  className?: string;
  size?: number;
}) {
  const colorClass = PLATFORM_COLORS[platform] || "text-zinc-400";
  const combinedClass = `${colorClass} ${className}`.trim();

  switch (platform) {
    case "hackerone":
      return <HackerOneIcon className={combinedClass} size={size} />;
    case "bugcrowd":
      return <BugcrowdIcon className={combinedClass} size={size} />;
    case "intigriti":
      return <IntigritiIcon className={combinedClass} size={size} />;
    case "synack":
      return <SynackIcon className={combinedClass} size={size} />;
    case "yeswehack":
      return <YesWeHackIcon className={combinedClass} size={size} />;
    case "open_bug_bounty":
      return <OpenBugBountyIcon className={combinedClass} size={size} />;
    case "immunefi":
      return <ImmunefiIcon className={combinedClass} size={size} />;
    case "burpsuite_pro":
    case "burpsuite_enterprise":
      return <BurpSuiteIcon className={combinedClass} size={size} />;
    case "custom":
    case "manual":
      return <CustomPlatformIcon className={combinedClass} size={size} />;
    default:
      return <CustomPlatformIcon className={combinedClass} size={size} />;
  }
}

/** Platform display names */
export const PLATFORM_NAMES: Record<string, string> = {
  hackerone: "HackerOne",
  bugcrowd: "Bugcrowd",
  intigriti: "Intigriti",
  synack: "Synack",
  yeswehack: "YesWeHack",
  open_bug_bounty: "Open Bug Bounty",
  immunefi: "Immunefi",
  burpsuite_pro: "Burp Suite Pro",
  burpsuite_enterprise: "Burp Suite Enterprise",
  custom: "Custom",
  manual: "Manual",
};
