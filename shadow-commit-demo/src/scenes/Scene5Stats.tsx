import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

const STATS = [
  { value: "455",   label: "tests written",      color: "#6366f1", appearAt: 10 },
  { value: "96%",   label: "code coverage",       color: "#00ff88", appearAt: 30 },
  { value: "5 / 5", label: "attack types caught", color: "#00ff88", appearAt: 50 },
] as const;

const GITHUB_URL = "github.com/YashDThapliyal/ShadowCommit";

// ── Stat Card ─────────────────────────────────────────────────────────────────
const StatCard: React.FC<{ value: string; label: string; color: string; appearAt: number; frame: number; fps: number }> = ({ value, label, color, appearAt, frame, fps }) => {
  const sp = spring({ frame: frame - appearAt, fps, config: { damping: 14, stiffness: 140 }, durationInFrames: 35 });
  const glowAge = Math.max(0, frame - appearAt);
  const glow = interpolate(glowAge, [0, 20, 50], [0, 1, 0.3], { extrapolateRight: "clamp" });

  return (
    <div style={{
      opacity: interpolate(sp, [0, 1], [0, 1]),
      transform: `translateY(${interpolate(sp, [0, 1], [60, 0])}px)`,
      background: "#111", border: `1.5px solid ${color}40`, borderRadius: 18,
      padding: "40px 56px", textAlign: "center",
      boxShadow: `0 0 ${24 * glow}px ${color}30, 0 24px 48px rgba(0,0,0,0.4)`,
      minWidth: 280,
    }}>
      <div style={{ fontSize: 88, fontWeight: 900, color, fontFamily: "system-ui, -apple-system, sans-serif", letterSpacing: "-2px", lineHeight: 1, textShadow: `0 0 ${20 * glow}px ${color}80` }}>
        {value}
      </div>
      <div style={{ marginTop: 12, fontSize: 20, color: "#666", fontFamily: "ui-monospace, 'Courier New', monospace", letterSpacing: "1px" }}>
        {label}
      </div>
    </div>
  );
};

// ── Main Scene ────────────────────────────────────────────────────────────────
export const Scene5Stats: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const taglineOpacity = interpolate(frame, [100, 130], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const taglineY = interpolate(frame, [100, 130], [20, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const fadeToBlack = interpolate(frame, [210, 250], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const urlOpacity = interpolate(frame, [255, 275], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const urlScale = spring({ frame: frame - 255, fps, config: { damping: 200 }, durationInFrames: 20 });

  return (
    <AbsoluteFill style={{ background: "#0a0a0a", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 80px" }}>
      {/* Stat cards */}
      <div style={{ display: "flex", gap: 36, marginBottom: 64 }}>
        {STATS.map((s) => <StatCard key={s.value} value={s.value} label={s.label} color={s.color} appearAt={s.appearAt} frame={frame} fps={fps} />)}
      </div>

      {/* Tagline */}
      <div style={{ opacity: taglineOpacity, transform: `translateY(${taglineY}px)`, textAlign: "center" }}>
        <div style={{ fontSize: 44, fontWeight: 700, color: "#fff", fontFamily: "system-ui, -apple-system, sans-serif", lineHeight: 1.35, maxWidth: 900 }}>
          Because <span style={{ color: "#ff4444" }}>&lsquo;trust me&rsquo;</span> is not a security model.
        </div>
        <div style={{ marginTop: 16, fontSize: 24, color: "#555", fontFamily: "ui-monospace, monospace", letterSpacing: "0.5px" }}>
          Stop trusting what agents say. Start measuring what they do.
        </div>
      </div>

      {/* Fade to black */}
      <div style={{ position: "absolute", inset: 0, background: "#000", opacity: fadeToBlack, pointerEvents: "none" }} />

      {/* GitHub URL */}
      <div style={{ position: "absolute", display: "flex", flexDirection: "column", alignItems: "center", gap: 18, opacity: urlOpacity, transform: `scale(${interpolate(urlScale, [0, 1], [0.95, 1])})` }}>
        <div style={{ width: 48, height: 3, background: "#00ff88", borderRadius: 2 }} />
        <div style={{ fontSize: 36, color: "#00ff88", fontFamily: "ui-monospace, 'Courier New', monospace", letterSpacing: "1px" }}>{GITHUB_URL}</div>
        <div style={{ fontSize: 18, color: "#444", fontFamily: "ui-monospace, monospace", letterSpacing: "2px", textTransform: "uppercase" }}>Open Source · MIT License</div>
      </div>
    </AbsoluteFill>
  );
};
