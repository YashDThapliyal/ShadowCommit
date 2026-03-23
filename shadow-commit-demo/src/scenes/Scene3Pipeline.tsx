import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

const STAGES = [
  { id: "agent",      title: "Agent",           sub: "proposes command",     detail: "untrusted — could be malicious",          appearAt: 40  },
  { id: "commitment", title: "Commitment",       sub: "signs a promise",      detail: '"I will only touch src/*.py"',            appearAt: 125 },
  { id: "shadow",     title: "Shadow\nExecutor", sub: "isolated clone",       detail: "shutil.copytree → real env never touched", appearAt: 215 },
  { id: "diff",       title: "Diff\nExtractor",  sub: "before vs. after",     detail: "files changed, secrets read, network used",appearAt: 310 },
  { id: "rule",       title: "Rule\nChecker",    sub: "promise vs. reality",  detail: "4 deterministic rules, frozen result",     appearAt: 400 },
] as const;

const OUTCOMES = [
  { id: "allow", text: "✓  ALLOW", color: "#00ff88", bg: "rgba(0,255,136,0.12)", border: "rgba(0,255,136,0.5)", appearAt: 490 },
  { id: "block", text: "✗  BLOCK", color: "#ff4444", bg: "rgba(255,68,68,0.12)",  border: "rgba(255,68,68,0.5)",  appearAt: 510 },
] as const;

// ── Stage Box ─────────────────────────────────────────────────────────────────
const StageBox: React.FC<{ title: string; sub: string; detail: string; appearAt: number; frame: number; fps: number }> = ({ title, sub, detail, appearAt, frame, fps }) => {
  const sp = spring({ frame: frame - appearAt, fps, config: { damping: 10, stiffness: 140 }, durationInFrames: 30 });
  const glowAge = Math.max(0, frame - appearAt);
  const glow = interpolate(glowAge, [0, 18, 50], [0, 1, 0.3], { extrapolateRight: "clamp" });
  const detailOpacity = interpolate(frame, [appearAt + 20, appearAt + 40], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <div style={{
      opacity: interpolate(sp, [0, 1], [0, 1]),
      transform: `scale(${interpolate(sp, [0, 1], [0.5, 1])})`,
      background: "rgba(18,18,28,0.95)",
      border: `1.5px solid rgba(99,102,241,${0.35 + glow * 0.65})`,
      borderRadius: 14, padding: "20px 22px",
      minWidth: 178, maxWidth: 178, textAlign: "center",
      boxShadow: `0 0 ${22 * glow}px rgba(99,102,241,0.45)`, flexShrink: 0,
    }}>
      <div style={{ fontSize: 20, fontWeight: 700, color: "#e8e8e8", fontFamily: "system-ui, sans-serif", lineHeight: 1.25, whiteSpace: "pre" }}>{title}</div>
      <div style={{ marginTop: 6, fontSize: 14, color: "#6366f1", fontFamily: "ui-monospace, monospace", letterSpacing: "0.3px" }}>{sub}</div>
      <div style={{ opacity: detailOpacity, marginTop: 7, fontSize: 12, color: "#3a3a4a", fontFamily: "ui-monospace, monospace", lineHeight: 1.3 }}>{detail}</div>
    </div>
  );
};

// ── Arrow ─────────────────────────────────────────────────────────────────────
const Arrow: React.FC<{ opacity: number }> = ({ opacity }) => (
  <div style={{ display: "flex", alignItems: "center", width: 52, flexShrink: 0, opacity }}>
    <div style={{ flex: 1, height: 2, background: "rgba(99,102,241,0.6)" }} />
    <div style={{ width: 0, height: 0, borderTop: "6px solid transparent", borderBottom: "6px solid transparent", borderLeft: "11px solid rgba(99,102,241,0.6)" }} />
  </div>
);

// ── Outcome Box ───────────────────────────────────────────────────────────────
const OutcomeBox: React.FC<{ text: string; color: string; bg: string; border: string; appearAt: number; frame: number; fps: number }> = ({ text, color, bg, border, appearAt, frame, fps }) => {
  const sp = spring({ frame: frame - appearAt, fps, config: { damping: 12, stiffness: 200 }, durationInFrames: 20 });
  const glowAge = Math.max(0, frame - appearAt);
  const glow = interpolate(glowAge, [0, 14, 40], [0, 1, 0.4], { extrapolateRight: "clamp" });
  return (
    <div style={{
      opacity: interpolate(sp, [0, 1], [0, 1]),
      transform: `scale(${interpolate(sp, [0, 1], [0.7, 1])})`,
      background: bg, border: `2px solid ${border}`, borderRadius: 10,
      padding: "15px 28px",
      fontFamily: "ui-monospace, monospace", fontSize: 22, fontWeight: 700, color,
      letterSpacing: "1.5px", textAlign: "center",
      boxShadow: `0 0 ${22 * glow}px ${color}40`, minWidth: 175,
    }}>
      {text}
    </div>
  );
};

// ── Shadow execution callout ──────────────────────────────────────────────────
const ShadowCallout: React.FC<{ frame: number }> = ({ frame }) => {
  const APPEAR_AT = 240;
  const opacity = interpolate(frame, [APPEAR_AT, APPEAR_AT + 25], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const y = interpolate(frame, [APPEAR_AT, APPEAR_AT + 25], [12, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  const steps = [
    { icon: "①", text: "shutil.copytree → shadow workspace", delay: 0 },
    { icon: "②", text: "command runs against the clone", delay: 18 },
    { icon: "③", text: "filesystem fingerprint: before vs after", delay: 36 },
    { icon: "④", text: "shadow discarded — real env untouched", delay: 54 },
  ];

  return (
    <div style={{ opacity, transform: `translateY(${y}px)`, background: "rgba(8,8,20,0.95)", border: "1px solid rgba(99,102,241,0.25)", borderLeft: "3px solid #6366f1", borderRadius: 10, padding: "18px 24px", maxWidth: 480 }}>
      <div style={{ fontSize: 14, color: "#6366f1", fontFamily: "ui-monospace, monospace", letterSpacing: "2px", marginBottom: 14 }}>HOW SHADOW EXECUTION WORKS</div>
      {steps.map((s) => (
        <div key={s.icon} style={{ opacity: interpolate(frame, [APPEAR_AT + s.delay, APPEAR_AT + s.delay + 16], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }), display: "flex", alignItems: "flex-start", gap: 12, marginBottom: 10 }}>
          <span style={{ color: "#6366f1", fontFamily: "ui-monospace, monospace", fontSize: 16, flexShrink: 0 }}>{s.icon}</span>
          <span style={{ color: "#888", fontFamily: "ui-monospace, monospace", fontSize: 16, lineHeight: 1.4 }}>{s.text}</span>
        </div>
      ))}
    </div>
  );
};

// ── Rules callout ─────────────────────────────────────────────────────────────
const RulesCallout: React.FC<{ frame: number }> = ({ frame }) => {
  const APPEAR_AT = 420;
  const opacity = interpolate(frame, [APPEAR_AT, APPEAR_AT + 25], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const y = interpolate(frame, [APPEAR_AT, APPEAR_AT + 25], [12, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  const rules = ["UNDECLARED_SENSITIVE_PATH", "UNDECLARED_FILE_MODIFICATIONS", "WRITES_OUTSIDE_SRC", "UNDECLARED_NETWORK"];

  return (
    <div style={{ opacity, transform: `translateY(${y}px)`, background: "rgba(8,8,20,0.95)", border: "1px solid rgba(99,102,241,0.25)", borderLeft: "3px solid #6366f1", borderRadius: 10, padding: "18px 24px", maxWidth: 420 }}>
      <div style={{ fontSize: 14, color: "#6366f1", fontFamily: "ui-monospace, monospace", letterSpacing: "2px", marginBottom: 14 }}>4 DETERMINISTIC RULES</div>
      {rules.map((r, i) => (
        <div key={r} style={{ opacity: interpolate(frame, [APPEAR_AT + i * 12, APPEAR_AT + i * 12 + 14], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }), fontFamily: "ui-monospace, monospace", fontSize: 15, color: "#ff4444", marginBottom: 8, letterSpacing: "0.5px" }}>
          ▸ {r}
        </div>
      ))}
    </div>
  );
};

// ── Main Scene ────────────────────────────────────────────────────────────────
export const Scene3Pipeline: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 25], [0, 1], { extrapolateRight: "clamp" });
  const titleY = interpolate(frame, [0, 25], [20, 0], { extrapolateRight: "clamp" });

  const arrowOpacities = STAGES.slice(1).map((s) =>
    interpolate(frame, [s.appearAt, s.appearAt + 20], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" })
  );
  const forkArrowOpacity = interpolate(frame, [OUTCOMES[0].appearAt - 20, OUTCOMES[0].appearAt], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const footerOpacity = interpolate(frame, [555, 580], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{ background: "#0a0a0a", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "0 60px" }}>
      {/* Title */}
      <div style={{ opacity: titleOpacity, transform: `translateY(${titleY}px)`, marginBottom: 52, textAlign: "center" }}>
        <div style={{ fontSize: 52, fontWeight: 800, color: "#fff", fontFamily: "system-ui, sans-serif", letterSpacing: "-1px" }}>How ShadowCommit Works</div>
        <div style={{ marginTop: 10, fontSize: 20, color: "#444", fontFamily: "ui-monospace, monospace", letterSpacing: "1.5px" }}>every command passes through 5 stages before reaching the real environment</div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 36, width: "100%" }}>
        {/* Pipeline row */}
        <div style={{ display: "flex", alignItems: "center" }}>
          {STAGES.map((stage, i) => (
            <div key={stage.id} style={{ display: "flex", alignItems: "center" }}>
              <StageBox title={stage.title} sub={stage.sub} detail={stage.detail} appearAt={stage.appearAt} frame={frame} fps={fps} />
              {i < STAGES.length - 1 && <Arrow opacity={arrowOpacities[i]} />}
            </div>
          ))}
          <Arrow opacity={forkArrowOpacity} />
          <div style={{ display: "flex", flexDirection: "column", gap: 14, borderLeft: `2px solid rgba(99,102,241,${forkArrowOpacity * 0.35})`, paddingLeft: 14 }}>
            {OUTCOMES.map((o) => (
              <OutcomeBox key={o.id} text={o.text} color={o.color} bg={o.bg} border={o.border} appearAt={o.appearAt} frame={frame} fps={fps} />
            ))}
          </div>
        </div>

        {/* Callouts */}
        <div style={{ display: "flex", gap: 32, alignItems: "flex-start", justifyContent: "center", width: "100%" }}>
          {frame >= 235 && <ShadowCallout frame={frame} />}
          {frame >= 415 && <RulesCallout frame={frame} />}
        </div>
      </div>

      {/* Footer */}
      <div style={{ opacity: footerOpacity, marginTop: 36, fontSize: 18, color: "#333", fontFamily: "ui-monospace, monospace", textAlign: "center", letterSpacing: "1px" }}>
        no token parsing · no regex · execution evidence only
      </div>
    </AbsoluteFill>
  );
};
