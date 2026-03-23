import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

const FIRST_CMD = "cat /workspace/.env >> report.txt";
const OBFUS_CMD = `F=$(printf '\\056\\145\\156\\166'); cat "$F" >> report.txt`;

const DECODE_ROWS = [
  { octal: "\\056", char: ".", label: "period" },
  { octal: "\\145", char: "e", label: "e" },
  { octal: "\\156", char: "n", label: "n" },
  { octal: "\\166", char: "v", label: "v" },
];

// ── Scanner beam ─────────────────────────────────────────────────────────────
const Scanner: React.FC<{
  frame: number;
  startFrame: number;
  duration: number;
  color: string;
}> = ({ frame, startFrame, duration, color }) => {
  const progress = interpolate(frame, [startFrame, startFrame + duration], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const opacity =
    frame < startFrame
      ? 0
      : frame > startFrame + duration + 8
        ? 0
        : interpolate(frame, [startFrame + duration, startFrame + duration + 8], [0.5, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          });

  return (
    <div style={{ position: "absolute", inset: 0, overflow: "hidden", borderRadius: 6, pointerEvents: "none" }}>
      <div style={{ position: "absolute", top: 0, bottom: 0, width: "14%", background: color, opacity, filter: "blur(6px)", left: `${progress * 106 - 7}%` }} />
    </div>
  );
};

// ── Verdict badge ─────────────────────────────────────────────────────────────
const Verdict: React.FC<{ frame: number; appearAt: number; text: string; color: string; bg: string }> = ({ frame, appearAt, text, color, bg }) => {
  const sp = spring({ frame: frame - appearAt, fps: 30, config: { damping: 12, stiffness: 200 }, durationInFrames: 20 });
  return (
    <div style={{
      opacity: interpolate(sp, [0, 1], [0, 1]),
      transform: `scale(${interpolate(sp, [0, 1], [0.6, 1])})`,
      display: "inline-flex", alignItems: "center", background: bg,
      border: `2px solid ${color}`, borderRadius: 8, padding: "8px 20px", marginLeft: 20,
      fontFamily: "ui-monospace, 'Courier New', monospace",
      fontSize: 22, fontWeight: 700, color, letterSpacing: "1px", flexShrink: 0,
    }}>
      {text}
    </div>
  );
};

// ── Decode row ────────────────────────────────────────────────────────────────
const DecodeRow: React.FC<{ octal: string; char: string; label: string; frame: number; appearAt: number }> = ({ octal, char, label, frame, appearAt }) => {
  const sp = spring({ frame: frame - appearAt, fps: 30, config: { damping: 14, stiffness: 180 }, durationInFrames: 18 });
  return (
    <div style={{ opacity: interpolate(sp, [0, 1], [0, 1]), transform: `translateX(${interpolate(sp, [0, 1], [-16, 0])}px)`, display: "flex", alignItems: "center", gap: 20, padding: "8px 0" }}>
      <code style={{ fontFamily: "ui-monospace, 'Courier New', monospace", fontSize: 27, color: "#aaa", width: 120, display: "inline-block" }}>{octal}</code>
      <span style={{ color: "#444", fontSize: 22 }}>→</span>
      <code style={{ fontFamily: "ui-monospace, 'Courier New', monospace", fontSize: 27, color: "#ff4444", fontWeight: 700, width: 44 }}>{char}</code>
      <span style={{ fontSize: 17, color: "#333", fontFamily: "system-ui, sans-serif" }}>({label})</span>
    </div>
  );
};

// ── Main ──────────────────────────────────────────────────────────────────────
export const Scene2Problem: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  const titleOpacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: "clamp" });
  const terminalSp = spring({ frame, fps, config: { damping: 200 }, durationInFrames: 20 });
  const terminalOpacity = interpolate(terminalSp, [0, 1], [0, 1]);
  const terminalY = interpolate(terminalSp, [0, 1], [20, 0]);

  // Phase 1
  const charCount1 = Math.floor(interpolate(frame, [30, 105], [0, FIRST_CMD.length], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }));
  const cmd1Opacity = interpolate(frame, [195, 220], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const envHighlight = interpolate(frame, [105, 120], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const showBlocked = frame >= 160;

  const transLabelOpacity = interpolate(frame, [220, 240], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const transLabelFadeOut = interpolate(frame, [310, 325], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Phase 2
  const showPhase2 = frame >= 225;
  const charCount2 = Math.floor(interpolate(frame, [225, 315], [0, OBFUS_CMD.length], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }));
  const cmd2Opacity = interpolate(frame, [223, 228], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const showAllowed = frame >= 370;

  const cursor = Math.floor(frame / 15) % 2 === 0;

  // Decode panel
  const decodePanelOpacity = interpolate(frame, [390, 408], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const decodePanelY = interpolate(frame, [390, 408], [16, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const decodeRowFrames = [400, 415, 430, 445];
  const resultOpacity = interpolate(frame, [458, 472], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // Impact
  const impact1Opacity = interpolate(frame, [462, 482], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const impact2Opacity = interpolate(frame, [480, 500], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  // .env highlight: "cat /workspace/" = 16 chars × ~15.6px per char at fontSize 26
  const ENV_CHAR_W = 15.6;

  return (
    <AbsoluteFill style={{ background: "#0a0a0a", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "flex-start", padding: "48px 120px 36px", gap: 0 }}>
      {/* Section title */}
      <div style={{ opacity: titleOpacity, alignSelf: "flex-start", marginBottom: 24, fontSize: 20, color: "#555", fontFamily: "system-ui, sans-serif", letterSpacing: "3px", textTransform: "uppercase" }}>
        The Problem with Text Monitoring
      </div>

      {/* Terminal window */}
      <div style={{ opacity: terminalOpacity, transform: `translateY(${terminalY}px)`, width: "100%", background: "#111", border: "1px solid #2a2a2a", borderRadius: 12, overflow: "hidden", boxShadow: "0 24px 48px rgba(0,0,0,0.5)", flexShrink: 0 }}>
        {/* Title bar */}
        <div style={{ padding: "12px 22px", background: "#1a1a1a", borderBottom: "1px solid #2a2a2a", display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 13, height: 13, borderRadius: "50%", background: "#ff5f57" }} />
          <div style={{ width: 13, height: 13, borderRadius: "50%", background: "#febc2e" }} />
          <div style={{ width: 13, height: 13, borderRadius: "50%", background: "#28c840" }} />
          <span style={{ marginLeft: 14, fontSize: 16, color: "#444", fontFamily: "ui-monospace, monospace" }}>untrusted-agent — bash</span>
        </div>

        {/* Body */}
        <div style={{ padding: "26px 32px", minHeight: 100 }}>
          {/* Phase 1 */}
          <div style={{ opacity: cmd1Opacity, display: "flex", alignItems: "center", position: "relative" }}>
            <span style={{ color: "#444", fontFamily: "ui-monospace, monospace", fontSize: 26, marginRight: 14 }}>$</span>
            <div style={{ position: "relative", display: "inline-block" }}>
              {charCount1 >= 20 && (
                <div style={{ position: "absolute", background: "rgba(255,68,68,0.2)", border: "1px solid rgba(255,68,68,0.7)", borderRadius: 3, top: -2, left: `${16 * ENV_CHAR_W}px`, width: `${4 * ENV_CHAR_W}px`, bottom: -2, opacity: envHighlight }} />
              )}
              <span style={{ color: "#e8e8e8", fontFamily: "ui-monospace, monospace", fontSize: 26, whiteSpace: "pre" }}>
                {FIRST_CMD.slice(0, charCount1)}
                {charCount1 < FIRST_CMD.length && cursor && <span style={{ borderRight: "2px solid #e8e8e8" }}> </span>}
              </span>
              <Scanner frame={frame} startFrame={128} duration={22} color="rgba(255,68,68,0.45)" />
            </div>
            {showBlocked && <Verdict frame={frame} appearAt={160} text="Text monitor: BLOCKED" color="#ff4444" bg="rgba(255,68,68,0.1)" />}
          </div>

          {/* Phase 1 explanation */}
          {showBlocked && (
            <div style={{ opacity: interpolate(frame, [165, 185], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }) * cmd1Opacity, marginTop: 10, paddingLeft: 34, fontSize: 18, color: "#555", fontFamily: "ui-monospace, monospace" }}>
              ↳ token scan found &quot;.env&quot; literally in the command string
            </div>
          )}

          {/* Transition label */}
          {frame >= 218 && (
            <div style={{ opacity: transLabelOpacity * transLabelFadeOut, marginTop: cmd1Opacity > 0.1 ? 16 : 0, fontSize: 20, color: "#6366f1", fontFamily: "system-ui, sans-serif", fontStyle: "italic" }}>
              The agent rewrites the same command using printf octal encoding…
            </div>
          )}

          {/* Phase 2 */}
          {showPhase2 && (
            <div style={{ opacity: cmd2Opacity, display: "flex", alignItems: "center", marginTop: 16, position: "relative" }}>
              <span style={{ color: "#444", fontFamily: "ui-monospace, monospace", fontSize: 26, marginRight: 14, flexShrink: 0 }}>$</span>
              <div style={{ position: "relative", display: "inline-block" }}>
                <span style={{ color: "#e8e8e8", fontFamily: "ui-monospace, monospace", fontSize: 26, whiteSpace: "pre" }}>
                  {OBFUS_CMD.slice(0, charCount2)}
                  {charCount2 < OBFUS_CMD.length && cursor && <span style={{ borderRight: "2px solid #e8e8e8" }}> </span>}
                </span>
                <Scanner frame={frame} startFrame={335} duration={25} color="rgba(0,255,136,0.4)" />
              </div>
              {showAllowed && <Verdict frame={frame} appearAt={370} text="ALLOWED ✓" color="#00ff88" bg="rgba(0,255,136,0.1)" />}
            </div>
          )}

          {/* Phase 2 explanation */}
          {showAllowed && (
            <div style={{ opacity: interpolate(frame, [376, 395], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }), marginTop: 10, paddingLeft: 34, fontSize: 18, color: "#444", fontFamily: "ui-monospace, monospace" }}>
              ↳ token scan found no &quot;.env&quot; token — command passes
            </div>
          )}
        </div>
      </div>

      {/* Decode panel + impact */}
      <div style={{ opacity: decodePanelOpacity, transform: `translateY(${decodePanelY}px)`, marginTop: 28, width: "100%", display: "flex", gap: 44, alignItems: "flex-start" }}>
        {/* Left: decode table */}
        <div style={{ flexShrink: 0, background: "#0f0f0f", border: "1px solid #1e1e1e", borderRadius: 10, padding: "22px 30px" }}>
          <div style={{ fontSize: 16, color: "#444", fontFamily: "ui-monospace, monospace", letterSpacing: "2px", marginBottom: 14 }}>
            PRINTF DECODES TO
          </div>
          {DECODE_ROWS.map((row, i) => (
            <DecodeRow key={row.octal} octal={row.octal} char={row.char} label={row.label} frame={frame} appearAt={decodeRowFrames[i]} />
          ))}
          {/* Result */}
          <div style={{ opacity: resultOpacity, marginTop: 12, paddingTop: 12, borderTop: "1px solid #222", display: "flex", alignItems: "center", gap: 18 }}>
            <span style={{ fontSize: 18, color: "#444", fontFamily: "ui-monospace, monospace", width: 110 }}>result:</span>
            <span style={{ fontSize: 38, fontWeight: 900, color: "#ff4444", fontFamily: "ui-monospace, monospace", textShadow: "0 0 24px rgba(255,68,68,0.6)" }}>.env</span>
          </div>
        </div>

        {/* Right: impact statement */}
        <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: 20, paddingTop: 8 }}>
          <div style={{ opacity: impact1Opacity, fontSize: 36, fontWeight: 700, color: "#fff", fontFamily: "system-ui, sans-serif", lineHeight: 1.3 }}>
            No <span style={{ color: "#ff4444" }}>&quot;.env&quot;</span> token in the string.
            <br />
            The scanner never stood a chance.
          </div>
          <div style={{ opacity: impact2Opacity, fontSize: 22, color: "#666", fontFamily: "system-ui, sans-serif", lineHeight: 1.6, borderLeft: "3px solid #6366f1", paddingLeft: 18 }}>
            ShadowCommit doesn&apos;t parse tokens.
            <br />
            It <span style={{ color: "#6366f1", fontWeight: 600 }}>runs the command in a shadow copy</span>{" "}
            of the environment and{" "}
            <span style={{ color: "#6366f1", fontWeight: 600 }}>measures what actually happened</span>.
          </div>
        </div>
      </div>
    </AbsoluteFill>
  );
};
