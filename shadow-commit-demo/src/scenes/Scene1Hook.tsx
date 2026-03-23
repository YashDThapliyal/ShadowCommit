import {
  AbsoluteFill,
  interpolate,
  spring,
  useCurrentFrame,
  useVideoConfig,
} from "remotion";

export const Scene1Hook: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();

  // "AI agents lie." — bouncy spring entrance
  const line1Spring = spring({
    frame,
    fps,
    config: { damping: 14, stiffness: 120 },
    durationInFrames: 45,
  });
  const line1Y = interpolate(line1Spring, [0, 1], [60, 0]);
  const line1Opacity = interpolate(line1Spring, [0, 1], [0, 1]);

  // "ShadowCommit catches them." — smooth fade after pause
  const line2Spring = spring({
    frame: frame - 55,
    fps,
    config: { damping: 200 },
    durationInFrames: 35,
  });
  const line2Y = interpolate(line2Spring, [0, 1], [30, 0]);
  const line2Opacity = interpolate(line2Spring, [0, 1], [0, 1]);

  // Subtle green glow pulse on line 2
  const glowPulse = 0.5 + 0.5 * Math.sin(frame * 0.08);
  const line2Glow = interpolate(frame, [90, 120], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  // Horizontal rule between lines fades in
  const ruleOpacity = interpolate(frame, [50, 70], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });

  return (
    <AbsoluteFill
      style={{
        background: "#0a0a0a",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 0,
      }}
    >
      {/* Line 1 */}
      <div
        style={{
          opacity: line1Opacity,
          transform: `translateY(${line1Y}px)`,
          fontSize: 128,
          fontWeight: 900,
          color: "#ffffff",
          fontFamily:
            "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
          letterSpacing: "-3px",
          lineHeight: 1,
        }}
      >
        AI agents lie.
      </div>

      {/* Divider */}
      <div
        style={{
          opacity: ruleOpacity,
          width: 80,
          height: 3,
          background: "#00ff88",
          borderRadius: 2,
          margin: "32px 0",
          boxShadow: `0 0 ${12 * glowPulse}px rgba(0,255,136,0.8)`,
        }}
      />

      {/* Line 2 */}
      <div
        style={{
          opacity: line2Opacity,
          transform: `translateY(${line2Y}px)`,
          fontSize: 80,
          fontWeight: 700,
          color: "#00ff88",
          fontFamily:
            "system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
          letterSpacing: "-1px",
          textShadow: `0 0 ${30 * glowPulse * line2Glow}px rgba(0,255,136,0.6)`,
        }}
      >
        ShadowCommit catches them.
      </div>
    </AbsoluteFill>
  );
};
