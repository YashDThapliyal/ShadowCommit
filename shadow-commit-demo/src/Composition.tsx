import { AbsoluteFill } from "remotion";
import { TransitionSeries, linearTiming } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { Scene1Hook } from "./scenes/Scene1Hook";
import { Scene2Problem } from "./scenes/Scene2Problem";
import { Scene3Pipeline } from "./scenes/Scene3Pipeline";
import { Scene4Matrix } from "./scenes/Scene4Matrix";
import { Scene5Stats } from "./scenes/Scene5Stats";

// ── Frame math (30 fps, target ~71 s) ─────────────────────────────────────────
// 4 transitions × 15 frames each = 60 frames overlap
// Scene totals = 165 + 510 + 615 + 600 + 300 = 2190
// Total composition = 2190 − 60 = 2130 frames = 71 s
const S1 = 165;
const S2 = 510;
const S3 = 615;
const S4 = 600;
const S5 = 300;
const T = 15; // transition duration in frames

const FADE = fade();
const TIMING = linearTiming({ durationInFrames: T });

export const ShadowCommitDemo: React.FC = () => (
  <AbsoluteFill>
    <TransitionSeries>
      <TransitionSeries.Sequence durationInFrames={S1}>
        <Scene1Hook />
      </TransitionSeries.Sequence>

      <TransitionSeries.Transition presentation={FADE} timing={TIMING} />

      <TransitionSeries.Sequence durationInFrames={S2}>
        <Scene2Problem />
      </TransitionSeries.Sequence>

      <TransitionSeries.Transition presentation={FADE} timing={TIMING} />

      <TransitionSeries.Sequence durationInFrames={S3}>
        <Scene3Pipeline />
      </TransitionSeries.Sequence>

      <TransitionSeries.Transition presentation={FADE} timing={TIMING} />

      <TransitionSeries.Sequence durationInFrames={S4}>
        <Scene4Matrix />
      </TransitionSeries.Sequence>

      <TransitionSeries.Transition presentation={FADE} timing={TIMING} />

      <TransitionSeries.Sequence durationInFrames={S5}>
        <Scene5Stats />
      </TransitionSeries.Sequence>
    </TransitionSeries>
  </AbsoluteFill>
);

// Re-export under the name Root.tsx expects
export { ShadowCommitDemo as MyComposition };
