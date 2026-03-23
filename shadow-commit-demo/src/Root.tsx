import "./index.css";
import { Composition } from "remotion";
import { MyComposition } from "./Composition";

// 165 + 510 + 615 + 600 + 300 − 4×15 = 2130 frames = 71 s at 30 fps
const TOTAL_FRAMES = 2130;

export const RemotionRoot: React.FC = () => (
  <Composition
    id="ShadowCommitDemo"
    component={MyComposition}
    durationInFrames={TOTAL_FRAMES}
    fps={30}
    width={1920}
    height={1080}
  />
);
