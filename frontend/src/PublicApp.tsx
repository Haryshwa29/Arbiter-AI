import { Site } from "./site/Site";

// The public build contains the product website only; no dashboard or auth.
export default function PublicApp() {
  return <Site />;
}
