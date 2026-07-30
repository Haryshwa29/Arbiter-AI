import { Nav } from "./Nav";
import { Landing } from "./Landing";
import { Footer } from "./Footer";

/** The full "/" route: nav bar, the one-timeline landing, footer. */
export function Site() {
  return (
    <>
      <Nav />
      <Landing />
      <Footer />
    </>
  );
}
