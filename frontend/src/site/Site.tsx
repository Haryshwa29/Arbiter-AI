import { Nav } from "./Nav";
import { Landing } from "./Landing";
import { Footer } from "./Footer";
import "./product.css";
import { lazy, Suspense, useEffect, useRef, useState } from "react";
const DemoDrawer = lazy(() => import("./DemoDrawer"));
export function Site() {
  const [demo, setDemo] = useState(false);
  const site = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const root = site.current;
    if (!root) return;
    const motion = matchMedia("(prefers-reduced-motion: reduce)");
    let frame = 0;
    const update = () => {
      frame = 0;
      root.style.setProperty("--ambient-shift", motion.matches ? "0px" : `${Math.min(scrollY * .04, 180)}px`);
    };
    const scroll = () => {if (!frame) frame = requestAnimationFrame(update);};
    const observer = new IntersectionObserver(entries => {
      for (const entry of entries) if (entry.isIntersecting) {
        entry.target.classList.add("section-arrived");
        observer.unobserve(entry.target);
      }
    }, {threshold: .08});
    root.querySelectorAll("#main-content > section").forEach(section => observer.observe(section));
    window.addEventListener("scroll", scroll, {passive: true});
    motion.addEventListener("change", update);
    update();
    return () => {observer.disconnect();window.removeEventListener("scroll", scroll);motion.removeEventListener("change", update);cancelAnimationFrame(frame);};
  }, []);
  return <div ref={site} className="product-site" id="top"><div className="site-ambience" aria-hidden="true" /><div inert={demo}><a className="product-skip" href="#main-content">Skip to content</a><Nav onDemo={() => setDemo(true)} /><Landing /><Footer /></div>{demo && <Suspense fallback={<div className="public-demo-backdrop"><section className="public-demo"><button onClick={() => setDemo(false)}>Close demo</button><p role="status">Opening demo…</p></section></div>}><DemoDrawer onClose={() => setDemo(false)} /></Suspense>}</div>;
}
