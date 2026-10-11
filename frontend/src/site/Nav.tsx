import { ArbiterMark } from "./ArbiterMark";
export function Nav({onDemo}: {onDemo: () => void}) {
  return <header className="product-nav product-wrap"><a className="product-brand" href="#top" aria-label="Arbiter AI home"><span className="product-mark"><ArbiterMark /></span><span className="brand-name">Arbiter <span className="brand-ai">AI</span></span></a><nav aria-label="Main navigation"><a href="#how-it-works">How it works</a><a href="#brain">The brain</a><button className="demo-trigger" onClick={onDemo}>Try demo</button><a className="product-button compact" href="#install">Get Arbiter ↗</a></nav></header>;
}
