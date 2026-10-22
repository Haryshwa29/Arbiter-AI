import { useEffect, useRef } from "react";
import { DemoReplay } from "../views/DemoReplay";
import { ArbiterMark } from "./ArbiterMark";

export default function DemoDrawer({onClose}: {onClose: () => void}) {
  const close = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement;
    const overflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    close.current?.focus();
    return () => {document.body.style.overflow = overflow;previous?.focus();};
  }, []);
  return <div className="public-demo-backdrop" onMouseDown={e => {if(e.target === e.currentTarget) onClose();}}>
    <section className="public-demo premium-dashboard" data-theme="dark" role="dialog" aria-modal="true" aria-label="Try Arbiter demo" onKeyDown={e => {
      if((e.target as HTMLElement).closest('[role="dialog"]') !== e.currentTarget) return;
      if(e.key === "Escape") {e.stopPropagation();onClose();}
      if(e.key === "Tab") {
        const nodes = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a, input, select, summary, [tabindex="0"]')).filter(node => node.getClientRects().length);
        const first=nodes[0],last=nodes[nodes.length-1];
        if(e.shiftKey && document.activeElement === first){e.preventDefault();last?.focus();}
        else if(!e.shiftKey && document.activeElement === last){e.preventDefault();first?.focus();}
      }
    }}>
      <header className="public-demo-header"><div><span className="product-eyebrow"><ArbiterMark />TRY ARBITER / LIVE AI DEMO</span><p>Live demo: security rules, scoped context and cloud AI when needed. No device actions.</p></div><button ref={close} onClick={onClose}>Close demo ×</button></header>
      <div className="premium-main"><DemoReplay publicDemo /></div>
    </section>
  </div>;
}
