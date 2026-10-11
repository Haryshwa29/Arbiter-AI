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
    <section className="public-demo" data-theme="dark" role="dialog" aria-modal="true" aria-label="Try Arbiter demo" onKeyDown={e => {
      if((e.target as HTMLElement).closest('[role="dialog"]') !== e.currentTarget) return;
      if(e.key === "Escape") {e.stopPropagation();onClose();}
      if(e.key === "Tab") {
        const nodes = Array.from(e.currentTarget.querySelectorAll<HTMLElement>('button:not(:disabled), a, input, select, summary, [tabindex="0"]')).filter(node => node.getClientRects().length);
        const first=nodes[0],last=nodes[nodes.length-1];
        if(e.shiftKey && document.activeElement === first){e.preventDefault();last?.focus();}
        else if(!e.shiftKey && document.activeElement === last){e.preventDefault();first?.focus();}
      }
    }}>
      <header className="public-demo-header"><div><span className="product-eyebrow"><ArbiterMark />TRY ARBITER / ISOLATED SIMULATION</span><p>Your files. The same decision pipeline. Simulated responses.</p></div><button ref={close} onClick={onClose}>Close demo ×</button></header>
      <p className="public-demo-notice">No login needed. This website demo uses deterministic test reasoning, not a connected AI model. Uploads are processed in a temporary session on the demo server; use sample or sanitized data. Idle sessions expire after 30 minutes. Closing this panel keeps your session available until expiry.</p>
      <DemoReplay publicDemo />
    </section>
  </div>;
}
