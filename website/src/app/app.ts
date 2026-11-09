import { ChangeDetectionStrategy, Component } from '@angular/core';
import { SiteNav } from './sections/site-nav';
import { Hero } from './sections/hero';
import { ProtocolStrip } from './sections/protocol-strip';
import { DemoSection } from './sections/demo-section';
import { SiteFooter } from './sections/site-footer';

@Component({
  selector: 'app-root',
  imports: [SiteNav, Hero, ProtocolStrip, DemoSection, SiteFooter],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="backdrop" aria-hidden="true">
      <div class="blob b1"></div>
      <div class="blob b2"></div>
      <div class="blob b3"></div>
      <div class="grid"></div>
      <div class="grain"></div>
    </div>

    <app-site-nav />
    <main>
      <app-hero />
      <app-protocol-strip />
      <app-demo-section />
    </main>
    <app-site-footer />
  `,
  styles: `
    :host { position: relative; display: block; isolation: isolate; }

    /* Fundo: brilhos "aurora" a mexer devagar, grelha subtil e grão, como o Mica da app */
    .backdrop { position: fixed; inset: 0; z-index: -1; overflow: hidden; pointer-events: none; background: var(--bg); }
    .blob { position: absolute; border-radius: 50%; filter: blur(90px); opacity: .55; will-change: transform; }
    .b1 {
      width: 60vmax; height: 60vmax; top: -30vmax; right: -14vmax;
      background: radial-gradient(circle, rgba(124,108,255,.55), transparent 65%);
      animation: drift1 26s ease-in-out infinite alternate;
    }
    .b2 {
      width: 50vmax; height: 50vmax; top: 30vh; left: -26vmax;
      background: radial-gradient(circle, rgba(76,141,255,.4), transparent 65%);
      animation: drift2 32s ease-in-out infinite alternate;
    }
    .b3 {
      width: 40vmax; height: 40vmax; bottom: -22vmax; right: 10vw;
      background: radial-gradient(circle, rgba(167,139,250,.3), transparent 65%);
      animation: drift1 38s ease-in-out infinite alternate-reverse;
    }
    @keyframes drift1 { to { transform: translate(-8vw, 10vh) scale(1.1); } }
    @keyframes drift2 { to { transform: translate(10vw, -8vh) scale(1.15); } }
    .grid {
      position: absolute; inset: 0;
      background-image:
        linear-gradient(rgba(255,255,255,.035) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.035) 1px, transparent 1px);
      background-size: 64px 64px;
      mask: radial-gradient(ellipse 80% 60% at 50% 0%, #000 20%, transparent 75%);
      -webkit-mask: radial-gradient(ellipse 80% 60% at 50% 0%, #000 20%, transparent 75%);
    }
    .grain {
      position: absolute; inset: -50%; opacity: .07; mix-blend-mode: overlay;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='160' height='160'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
    }
  `,
})
export class App {}
