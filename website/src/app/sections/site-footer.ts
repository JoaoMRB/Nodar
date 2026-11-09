import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { Reveal } from '../shared/reveal';
import { ISSUES, LATEST_EXE, LICENSE, README, REPO } from '../shared/links';

@Component({
  selector: 'app-site-footer',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let tx = i18n.t();
    <section class="cta container" appReveal>
      <div class="cta-card">
        <div class="cta-glow" aria-hidden="true"></div>
        <img src="img/nodar-256.png" alt="" width="88" height="88" />
        <h2>{{ tx.cta.title }}</h2>
        <p>{{ tx.cta.text }}</p>
        <div class="ctas">
          <a class="btn btn-primary" [href]="download" target="_blank" rel="noopener">
            <app-icon name="windows" />{{ tx.hero.ctaDownload }}
          </a>
          <a class="btn btn-ghost" [href]="repo" target="_blank" rel="noopener">
            <app-icon name="github" />{{ tx.nav.github }}
          </a>
        </div>
      </div>
    </section>

    <footer class="container">
      <div class="row">
        <div class="brand">
          <img src="img/nodar-64.png" alt="" width="24" height="24" />
          <div>
            <strong>Nodar</strong>
            <span>{{ tx.footer.tagline }}</span>
          </div>
        </div>
        <nav class="links">
          <a [href]="readme(i18n.lang())" target="_blank" rel="noopener">{{ tx.footer.readme }}</a>
          <a [href]="issues" target="_blank" rel="noopener">{{ tx.footer.issues }}</a>
          <a [href]="license" target="_blank" rel="noopener">{{ tx.footer.license }}</a>
          <a [href]="repo" target="_blank" rel="noopener">GitHub</a>
        </nav>
      </div>
      <div class="fine">
        <span>© 2026 Malog · {{ tx.footer.made }}</span>
        <span>{{ tx.footer.disclaimer }}</span>
      </div>
    </footer>
  `,
  styles: `
    :host { display: block; padding-top: clamp(40px, 6vw, 80px); }
    .cta-card {
      position: relative; isolation: isolate; overflow: hidden; display: flex; flex-direction: column; align-items: center;
      padding: clamp(48px, 8vw, 88px) 24px; border: 1px solid var(--stroke-strong); border-radius: 32px;
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.015));
      text-align: center; backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
    }
    .cta-glow {
      position: absolute; inset: -40% -10% auto; height: 120%; z-index: -1;
      background: radial-gradient(50% 50% at 50% 50%, rgba(124,108,255,.45), rgba(76,141,255,.15) 50%, transparent 70%);
      filter: blur(40px); animation: breathe 8s ease-in-out infinite;
    }
    @keyframes breathe { 50% { transform: scale(1.12); opacity: .75; } }
    img { width: 88px; height: 88px; filter: drop-shadow(0 16px 40px rgba(124,108,255,.55)); }
    h2 { margin-top: 26px; font-size: clamp(30px, 5vw, 52px); font-weight: 800; }
    p { max-width: 520px; margin-top: 14px; color: var(--text-2); font-size: 17px; }
    .ctas { display: flex; flex-wrap: wrap; justify-content: center; gap: 12px; margin-top: 32px; }
    footer { padding-block: 64px 40px; }
    .row { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 20px; }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand img { width: 24px; height: 24px; filter: none; }
    .brand strong { display: block; font-size: 15px; }
    .brand span { color: var(--text-3); font-size: 13px; }
    .links { display: flex; flex-wrap: wrap; gap: 6px 22px; }
    .links a { color: var(--text-2); font-size: 14px; transition: color .2s; }
    .links a:hover { color: var(--text); }
    .fine {
      display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px 24px; margin-top: 28px;
      padding-top: 24px; border-top: 1px solid var(--stroke); color: var(--text-3); font-size: 12.5px;
    }
    @media (max-width: 560px) {
      .ctas { width: 100%; flex-direction: column; }
      .ctas .btn { width: 100%; }
    }
  `,
})
export class SiteFooter {
  protected readonly i18n = inject(I18n);
  protected readonly repo = REPO;
  protected readonly download = LATEST_EXE;
  protected readonly issues = ISSUES;
  protected readonly license = LICENSE;
  protected readonly readme = README;
}
