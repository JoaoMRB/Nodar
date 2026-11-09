import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';

/** Faixa contínua com os protocolos e fontes de dados que o Nodar usa. */
@Component({
  selector: 'app-protocol-strip',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <p class="title">{{ i18n.t().strip.title }}</p>
    <div class="marquee" aria-hidden="true">
      @for (copy of [0, 1]; track copy) {
        <ul>
          @for (p of items; track p) {
            <li>{{ p }}</li>
          }
        </ul>
      }
    </div>
    <p class="sr-only">{{ items.join(', ') }}</p>
  `,
  styles: `
    :host { display: block; padding: 24px 0 8px; }
    .title {
      margin-bottom: 18px; color: var(--text-3); font-size: 12px; font-weight: 600;
      letter-spacing: .14em; text-align: center; text-transform: uppercase;
    }
    .marquee {
      display: flex; overflow: hidden;
      mask: linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent);
      -webkit-mask: linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent);
    }
    ul {
      display: flex; flex: none; gap: 12px; margin: 0; padding: 0 6px; list-style: none;
      animation: scroll 38s linear infinite;
    }
    li {
      padding: 9px 18px; border: 1px solid var(--stroke); border-radius: 999px; background: var(--surface);
      color: var(--text-2); font-family: var(--mono); font-size: 13px; white-space: nowrap;
    }
    @keyframes scroll { to { transform: translateX(-100%); } }
  `,
})
export class ProtocolStrip {
  protected readonly i18n = inject(I18n);
  protected readonly items = [
    'ARP', 'mDNS / Bonjour', 'SSDP / UPnP', 'NetBIOS', 'Reverse DNS', 'IEEE OUI', 'TCP banners',
    'TLS / X.509', 'NVD (NIST)', 'CISA KEV', 'CVSS 3.1', 'UPnP IGD', 'Shodan InternetDB', 'TCP/IP fingerprint',
  ];
}
