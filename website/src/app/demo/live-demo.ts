import {
  ChangeDetectionStrategy,
  Component,
  DestroyRef,
  ElementRef,
  afterNextRender,
  computed,
  inject,
  signal,
} from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import {
  DEVICES,
  FILTERS,
  INTERNET_PORTS,
  KIND_COLORS,
  SEVERITY_COLORS,
  UPNP_PORTS,
  type Device,
  type FilterId,
  type Trust,
} from './demo-data';

type View = 'devices' | 'security' | 'history' | 'watched';

interface Toast {
  id: number;
  icon: 'sparkle' | 'star' | 'check' | 'alert';
  tone: 'accent' | 'success' | 'danger' | 'warning';
  title: string;
  text: string;
}

/**
 * Réplica da janela do Nodar em modo demonstração. Tudo corre no browser com dados fictícios:
 * nada é analisado de verdade e nada sai daqui.
 */
@Component({
  selector: 'app-live-demo',
  imports: [Icon],
  templateUrl: './live-demo.html',
  styleUrl: './live-demo.scss',
  changeDetection: ChangeDetectionStrategy.OnPush,
})
export class LiveDemo {
  protected readonly i18n = inject(I18n);
  protected readonly t = this.i18n.t;
  protected readonly lang = this.i18n.lang;
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly destroyRef = inject(DestroyRef);

  protected readonly devices = DEVICES;
  protected readonly upnpPorts = UPNP_PORTS;
  protected readonly internetPorts = INTERNET_PORTS;
  protected readonly severityColors = SEVERITY_COLORS;

  protected readonly view = signal<View>('devices');
  protected readonly query = signal('');
  protected readonly filter = signal<FilterId>('all');
  protected readonly selectedId = signal<string | null>(null);
  protected readonly trust = signal<Record<string, Trust>>(
    Object.fromEntries(DEVICES.map((d) => [d.id, d.trust])),
  );
  protected readonly watched = signal<ReadonlySet<string>>(new Set());
  protected readonly toasts = signal<Toast[]>([]);
  protected readonly copied = signal(false);

  // Scan simulado
  protected readonly scanning = signal(false);
  protected readonly progress = signal(0);
  protected readonly step = signal(0);
  protected readonly revealed = signal(0);
  protected readonly hasScanned = signal(false);

  private timers: ReturnType<typeof setTimeout>[] = [];
  private toastSeq = 0;

  protected readonly visible = computed(() => this.devices.slice(0, this.revealed()));

  private readonly matching = computed(() => {
    const q = this.query().trim().toLowerCase();
    const lang = this.lang();
    if (!q) return this.visible();
    return this.visible().filter((d) =>
      [d.name[lang], d.ip, d.mac, d.vendor, d.hostname, d.model[lang], d.note?.[lang] ?? '']
        .join(' ')
        .toLowerCase()
        .includes(q),
    );
  });

  protected readonly filters = computed(() => {
    const trust = this.trust();
    const base = this.matching();
    return FILTERS.map((f) => ({ ...f, count: base.filter((d) => f.test(d, trust[d.id])).length })).filter(
      (f) => f.id === 'all' || f.count > 0,
    );
  });

  protected readonly list = computed(() => {
    const f = FILTERS.find((x) => x.id === this.filter())!;
    const trust = this.trust();
    return this.matching().filter((d) => f.test(d, trust[d.id]));
  });

  protected readonly selected = computed(() => this.devices.find((d) => d.id === this.selectedId()) ?? null);

  protected readonly stats = computed(() => {
    const v = this.visible();
    return {
      online: v.length,
      fresh: v.filter((d) => d.id === 'phone').length,
      services: v.reduce((n, d) => n + d.services.length, 0),
      vulns: v.reduce((n, d) => n + d.cveCount, 0),
      kev: v.reduce((n, d) => n + d.kevCount, 0),
    };
  });

  protected readonly toReview = computed(() => {
    const trust = this.trust();
    return this.visible().filter((d) => trust[d.id] === 'review').length;
  });

  protected readonly watchedDevices = computed(() => this.devices.filter((d) => this.watched().has(d.id)));

  constructor() {
    this.destroyRef.onDestroy(() => this.timers.forEach(clearTimeout));

    // A primeira análise começa sozinha quando a demo aparece no ecrã.
    afterNextRender(() => {
      if (!('IntersectionObserver' in window)) {
        this.scan();
        return;
      }
      const io = new IntersectionObserver(
        (entries) => {
          if (entries.some((e) => e.isIntersecting)) {
            io.disconnect();
            this.later(() => this.scan(), 350);
          }
        },
        { threshold: 0.35 },
      );
      io.observe(this.host.nativeElement);
      this.destroyRef.onDestroy(() => io.disconnect());
    });
  }

  // ---------- Ações ----------

  protected scan(): void {
    if (this.scanning()) return;
    const first = !this.hasScanned();
    this.scanning.set(true);
    this.view.set('devices');
    this.selectedId.set(null);
    this.revealed.set(0);
    this.progress.set(0);
    this.step.set(0);

    const total = 2600;
    const ticks = 26;
    for (let i = 1; i <= ticks; i++) {
      this.later(() => {
        const p = i / ticks;
        this.progress.set(Math.round(p * 100));
        this.step.set(Math.min(3, Math.floor(p * 4)));
        this.revealed.set(Math.min(this.devices.length, Math.ceil(p * 1.6 * this.devices.length)));
      }, (total / ticks) * i);
    }
    this.later(() => {
      this.scanning.set(false);
      this.hasScanned.set(true);
      if (first) {
        const phone = this.devices.find((d) => d.id === 'phone')!;
        this.toast({
          icon: 'sparkle',
          tone: 'accent',
          title: this.t().app.toastNew,
          text: `${phone.name[this.lang()]} · ${phone.ip}`,
        });
      }
    }, total + 150);
  }

  protected select(d: Device): void {
    this.selectedId.set(this.selectedId() === d.id ? null : d.id);
    this.copied.set(false);
  }

  protected toggleWatch(d: Device, ev?: Event): void {
    ev?.stopPropagation();
    const next = new Set(this.watched());
    if (next.has(d.id)) {
      next.delete(d.id);
    } else {
      next.add(d.id);
      this.toast({
        icon: 'star',
        tone: 'warning',
        title: this.t().app.watching,
        text: this.i18n.format(this.t().app.toastWatch, d.name[this.lang()]),
      });
    }
    this.watched.set(next);
  }

  protected setTrust(d: Device, value: Trust): void {
    const current = this.trust()[d.id];
    const next: Trust = current === value ? 'review' : value;
    this.trust.update((t) => ({ ...t, [d.id]: next }));
    if (next === 'known') {
      this.toast({ icon: 'check', tone: 'success', title: this.t().app.mine, text: this.i18n.format(this.t().app.toastMine, d.name[this.lang()]) });
    } else if (next === 'suspicious') {
      this.toast({
        icon: 'alert',
        tone: 'danger',
        title: this.t().app.notMine,
        text: this.i18n.format(this.t().app.toastSuspicious, d.name[this.lang()]),
      });
    }
  }

  protected async copyIp(d: Device): Promise<void> {
    try {
      await navigator.clipboard.writeText(d.ip);
    } catch {
      /* sem permissão: mostra na mesma o estado */
    }
    this.copied.set(true);
    this.later(() => this.copied.set(false), 1600);
  }

  protected go(view: View): void {
    this.view.set(view);
    this.selectedId.set(null);
  }

  protected onSearch(ev: Event): void {
    this.query.set((ev.target as HTMLInputElement).value);
  }

  protected dismiss(id: number): void {
    this.toasts.update((list) => list.filter((x) => x.id !== id));
  }

  // ---------- Apresentação ----------

  protected colors(d: Device): [string, string] {
    return KIND_COLORS[d.isThisPc ? 'thisPc' : d.kind];
  }

  protected deviceById(id: string): Device {
    return this.devices.find((d) => d.id === id)!;
  }

  protected portsLabel(n: number): string {
    return `${n} ${n === 1 ? this.t().app.port : this.t().app.ports}`;
  }

  protected cveLabel(d: Device): string {
    const app = this.t().app;
    if (!d.kevCount) return `${d.cveCount} CVE`;
    return `${d.cveCount} CVE · ${d.kevCount} ${d.kevCount === 1 ? app.exploited : app.exploitedPl}`;
  }

  protected hasDistro(d: Device): boolean {
    return d.services.some((s) => !!s.distro);
  }

  protected nvdUrl(id: string): string {
    return `https://nvd.nist.gov/vuln/detail/${id}`;
  }

  private toast(t: Omit<Toast, 'id'>): void {
    const id = ++this.toastSeq;
    this.toasts.update((list) => [...list.slice(-2), { ...t, id }]);
    this.later(() => this.dismiss(id), 4200);
  }

  private later(fn: () => void, ms: number): void {
    this.timers.push(setTimeout(fn, ms));
  }
}
