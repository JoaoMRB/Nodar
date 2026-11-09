import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';

/**
 * Ícones de traço 24×24, os mesmos da app (src/Nodar.App/Styles/Icons.axaml).
 * Pontos ("h.01") ficam redondos graças ao stroke-linecap="round".
 */
export const ICONS = {
  radar: 'M12 12 L18.4 5.6 M12 3 A9 9 0 1 0 21 12 M12 7.5 A4.5 4.5 0 1 0 16.5 12 M12 12 h.01',
  grid: 'M4 4 h6 v6 h-6 z M14 4 h6 v6 h-6 z M4 14 h6 v6 h-6 z M14 14 h6 v6 h-6 z',
  shield: 'M12 3 L19.5 6 V11.5 C19.5 16 16.3 19.6 12 21 C7.7 19.6 4.5 16 4.5 11.5 V6 Z',
  shieldCheck: 'M12 3 L19.5 6 V11.5 C19.5 16 16.3 19.6 12 21 C7.7 19.6 4.5 16 4.5 11.5 V6 Z M9 12 l2 2 l4 -4.5',
  clock: 'M3 12 A9 9 0 1 0 21 12 A9 9 0 1 0 3 12 M12 7 V12 L15 14',
  eye: 'M2.5 12 C5 7 8.5 5 12 5 C15.5 5 19 7 21.5 12 C19 17 15.5 19 12 19 C8.5 19 5 17 2.5 12 Z M9 12 A3 3 0 1 0 15 12 A3 3 0 1 0 9 12',
  search: 'M4 11 A7 7 0 1 0 18 11 A7 7 0 1 0 4 11 M20 20 L16 16',
  sliders: 'M4 7 H13 M17 7 H20 M15 5 V9 M4 17 H7 M11 17 H20 M9 15 V19 M4 12 H20',
  close: 'M6 6 L18 18 M18 6 L6 18',
  star: 'M12 3.5 L14.6 8.8 L20.4 9.6 L16.2 13.7 L17.2 19.5 L12 16.8 L6.8 19.5 L7.8 13.7 L3.6 9.6 L9.4 8.8 Z',
  download: 'M12 4 V15 M7 10.5 L12 15.5 L17 10.5 M5 20 H19',
  fileText: 'M14 3 H7 A2 2 0 0 0 5 5 V19 A2 2 0 0 0 7 21 H17 A2 2 0 0 0 19 19 V8 Z M14 3 V8 H19 M9 13 H15 M9 17 H13',
  copy: 'M9 9 H19 V19 H9 Z M5 15 V5 H15',
  external: 'M14 4 H20 V10 M20 4 L11 13 M18 14 V19 A1 1 0 0 1 17 20 H5 A1 1 0 0 1 4 19 V7 A1 1 0 0 1 5 6 H10',
  refresh: 'M20 12 A8 8 0 1 1 17.7 6.3 M20 4 V9 H15',
  flame: 'M12 3 C12.8 6.5 17 8.5 17 13.5 A5 5 0 0 1 7 13.5 C7 10.8 8.6 9.6 9.2 7.6 C10.6 8.6 11 10.2 11 11.5 C12.2 9.7 12.4 6.5 12 3 Z',
  alert: 'M12 4 L21 19.5 H3 Z M12 10 V14 M12 17 h.01',
  check: 'M5 12.5 L10 17 L19 7',
  info: 'M3 12 A9 9 0 1 0 21 12 A9 9 0 1 0 3 12 M12 11 V16 M12 8 h.01',
  plug: 'M9 3 V7 M15 3 V7 M7 7 H17 V11 A5 5 0 0 1 7 11 Z M12 16 V21',
  globe: 'M3 12 A9 9 0 1 0 21 12 A9 9 0 1 0 3 12 M3 12 H21 M12 3 C15 6 15 18 12 21 C9 18 9 6 12 3',
  sparkle: 'M12 3 L13.8 10.2 L21 12 L13.8 13.8 L12 21 L10.2 13.8 L3 12 L10.2 10.2 Z',
  arrowIn: 'M13 5 H18 A1 1 0 0 1 19 6 V18 A1 1 0 0 1 18 19 H13 M4 12 H14 M10 8 L14 12 L10 16',
  arrowOut: 'M11 5 H6 A1 1 0 0 0 5 6 V18 A1 1 0 0 0 6 19 H11 M10 12 H20 M16 8 L20 12 L16 16',
  router: 'M3 14 H21 V20 H3 Z M7 17 h.01 M11 17 h.01 M8.5 10.5 A5 5 0 0 1 15.5 10.5 M5.8 7.8 A9 9 0 0 1 18.2 7.8',
  computer: 'M3 5 H21 V16 H3 Z M8 20 H16 M12 16 V20',
  laptop: 'M5 5 H19 V15 H5 Z M2.5 19 H21.5',
  phone: 'M8 2.5 H16 A2 2 0 0 1 18 4.5 V19.5 A2 2 0 0 1 16 21.5 H8 A2 2 0 0 1 6 19.5 V4.5 A2 2 0 0 1 8 2.5 Z M11 18 H13',
  tv: 'M3 7 H21 V18 H3 Z M8 21 H16 M8 3 L12 7 L16 3',
  printer: 'M7 9 V3.5 H17 V9 M7 17 H5 A2 2 0 0 1 3 15 V11 A2 2 0 0 1 5 9 H19 A2 2 0 0 1 21 11 V15 A2 2 0 0 1 19 17 H17 M7 14 H17 V20.5 H7 Z',
  server: 'M4 4 H20 V10 H4 Z M4 14 H20 V20 H4 Z M8 7 h.01 M8 17 h.01',
  home: 'M3.5 11 L12 4 L20.5 11 M6 9.5 V20 H18 V9.5 M10 20 V14 H14 V20',
  gamepad: 'M6 8 H18 A4 4 0 0 1 22 12 V13 A4 4 0 0 1 15 16 L14 15 H10 L9 16 A4 4 0 0 1 2 13 V12 A4 4 0 0 1 6 8 Z M7 11 V14 M5.5 12.5 H8.5 M16 12 h.01 M18 13.5 h.01',
  camera: 'M3 8 A2 2 0 0 1 5 6 H7 L9 3.5 H15 L17 6 H19 A2 2 0 0 1 21 8 V18 A2 2 0 0 1 19 20 H5 A2 2 0 0 1 3 18 Z M8.5 12.5 A3.5 3.5 0 1 0 15.5 12.5 A3.5 3.5 0 1 0 8.5 12.5',
  cube: 'M12 3 L20 7.5 V16.5 L12 21 L4 16.5 V7.5 Z M4 7.5 L12 12 L20 7.5 M12 12 V21',
  chip: 'M7 7 H17 V17 H7 Z M10 10 H14 V14 H10 Z M9.5 3 V7 M14.5 3 V7 M9.5 17 V21 M14.5 17 V21 M3 9.5 H7 M3 14.5 H7 M17 9.5 H21 M17 14.5 H21',
  // Extras do site (mesmo estilo de traço)
  lock: 'M6 11 H18 V20 H6 Z M8.5 11 V8 A3.5 3.5 0 0 1 15.5 8 V11 M12 14.5 V16.5',
  bell: 'M6 16 V11 A6 6 0 0 1 18 11 V16 L19.5 18 H4.5 Z M10 21 H14',
  github:
    'M9 19 C4.7 20.4 4.7 16.5 3 16 M15 21 V17.5 C15 16.5 15.1 16.1 14.5 15.5 C17.3 15.2 20 14.1 20 9.5 A4.6 4.6 0 0 0 18.8 6.3 A4.3 4.3 0 0 0 18.7 3.2 S17.6 2.9 15.1 4.6 A12.3 12.3 0 0 0 8.9 4.6 C6.4 2.9 5.3 3.2 5.3 3.2 A4.3 4.3 0 0 0 5.2 6.3 A4.6 4.6 0 0 0 4 9.5 C4 14.1 6.7 15.2 9.5 15.5 C8.9 16.1 8.9 16.7 9 17.5 V21',
  windows: 'M4 5.5 L11 4.5 V11.5 H4 Z M13 4.2 L20 3 V11.5 H13 Z M4 12.5 H11 V19.5 L4 18.5 Z M13 12.5 H20 V21 L13 19.8 Z',
  terminal: 'M3 5 H21 V19 H3 Z M7 10 L10 12.5 L7 15 M12.5 15 H16.5',
  layers: 'M12 3 L21 8 L12 13 L3 8 Z M3 12.5 L12 17.5 L21 12.5 M3 16.5 L12 21.5 L21 16.5',
  wifi: 'M2.5 9 A14 14 0 0 1 21.5 9 M5.5 12.5 A9.5 9.5 0 0 1 18.5 12.5 M8.5 16 A5 5 0 0 1 15.5 16 M12 19.5 h.01',
  chevron: 'M9 6 L15 12 L9 18',
  plus: 'M12 5 V19 M5 12 H19',
  menu: 'M4 7 H20 M4 12 H20 M4 17 H20',
  userCheck: 'M4 20 C4 16.5 6.5 14.5 10 14.5 C11.5 14.5 12.7 14.8 13.6 15.4 M6.5 8 A3.5 3.5 0 1 0 13.5 8 A3.5 3.5 0 1 0 6.5 8 M15 18 L17 20 L21 16',
  userX: 'M4 20 C4 16.5 6.5 14.5 10 14.5 C11.5 14.5 12.7 14.8 13.6 15.4 M6.5 8 A3.5 3.5 0 1 0 13.5 8 A3.5 3.5 0 1 0 6.5 8 M16 15.5 L21 20.5 M21 15.5 L16 20.5',
} as const;

export type IconName = keyof typeof ICONS;

@Component({
  selector: 'app-icon',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" [attr.stroke-width]="stroke()"
         stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path [attr.d]="d()" />
    </svg>
  `,
  styles: `
    :host { display: inline-flex; width: 1em; height: 1em; flex: none; }
    svg { width: 100%; height: 100%; overflow: visible; }
  `,
})
export class Icon {
  readonly name = input.required<IconName>();
  readonly stroke = input(1.7);
  protected readonly d = computed(() => ICONS[this.name()]);
}
