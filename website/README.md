# Site do Nodar

Site de apresentação do Nodar, com uma **demo interativa** da app que corre no browser. Dá para ver como funciona antes de instalar.

Feito em **Angular 22** (componentes standalone, signals, zoneless) e SCSS, sem bibliotecas de UI. Gera um site estático.

## Correr

```bash
cd website
npm install
npm start          # http://localhost:4200
npm run build      # dist/nodar-site/browser
```

`npm start` e `npm run build` correm primeiro [`scripts/sync-assets.mjs`](scripts/sync-assets.mjs). O script copia para `public/` o logo (`src/Nodar.App/Assets`) e os screenshots (`docs/screenshots`), por isso o site mostra sempre as mesmas imagens que o README. As cópias não vão para o git.

## Estrutura

```
src/
├── styles.scss              # Tokens (os mesmos de src/Nodar.App/Styles/Theme.axaml), vidro, botões
├── app/
│   ├── app.ts               # Página e fundo "aurora"
│   ├── i18n/                # pt.ts, en.ts (mesmas chaves, verificado pelo TypeScript) e o serviço de idioma
│   ├── shared/              # Ícones (os mesmos paths da app), reveal ao fazer scroll, links
│   ├── demo/                # A demo: réplica da janela com a rede fictícia do modo demonstração
│   └── sections/            # Hero, funcionalidades, como funciona, privacidade, capturas, instalar, FAQ
```

## Demo

A demo usa a mesma rede fictícia de `Nodar.exe --demo` ([DemoData.cs](../src/Nodar.App/Services/DemoData.cs)). Os dispositivos, IPs e MACs são inventados. Os CVEs mostrados são reais para as versões dos serviços (NVD e CISA KEV). Nada é analisado de verdade e nada sai do browser.

## Publicar

O workflow [`.github/workflows/website.yml`](../.github/workflows/website.yml) publica o site no GitHub Pages sempre que há alterações em `website/`, nos screenshots ou no logo. Só é preciso ativar uma vez: **Settings → Pages → Source: GitHub Actions**.
