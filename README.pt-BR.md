<p align="center">
  <img src=".github/eidolon.png" alt="Logo do Eidolon" width="220">
</p>

# EIDOLON

Um cliente HTTP para Go fiel ao navegador e atento ao fingerprint.

Não basta parecer. É preciso se comportar como.

[English](README.md)

O Eidolon envia requests HTTP do jeito que um navegador de verdade envia. Ele
copia mais que o fingerprint: o ClientHello do TLS, os settings, frames e
prioridades do HTTP/2, e a ordem e a grafia dos headers. Também se comporta
como o navegador: como usa as conexões, repete requests, segue redirects,
retoma sessões TLS, negocia o Encrypted Client Hello e passa por proxies. Cada
comportamento é conferido contra o código-fonte do navegador e contra
capturas do tráfego dele.

Foi feito para crawlers, que em geral rodam atrás de proxy.

## Instalação

```sh
go get github.com/acomerlatto/eidolon-tls
```

Requer Go 1.27.2 ou mais recente. A pilha TLS é um fork do uTLS,
[`github.com/acomerlatto/utls`](https://github.com/acomerlatto/utls),
exigido como módulo: não é preciso diretiva `replace`.

## Uso

```go
c, err := eidolon.New(eidolon.WithProfile(eidolon.Chrome156Linux()))
if err != nil {
	log.Fatal(err)
}
defer c.Close()

resp, err := c.Get("https://example.com/")
if err != nil {
	log.Fatal(err)
}
defer resp.Body.Close()
```

A API usa os tipos padrão do `net/http`. O `c.Transport()` é um
`http.RoundTripper` para código que monta o próprio `http.Client`.

Os [exemplos](example_test.go) mostram HTTP/2, um perfil customizado feito a
partir de um ClientHello capturado e de um fingerprint Akamai, ECH nos modos
automático e obrigatório, e um proxy.

## O que ele reproduz

- **Perfil:** Chrome 156 no Linux, embutido. Outros navegadores e versões se
  fazem com `Profile`, `ClientHelloFromRaw` e `ParseAkamai`.
- **TLS:** TLS 1.3 e 1.2, um ClientHello novo a cada conexão com o
  embaralhamento de extensões e o GREASE do Chrome, e o cache de sessões TLS
  do Chrome.
- **ECH:** nos modos automático (o padrão do Chrome), obrigatório ou
  desligado, com a configuração vinda dos registros DNS HTTPS (o resolver do
  sistema no Linux, ou DNS sobre HTTPS) ou definida à mão. O ClientHelloInner
  é montado como o BoringSSL monta.
- **HTTP/2:** SETTINGS, WINDOW_UPDATE, prioridades, HPACK, enquadramento de
  headers, tratamento de erros, ALPS e PING como o Chrome.
- **HTTP/1.1:** ordem e grafia dos headers, pool de conexões e limites.
- **Headers:** os headers do perfil por destino do request
  (`WithFetchDest`), `Sec-Fetch-*` e `Origin` como o padrão Fetch define, e
  um modo exato que envia só os campos dados, na ordem deles.
- **Proxies:** HTTP (CONNECT), HTTPS, SOCKS4/4a e SOCKS5/5h, com uma conexão
  por request como opção para proxies rotativos.
- **Redirects e cookies:** redirects seguidos como o padrão Fetch e o Chrome
  seguem, e um cookie jar opcional com a public suffix list.

## Limites

O que o Eidolon não faz, e onde ele difere do Chrome, está em
[LIMITS.pt-BR.md](LIMITS.pt-BR.md). Os pontos principais: sem HTTP/3, sem
verificação de revogação, certificados verificados contra as raízes do Go, e
verificado só no Linux x86_64.

## Upstreams

O motor HTTP/2 é uma cópia do `golang.org/x/net/http2` com patches locais, e
a pilha TLS é um fork do uTLS. O [UPSTREAM.md](UPSTREAM.md) lista os dois e
descreve como as correções de segurança deles chegam ao Eidolon.

## Licença

MIT, ver [LICENSE](LICENSE). O código copiado do `golang.org/x/net`, em
`internal/`, mantém a licença BSD-3-Clause.
