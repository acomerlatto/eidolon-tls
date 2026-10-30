# Limites

[English](LIMITS.md)

O que o Eidolon não faz, e onde ele difere de propósito do navegador que
reproduz. Cada item foi conferido contra o Chrome 156 (o código-fonte e
capturas do tráfego dele); o comportamento descrito aqui é o dessa versão.

## Protocolos

- TLS 1.3 e 1.2; HTTP/2 e HTTP/1.1, sobre TLS e em `http://`.
- **Sem HTTP/3 nem QUIC.** O Chrome passa para h3 depois de um `Alt-Svc` ou
  de um registro HTTPS; o Eidolon fica em h2 ou HTTP/1.1. O
  `WithDisableHTTP3` ainda não muda nada.
- Sem suporte: TLS 0-RTT, WebSocket e outros upgrades, pipelining HTTP/1.1,
  upload em streaming, trailers.
- Sem coalescing de conexões: cada origem tem as suas, enquanto o Chrome
  pode compartilhar uma conexão HTTP/2 entre origens com o mesmo IP e
  certificado.
- Sem preconnect: uma biblioteca não tem preditor.

## Perfis

- Um perfil embutido: Chrome 156 no Linux (`Chrome156Linux`). Outras versões
  e navegadores se fazem com `Profile` e `ClientHelloFromRaw`; só o embutido
  foi medido contra o navegador.
- Diferenças conhecidas do `Chrome156Linux` em relação ao Chrome 156:
  - o favicon sai com a prioridade de imagem (`u=2, i`); o Chrome mandou
    `u=1, i`;
  - a posição de alguns headers na ordem de uma navegação não foi capturada
    (`content-length`, `cache-control`, `origin`, `content-type`); headers
    de quem chama que o perfil não ordena vão no fim, em ordem alfabética;
  - `http://localhost` é tratado como inseguro; o Chrome o considera
    potencialmente confiável e envia `Sec-Fetch-*` e client hints;
  - uma navegação sem iniciador não envia `Origin`, nem num POST;
  - o `sec-fetch-storage-access` não é modelado, e o frame ACCEPT_CH do
    ALPS não alimenta client hints.
- O HTTP/2 segue o enquadramento, as prioridades, o controle de fluxo e o
  tratamento de erros do Chrome (`HTTP2Settings`), com alguns caminhos de
  erro que diferem em detalhe: um SETTINGS de tamanho inválido manda GOAWAY
  sem aplicar os settings anteriores; uma resposta que termina enquanto o
  corpo é enviado reseta o stream com NO_ERROR; o ID de um stream que falha
  antes do HEADERS fica pulado. A verificação periódica da conexão do
  Chrome (PING numa troca de rede) não é modelada.
- Um proxy HTTPS recebe ALPN só `http/1.1`; o Chrome também oferece `h2` e
  faz o túnel em streams HTTP/2. As credenciais do proxy vão desde o
  primeiro request, enquanto o Chrome espera um 407. O SOCKS5 também
  oferece usuário e senha quando há credenciais, o que o Chrome não suporta.
- Atrás de proxy, o ECH é usado como o Chrome o usa numa conexão direta: o
  registro HTTPS é consultado por DNS sobre HTTPS através do proxy. O Chrome
  atrás de proxy só manda GREASE ECH.

## DNS

- Só registros HTTPS são consultados, para o ECH; os endereços vêm do
  proxy, do `WithDialContext` ou do resolver do sistema. Não há Happy
  Eyeballs, lista de busca nem o fallback adaptativo do resolver do Chrome.
- Sem `WithDoH`, os registros HTTPS vêm dos servidores de nomes do
  `/etc/resolv.conf`, só no Linux e só em conexão direta. Em outros
  sistemas, através de proxy ou com `WithDialContext`, só o `WithECHConfig`
  dá configurações ECH.
- O DNS sobre HTTPS não segue redirects; o Chrome segue os que vão para
  `https://`.

## Retomada de sessão TLS

As sessões são guardadas como o Chrome as guarda (ver a documentação do
pacote), com estas diferenças:

- TLS 1.2 retoma só por session ticket, não por session ID: o `crypto/tls`
  do Go não retoma por ID.
- A idade do ticket é calculada antes do dial TCP; o Chrome calcula depois.
- Uma segunda sessão expirada de uma origem sai quando é consultada, não
  antes.
- A chave do cache é a origem, ou o endereço do proxy HTTPS. A chave do
  Chrome também tem a network anonymization key, o modo de privacidade, o
  uso da sessão e a cadeia de proxies; no Eidolon o cache é de um cliente,
  que tem um proxy só.
- Com `WithNewConnectionPerRequest`, nenhuma sessão é guardada.

## Certificados e revogação

- Os certificados são verificados pelo `crypto/x509` do Go contra as raízes
  do sistema, ou as do `WithRootCAs`, não contra o repositório de raízes do
  Chrome. Alguns certificados que o Chrome aceita podem falhar, e o
  contrário.
- **Sem verificação de revogação**: nem CRLSet, nem OCSP. Uma resposta OCSP
  grampeada e os signed certificate timestamps ficam disponíveis em
  `Response.TLS`, mas não são conferidos, e o Certificate Transparency não é
  exigido.
- Quando a verificação falha e o servidor informou suas âncoras de
  confiança, o Chrome refaz pedindo uma delas (Trust Anchor IDs); o Eidolon
  não refaz.
- O `Response.TLS.ExportKeyingMaterial` não alcança a conexão e entra em
  panic se chamado.

## Recursos

- Sem limite no total de conexões por padrão; o Chrome tem 256 por pool. O
  `WithMaxConns` define um.
- No máximo 64 consultas de registro HTTPS ao mesmo tempo por cliente, como
  o Chrome (`WithMaxDNSQueries`).

## Plataformas

- Verificado só no Linux x86_64. Windows, macOS, arm64, sistemas de 32 bits e
  redes IPv6 não foram verificados. Fora a consulta ao DNS do sistema, que
  só existe no Linux, nada depende do sistema.
